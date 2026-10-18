//! str0m WebRTC session: offerer that sends H.264 + two data channels (C-RD-HW-5 / C-RD-HW-IN).
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::time::{Duration, Instant};
use str0m::bwe::BweKind;
use str0m::change::{SdpAnswer, SdpPendingOffer};
use str0m::channel::ChannelId;
use str0m::crypto::from_feature_flags;
use str0m::media::{Direction, KeyframeRequestKind, MediaKind, MediaTime, Mid};
use str0m::net::{Protocol, Receive};
use str0m::bwe::Bitrate;
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc, RtcConfig};

use crate::desk;
use crate::encoder::Encoded;
use crate::media::{Ctl, MediaOut};

pub enum Cmd {
    Answer { sdp: String },
    Ice { candidate: String },
    Stop,
}

pub struct Stats {
    pub ice: String,
    pub frames_sent: u64,
    pub bytes_sent: u64,
    pub last_enc_ms: f64,
    pub bitrate_est_kbps: Option<u64>,
    pub keyframes: u64,
}

pub struct OfferBundle {
    pub rtc: Rtc,
    pub sock: UdpSocket,
    pub sdp: String,
    pub pending: SdpPendingOffer,
    pub mid: Mid,
    pub cid_u: ChannelId,
    pub cid_r: ChannelId,
}

pub fn make_offer() -> Result<OfferBundle, String> {
    from_feature_flags().install_process_default();
    let mut rtc = RtcConfig::new()
        .enable_bwe(Some(Bitrate::kbps(3000)))
        .set_stats_interval(Some(Duration::from_secs(1)))
        .build(Instant::now());
    rtc.bwe().set_desired_bitrate(Bitrate::kbps(20_000));

    let host = local_ip().ok_or("no local IP")?;
    let sock = UdpSocket::bind(SocketAddr::new(host, 0)).map_err(|e| e.to_string())?;
    sock.set_nonblocking(true).ok();
    // Also bind a loopback socket? For --self we need 127.0.0.1 connectivity.
    // Keep a single socket on the LAN IP; add both host and 127.0.0.1 candidates with same port via dual bind is impossible.
    // Instead: bind 0.0.0.0 but advertise only real IPs.
    let port = sock.local_addr().map_err(|e| e.to_string())?.port();
    // Rebind on 0.0.0.0 so we accept packets on any iface including loopback.
    drop(sock);
    let sock = UdpSocket::bind(SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), port))
        .or_else(|_| UdpSocket::bind(SocketAddr::new(host, port)))
        .map_err(|e| e.to_string())?;
    sock.set_nonblocking(true).ok();
    let _ = rtc.add_local_candidate(Candidate::host(SocketAddr::new(host, port), "udp").map_err(|e| e.to_string())?);
    let _ = rtc.add_local_candidate(Candidate::host(SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port), "udp").map_err(|e| e.to_string())?);

    let mut change = rtc.sdp_api();
    let mid = change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None);
    let cid_u = change.add_channel("input-u".into());
    let cid_r = change.add_channel("input-r".into());
    let (offer, pending) = change.apply().ok_or("sdp apply")?;
    let sdp = offer.to_sdp_string();
    Ok(OfferBundle { rtc, sock, sdp, pending, mid, cid_u, cid_r })
}

fn local_ip() -> Option<std::net::IpAddr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?;
    Some(s.local_addr().ok()?.ip())
}

pub fn apply_answer(rtc: &mut Rtc, pending: SdpPendingOffer, sdp: &str) -> Result<(), String> {
    let answer = SdpAnswer::from_sdp_string(sdp).map_err(|e| e.to_string())?;
    rtc.sdp_api().accept_answer(pending, answer).map_err(|e| e.to_string())
}

pub fn add_remote_ice(rtc: &mut Rtc, candidate: &str) -> Result<(), String> {
    let line = if candidate.starts_with("a=") {
        candidate.to_string()
    } else if candidate.starts_with("candidate:") {
        format!("a={candidate}")
    } else {
        format!("a=candidate:{candidate}")
    };
    let c = Candidate::from_sdp_string(&line).map_err(|e| e.to_string())?;
    rtc.add_remote_candidate(c);
    Ok(())
}

pub fn run(
    mut rtc: Rtc,
    sock: UdpSocket,
    pending: Option<SdpPendingOffer>,
    mid: Mid,
    cid_u: ChannelId,
    cid_r: ChannelId,
    media: Receiver<MediaOut>,
    ctl: Sender<Ctl>,
    cmds: Receiver<Cmd>,
    evt: Sender<Value>,
) -> Result<Stats, String> {
    let mut pending_offer = pending;
    let mut inj = desk::Injector::new();
    let mut ice = "new".to_string();
    let mut frames = 0u64;
    let mut bytes = 0u64;
    let mut keys = 0u64;
    let mut last_enc_ms = 0.0;
    let mut bitrate_est = None;
    let mut pending_frames: VecDeque<Encoded> = VecDeque::new();
    let mut last_clip = desk::clipboard_seq();
    let mut buf = vec![0u8; 2000];
    let mut pt_video = None;

    let _ = evt.send(json!({"t":"rtc","state":"running"}));

    loop {
        loop {
            match cmds.try_recv() {
                Ok(Cmd::Answer { sdp }) => {
                    let p = pending_offer.take().ok_or("no pending offer")?;
                    apply_answer(&mut rtc, p, &sdp)?;
                    let _ = evt.send(json!({"t":"rtc","state":"answered"}));
                }
                Ok(Cmd::Ice { candidate }) => {
                    if let Err(e) = add_remote_ice(&mut rtc, &candidate) {
                        let _ = evt.send(json!({"t":"warn","msg":format!("ice: {e}")}));
                    }
                }
                Ok(Cmd::Stop) | Err(TryRecvError::Disconnected) => {
                    return Ok(Stats { ice, frames_sent: frames, bytes_sent: bytes, last_enc_ms, bitrate_est_kbps: bitrate_est, keyframes: keys });
                }
                Err(TryRecvError::Empty) => break,
            }
        }
        loop {
            match media.try_recv() {
                Ok(MediaOut::Frame(e)) => pending_frames.push_back(e),
                Ok(MediaOut::Event(v)) => {
                    if v["t"] == "enc" { last_enc_ms = v["ms"].as_f64().unwrap_or(0.0); }
                    if matches!(v["t"].as_str(), Some("cur" | "cp" | "mons" | "desktop" | "media")) {
                        if let Some(mut ch) = rtc.channel(cid_r) {
                            let s = v.to_string();
                            let _ = ch.write(false, s.as_bytes());
                        }
                    }
                    let _ = evt.send(v);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    return Ok(Stats { ice, frames_sent: frames, bytes_sent: bytes, last_enc_ms, bitrate_est_kbps: bitrate_est, keyframes: keys });
                }
            }
        }
        let seq = desk::clipboard_seq();
        if seq != last_clip {
            last_clip = seq;
            if let Some(s) = desk::get_clipboard() {
                if s.len() <= 1 << 20 {
                    if let Some(mut ch) = rtc.channel(cid_r) {
                        let msg = json!({"t":"clip","s":s}).to_string();
                        let _ = ch.write(false, msg.as_bytes());
                    }
                }
            }
        }
        if ice == "connected" || ice == "completed" {
            if pt_video.is_none() {
                if let Some(w) = rtc.writer(mid) {
                    pt_video = w.payload_params().find(|p| p.spec().codec.is_video()).map(|p| p.pt());
                }
            }
            if let Some(pt) = pt_video {
                while let Some(e) = pending_frames.pop_front() {
                    if let Some(w) = rtc.writer(mid) {
                        let wall = Instant::now();
                        let mt = MediaTime::from_90khz((e.ts100ns as u64).saturating_mul(9) / 1000);
                        match w.write(pt, wall, mt, e.data.clone()) {
                            Ok(()) => {
                                frames += 1;
                                bytes += e.data.len() as u64;
                                if e.key { keys += 1 }
                            }
                            Err(err) => {
                                pending_frames.push_front(e);
                                let _ = evt.send(json!({"t":"warn","msg":format!("write: {err}")}));
                                break;
                            }
                        }
                    } else {
                        pending_frames.push_front(e);
                        break;
                    }
                }
            }
        }

        let timeout = match rtc.poll_output().map_err(|e| e.to_string())? {
            Output::Timeout(v) => v,
            Output::Transmit(v) => {
                let _ = sock.send_to(&v.contents, v.destination);
                continue;
            }
            Output::Event(ev) => {
                match ev {
                    Event::IceConnectionStateChange(s) => {
                        ice = format!("{s:?}").to_lowercase();
                        let _ = evt.send(json!({"t":"ice","state":&ice}));
                        if matches!(s, IceConnectionState::Disconnected) {
                            return Ok(Stats { ice, frames_sent: frames, bytes_sent: bytes, last_enc_ms, bitrate_est_kbps: bitrate_est, keyframes: keys });
                        }
                    }
                    Event::KeyframeRequest(req) => {
                        let _ = ctl.send(Ctl::Keyframe);
                        let _ = evt.send(json!({"t":"pli","kind":format!("{:?}", req.kind)}));
                        let _ = req.kind == KeyframeRequestKind::Pli;
                    }
                    Event::ChannelOpen(id, name) => {
                        let _ = evt.send(json!({"t":"channel","id":format!("{id:?}"),"name":name}));
                    }
                    Event::ChannelData(d) => {
                        if let Ok(m) = serde_json::from_slice::<Value>(&d.data) {
                            if d.id == cid_u || d.id == cid_r {
                                if let Some(reply) = inj.apply(&m) {
                                    if let Some(mut ch) = rtc.channel(cid_r) {
                                        let s = reply.to_string();
                                        let _ = ch.write(false, s.as_bytes());
                                    }
                                }
                                if m["t"] == "kf" { let _ = ctl.send(Ctl::Keyframe); }
                                if m["t"] == "mon" {
                                    if let Some(i) = m["m"].as_u64() { let _ = ctl.send(Ctl::Monitor(i as u32)); }
                                }
                            }
                        }
                    }
                    Event::EgressBitrateEstimate(k) => {
                        if let BweKind::Twcc { estimate, .. } = k {
                            let kbps = estimate.as_u64() / 1000;
                            bitrate_est = Some(kbps);
                            let _ = ctl.send(Ctl::Bitrate((kbps * 1000).clamp(300_000, 20_000_000) as u32));
                            let _ = evt.send(json!({"t":"bwe","kbps":kbps}));
                        }
                    }
                    Event::MediaAdded(m) => {
                        let _ = evt.send(json!({"t":"media_added","mid":format!("{}", m.mid),"kind":format!("{:?}", m.kind)}));
                    }
                    _ => {}
                }
                continue;
            }
        };

        let wait = timeout.saturating_duration_since(Instant::now()).min(Duration::from_millis(2));
        if wait.is_zero() {
            rtc.handle_input(Input::Timeout(Instant::now())).map_err(|e| e.to_string())?;
            continue;
        }
        sock.set_read_timeout(Some(wait)).ok();
        buf.resize(2000, 0);
        let input = match sock.recv_from(&mut buf) {
            Ok((n, source)) => {
                buf.truncate(n);
                let dest = sock.local_addr().unwrap();
                Input::Receive(
                    Instant::now(),
                    Receive::new(Protocol::Udp, source, dest, &buf).map_err(|e| e.to_string())?,
                )
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => Input::Timeout(Instant::now()),
            Err(e) => return Err(e.to_string()),
        };
        rtc.handle_input(input).map_err(|e| e.to_string())?;
    }
}
