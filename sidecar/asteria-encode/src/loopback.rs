//! `--loopback`: local HTTP + WebRTC offer; `--self` answers in-process (headless).
use crate::media::{self, Ctl, MediaCfg, MediaOut};
use crate::{desk, rtc};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use str0m::change::SdpOffer;
use str0m::crypto::from_feature_flags;
use str0m::media::{MediaKind, Mid};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc, RtcConfig};
use std::io::ErrorKind;
use std::net::UdpSocket;

const HTML: &str = include_str!("loopback.html");

struct Shared {
    offer_sdp: String,
    answer: Option<String>,
    remote_ice: Vec<String>,
    events: Vec<Value>,
    done: AtomicBool,
}

pub fn run(args: &[String]) -> i32 {
    desk::com_init();
    let secs: f64 = crate::bench::arg(args, "--seconds", 12.0);
    let fps: u32 = crate::bench::arg(args, "--fps", 60);
    let br: u32 = crate::bench::arg(args, "--bitrate", 8_000_000);
    let self_ans = args.iter().any(|a| a == "--self");
    let stamp = args.iter().any(|a| a == "--stamp");
    let scroll = args.iter().any(|a| a == "--scroll") || (!stamp && self_ans);

    let (m_ctl_tx, m_ctl_rx) = mpsc::channel::<Ctl>();
    let (m_out_tx, m_out_rx) = mpsc::channel::<MediaOut>();
    let _jh = media::spawn(MediaCfg { fps, bitrate: br, output: crate::bench::arg(args, "--output", 0), stamp, scroll }, m_ctl_rx, m_out_tx);

    let bundle = match rtc::make_offer() {
        Ok(b) => b,
        Err(e) => { println!("{}", json!({"t":"loopback","error":e})); return 1; }
    };
    let sid = format!("{:x}", Instant::now().elapsed().as_nanos() ^ std::process::id() as u128);
    let shared = Arc::new(Mutex::new(Shared {
        offer_sdp: bundle.sdp.clone(), answer: None, remote_ice: vec![], events: vec![], done: AtomicBool::new(false),
    }));
    // tiny HTTP on 127.0.0.1:0
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind http");
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}/{sid}");
    eprintln!("loopback url: {url}");
    {
        let sh = shared.clone();
        std::thread::spawn(move || {
            for s in listener.incoming().flatten() {
                if sh.lock().unwrap().done.load(Ordering::Relaxed) { break; }
                handle_http(s, &sh, &sid);
            }
        });
    }

    let (cmd_tx, cmd_rx) = mpsc::channel::<rtc::Cmd>();
    let (evt_tx, evt_rx) = mpsc::channel::<Value>();
    let offer = bundle;
    let rtc_thread = {
        let pending = Some(offer.pending);
        std::thread::spawn(move || {
            rtc::run(offer.rtc, offer.sock, pending, offer.mid, offer.cid_u, offer.cid_r, m_out_rx, m_ctl_tx, cmd_rx, evt_tx)
        })
    };

    if self_ans {
        let offer_sdp = shared.lock().unwrap().offer_sdp.clone();
        let cmd = cmd_tx.clone();
        std::thread::spawn(move || {
            if let Err(e) = self_answer(offer_sdp, cmd.clone(), secs) {
                eprintln!("self-answer err: {e}");
            }
            let _ = cmd.send(rtc::Cmd::Stop);
        });
    }

    let t0 = Instant::now();
    let mut ice_ok = false;
    let mut frames_hint = 0u64;
    let mut answered = false;
    let mut connected_at: Option<Instant> = None;
    while t0.elapsed().as_secs_f64() < secs + (if self_ans { 5.0 } else { 30.0 }) {
        if !self_ans {
            let mut g = shared.lock().unwrap();
            if !answered {
                if let Some(a) = g.answer.take() {
                    let _ = cmd_tx.send(rtc::Cmd::Answer { sdp: a });
                    answered = true;
                }
            }
            for c in g.remote_ice.drain(..) {
                let _ = cmd_tx.send(rtc::Cmd::Ice { candidate: c });
            }
        }
        while let Ok(ev) = evt_rx.try_recv() {
            if ev["t"] == "ice" && (ev["state"] == "connected" || ev["state"] == "completed") {
                ice_ok = true;
                connected_at.get_or_insert(Instant::now());
            }
            if ev["t"] == "enc" { frames_hint += 1; }
            shared.lock().unwrap().events.push(ev);
        }
        if rtc_thread.is_finished() { break; }
        if let Some(c) = connected_at {
            if c.elapsed().as_secs_f64() >= secs { break; }
        } else if !self_ans && answered && t0.elapsed().as_secs_f64() > secs + 5.0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = cmd_tx.send(rtc::Cmd::Stop);

    let stats = match rtc_thread.join() {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => { println!("{}", json!({"t":"loopback","error":e})); return 1; }
        Err(_) => { println!("{}", json!({"t":"loopback","error":"rtc panic"})); return 1; }
    };
    shared.lock().unwrap().done.store(true, Ordering::Relaxed);
    let el = t0.elapsed().as_secs_f64().max(0.001);
    println!("{}", json!({
        "t":"loopback","mode": if self_ans {"self"} else {"browser"},
        "url": url, "seconds": (el*10.0).round()/10.0,
        "ice": stats.ice, "ice_ok": ice_ok || stats.ice.contains("connected") || stats.ice.contains("completed"),
        "frames_sent": stats.frames_sent, "fps": (stats.frames_sent as f64 / el * 10.0).round()/10.0,
        "kbps": ((stats.bytes_sent * 8) as f64 / el / 1000.0).round(),
        "keyframes": stats.keyframes, "last_enc_ms": (stats.last_enc_ms*100.0).round()/100.0,
        "bwe_kbps": stats.bitrate_est_kbps, "enc_events": frames_hint,
    }));
    if stats.frames_sent == 0 { 1 } else { 0 }
}

fn handle_http(mut s: TcpStream, sh: &Arc<Mutex<Shared>>, sid: &str) {
    let mut buf = [0u8; 8192];
    let n = s.read(&mut buf).unwrap_or(0);
    let req = String::from_utf8_lossy(&buf[..n]);
    let line = req.lines().next().unwrap_or("");
    let path = line.split_whitespace().nth(1).unwrap_or("/");
    let body = req.split("\r\n\r\n").nth(1).unwrap_or("").as_bytes();
    let (code, ctype, body): (u16, &str, Vec<u8>) = if path == format!("/{sid}") || path == format!("/{sid}/") {
        (200, "text/html; charset=utf-8", HTML.as_bytes().to_vec())
    } else if path == format!("/offer/{sid}") {
        let sdp = sh.lock().unwrap().offer_sdp.clone();
        (200, "application/json", json!({"sdp":sdp}).to_string().into_bytes())
    } else if path.starts_with(&format!("/answer/{sid}")) && line.starts_with("POST") {
        if let Ok(v) = serde_json::from_slice::<Value>(body) {
            if let Some(sdp) = v["sdp"].as_str() { sh.lock().unwrap().answer = Some(sdp.to_string()); }
        }
        (200, "application/json", b"{}".to_vec())
    } else if path.starts_with(&format!("/ice/{sid}")) && line.starts_with("POST") {
        if let Ok(v) = serde_json::from_slice::<Value>(body) {
            if let Some(c) = v["candidate"].as_str() { sh.lock().unwrap().remote_ice.push(c.to_string()); }
        }
        (200, "application/json", b"{}".to_vec())
    } else {
        (404, "text/plain", b"not found".to_vec())
    };
    let _ = write!(s, "HTTP/1.1 {code} OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    let _ = s.write_all(&body);
}

/// In-process answerer: accepts offer, gathers host candidate, reports MediaData arrival.
fn self_answer(offer_sdp: String, cmd: mpsc::Sender<rtc::Cmd>, secs: f64) -> Result<(), String> {
    from_feature_flags().install_process_default();
    let mut rtc = RtcConfig::new().build(Instant::now());
    let sock = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    sock.set_nonblocking(true).ok();
    let addr = sock.local_addr().unwrap();
    let _ = rtc.add_local_candidate(Candidate::host(addr, "udp").map_err(|e| e.to_string())?);
    let offer = SdpOffer::from_sdp_string(&offer_sdp).map_err(|e| e.to_string())?;
    let answer = rtc.sdp_api().accept_offer(offer).map_err(|e| e.to_string())?;
    let answer_sdp = answer.to_sdp_string();
    let _ = cmd.send(rtc::Cmd::Answer { sdp: answer_sdp });
    // trickle local candidates back as "remote" to the offerer — host already in SDP usually.
    // Drive both until timeout.
    let t0 = Instant::now();
    let mut buf = vec![0u8; 2000];
    let mut frames = 0u64;
    let mut bytes = 0u64;
    let mut mid: Option<Mid> = None;
    while t0.elapsed().as_secs_f64() < secs {
        let timeout = match rtc.poll_output().map_err(|e| e.to_string())? {
            Output::Timeout(v) => v,
            Output::Transmit(v) => { let _ = sock.send_to(&v.contents, v.destination); continue; }
            Output::Event(ev) => {
                match ev {
                    Event::IceConnectionStateChange(IceConnectionState::Disconnected) => break,
                    Event::MediaAdded(m) if m.kind == MediaKind::Video => { mid = Some(m.mid); }
                    Event::MediaData(d) => { frames += 1; bytes += d.data.len() as u64; }
                    Event::IceConnectionStateChange(s) if matches!(s, IceConnectionState::Connected | IceConnectionState::Completed) => {}
                    _ => {}
                }
                continue;
            }
        };
        let wait = timeout.saturating_duration_since(Instant::now()).min(Duration::from_millis(5));
        if wait.is_zero() { rtc.handle_input(Input::Timeout(Instant::now())).ok(); continue; }
        sock.set_read_timeout(Some(wait)).ok();
        buf.resize(2000, 0);
        let input = match sock.recv_from(&mut buf) {
            Ok((n, source)) => {
                buf.truncate(n);
                Input::Receive(Instant::now(), Receive::new(Protocol::Udp, source, sock.local_addr().unwrap(), &buf).map_err(|e| e.to_string())?)
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => Input::Timeout(Instant::now()),
            Err(e) => return Err(e.to_string()),
        };
        rtc.handle_input(input).map_err(|e| e.to_string())?;
        let _ = (frames, bytes, mid);
    }
    eprintln!("self-answer recv frames={frames} bytes={bytes}");
    Ok(())
}
