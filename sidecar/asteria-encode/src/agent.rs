//! `--agent`: JSON-lines on stdin/stdout for the Python supervisor (C-RD-HW-SUP-1).
use crate::media::{self, Ctl, MediaCfg, MediaOut};
use crate::{desk, rtc};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn out(v: &Value) {
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{v}");
    let _ = stdout.flush();
}

pub fn run(args: &[String]) -> i32 {
    desk::com_init();
    out(&json!({"t":"hello","version":env!("CARGO_PKG_VERSION"),"role":"net"}));
    let stdin = BufReader::new(std::io::stdin());
    let mut lines = stdin.lines();

    // Wait for start
    let start = loop {
        let Ok(Some(line)) = lines.next().transpose() else { return 0 };
        let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
        match v["t"].as_str() {
            Some("start") => break v,
            Some("ping") => out(&json!({"t":"pong"})),
            Some("stop") | Some("bye") => return 0,
            _ => {}
        }
    };

    let fps = start["fps"].as_u64().unwrap_or(60) as u32;
    let br = start["bitrate"].as_u64().unwrap_or(3_000_000) as u32;
    let output = start["monitor"].as_u64().unwrap_or(0) as u32;
    let notify = start["notify_user"].as_bool().unwrap_or(false);
    let session_id = start["session_id"].as_u64();
    let _ = (notify, session_id); // toast/helper spawn in later milestone; capture follows input desktop today

    let (m_ctl_tx, m_ctl_rx) = mpsc::channel::<Ctl>();
    let (m_out_tx, m_out_rx) = mpsc::channel::<MediaOut>();
    let _jh = media::spawn(MediaCfg { fps, bitrate: br, output, stamp: false, scroll: false }, m_ctl_rx, m_out_tx);

    let bundle = match rtc::make_offer() {
        Ok(b) => b,
        Err(e) => { out(&json!({"t":"error","msg":e})); return 1; }
    };
    out(&json!({"t":"offer","sdp":bundle.sdp}));

    let (cmd_tx, cmd_rx) = mpsc::channel::<rtc::Cmd>();
    let (evt_tx, evt_rx) = mpsc::channel::<Value>();
    let pending = Some(bundle.pending);
    let rtc_thread = std::thread::spawn(move || {
        rtc::run(bundle.rtc, bundle.sock, pending, bundle.mid, bundle.cid_ctrl, m_out_rx, m_ctl_tx, cmd_rx, evt_tx)
    });

    // stdin reader thread
    let cmd_in = cmd_tx.clone();
    std::thread::spawn(move || {
        for line in lines.flatten() {
            let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
            match v["t"].as_str() {
                Some("answer") => {
                    if let Some(sdp) = v["sdp"].as_str() {
                        let _ = cmd_in.send(rtc::Cmd::Answer { sdp: sdp.to_string() });
                    }
                }
                Some("ice") => {
                    if let Some(c) = v["candidate"].as_str() {
                        let _ = cmd_in.send(rtc::Cmd::Ice { candidate: c.to_string() });
                    }
                }
                Some("kf") => { /* media ctl via rtc PLI path; also */ }
                Some("stop") | Some("bye") => { let _ = cmd_in.send(rtc::Cmd::Stop); break; }
                Some("ping") => out(&json!({"t":"pong","ts":v["ts"].clone()})),
                _ => {}
            }
        }
        let _ = cmd_in.send(rtc::Cmd::Stop);
    });

    let mut last_stats = Instant::now();
    let mut frames = 0u64;
    let mut bytes = 0u64;
    let mut last_enc_ms = 0.0;
    let mut encoder = String::new();
    let mut ice = "new".to_string();
    while !rtc_thread.is_finished() {
        while let Ok(ev) = evt_rx.try_recv() {
            match ev["t"].as_str() {
                Some("ice") => { ice = ev["state"].as_str().unwrap_or("").to_string(); out(&ev); }
                Some("enc") => {
                    frames += 1;
                    bytes += ev["bytes"].as_u64().unwrap_or(0);
                    last_enc_ms = ev["ms"].as_f64().unwrap_or(0.0);
                }
                Some("media") => { encoder = ev["encoder"].as_str().unwrap_or("").to_string(); out(&ev); }
                Some("error") => { out(&ev); }
                Some("bwe") | Some("desktop") | Some("mons") | Some("pli") | Some("channel") | Some("warn") | Some("rtc") => out(&ev),
                _ => {}
            }
        }
        if last_stats.elapsed() >= Duration::from_secs(1) {
            let el = last_stats.elapsed().as_secs_f64().max(0.001);
            out(&json!({
                "t":"stats","fps": (frames as f64 / el * 10.0).round()/10.0,
                "kbps": ((bytes * 8) as f64 / el / 1000.0).round(),
                "encode_ms": (last_enc_ms * 100.0).round() / 100.0,
                "encoder": encoder, "ice": ice,
            }));
            frames = 0; bytes = 0; last_stats = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    while let Ok(ev) = evt_rx.try_recv() { if matches!(ev["t"].as_str(), Some("error" | "warn" | "ice" | "media")) { out(&ev); } }
    match rtc_thread.join() {
        Ok(Ok(s)) => out(&json!({"t":"bye","frames":s.frames_sent,"kbps_est":s.bitrate_est_kbps,"ice":s.ice})),
        Ok(Err(e)) => out(&json!({"t":"error","msg":e})),
        Err(_) => out(&json!({"t":"error","msg":"rtc panic"})),
    }
    0
}
