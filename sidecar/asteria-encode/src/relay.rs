//! `--relay <wss-url> [--fps N]`: standalone test harness (no Python agent).
//! Bridges a cloud WS relay to a child `asteria-encode --agent` (same binary, same token / session).
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;
use tungstenite::{stream::MaybeTlsStream, Message};

fn flog(dir: &str, level: &str, s: &str) {
    static DEBUG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if level == "DEBUG_SET" { DEBUG.store(s == "1", std::sync::atomic::Ordering::Relaxed); return; }
    if level == "info" && !DEBUG.load(std::sync::atomic::Ordering::Relaxed) { return; }
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    let path = format!("{dir}\\asteria-rd.log");
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() > 1_000_000 { let _ = std::fs::rename(&path, format!("{dir}\\asteria-rd.log.1")); }
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{ts} [{level}] {s}");
    }
}

fn short(t: &str) -> String { // SDP: keep candidate/fmtp/rtpmap lines only
    if !t.contains("\"sdp\"") { return t.chars().take(600).collect(); }
    let v: Value = serde_json::from_str(t).unwrap_or(Value::Null);
    let keep: Vec<&str> = v["sdp"].as_str().unwrap_or("").split("\r\n").filter(|l| l.starts_with("a=candidate") || l.starts_with("a=fmtp") || l.starts_with("a=rtpmap") || l.starts_with("m=")).collect();
    format!("{} sdp: {}", v["t"], keep.join(" | "))
}

pub fn run(args: &[String]) -> i32 {
    let url = args.iter().position(|a| a == "--relay").and_then(|i| args.get(i + 1)).cloned().unwrap_or_default();
    let fps: u32 = crate::bench::arg(args, "--fps", 30);
    loop {
        if let Err(e) = session(&url, fps, args) { eprintln!("relay: {e}; reconnect in 3s"); let dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_string_lossy().to_string())).unwrap_or(".".into()); flog(&dir, "error", &format!("relay: {e}")); }
        std::thread::sleep(Duration::from_secs(3));
    }
}

fn kill(c: &mut Option<(Child, ChildStdin)>) {
    if let Some((mut ch, mut si)) = c.take() {
        let _ = writeln!(si, "{}", json!({"t":"stop"})); let _ = si.flush();
        std::thread::sleep(Duration::from_millis(200)); let _ = ch.kill();
    }
}

fn session(url: &str, fps: u32, args: &[String]) -> Result<(), String> {
    use tungstenite::client::IntoClientRequest;
    let mut req = url.into_client_request().map_err(|e| e.to_string())?;
    if let Ok(t) = std::env::var("ASTERIA_RD_TOKEN") { // product: agent machine credential (env only, never argv/logs)
        req.headers_mut().insert("Authorization", format!("Bearer {}", t.trim()).parse().map_err(|_| "bad token".to_string())?);
    }
    let (mut ws, _) = tungstenite::connect(req).map_err(|e| e.to_string())?;
    let to = Some(Duration::from_millis(15));
    let _ = match ws.get_mut() { MaybeTlsStream::Plain(s) => s.set_read_timeout(to), MaybeTlsStream::NativeTls(s) => s.get_ref().set_read_timeout(to), _ => Ok(()) };
    eprintln!("relay: connected, waiting for viewer");
    let _ = ws.send(Message::text(json!({"t":"pc_hello","version":env!("CARGO_PKG_VERSION")}).to_string()));
    let (tx, rx) = mpsc::channel::<String>();
    let mut child: Option<(Child, ChildStdin)> = None;
    let dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_string_lossy().to_string())).unwrap_or(".".into());
    flog(&dir, "DEBUG_SET", if args.iter().any(|a| a == "--debug") { "1" } else { "0" });
    flog(&dir, "warn", "relay connected");
    let res = loop {
        match ws.read() {
            Ok(Message::Text(t)) => {
                flog(&dir, "info", &format!("<viewer {}", short(&t)));
                let v: Value = serde_json::from_str(&t).unwrap_or(Value::Null);
                match v["t"].as_str() {
                    Some("join") => {
                        kill(&mut child);
                        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
                        let mut ch = Command::new(exe).arg("--agent").stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().map_err(|e| e.to_string())?;
                        let mut si = ch.stdin.take().unwrap();
                        let so = ch.stdout.take().unwrap();
                        let tx2 = tx.clone();
                        std::thread::spawn(move || { for l in BufReader::new(so).lines().flatten() { if tx2.send(l).is_err() { break } } });
                        let _ = writeln!(si, "{}", json!({"t":"start","fps":v["fps"].as_u64().unwrap_or(fps as u64),"bitrate":v["bitrate"].as_u64().unwrap_or(4_000_000)}));
                        let _ = si.flush();
                        child = Some((ch, si));
                        eprintln!("relay: viewer joined -> agent started");
                    }
                    Some("answer") | Some("ice") | Some("ping") => if let Some((_, si)) = child.as_mut() { let _ = writeln!(si, "{}", t.as_str()); let _ = si.flush(); },
                    Some("leave") => { kill(&mut child); eprintln!("relay: viewer left"); }
                    _ => {}
                }
            }
            Ok(Message::Close(_)) => break Err("closed".into()),
            Ok(_) => {}
            Err(tungstenite::Error::Io(e)) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => break Err(e.to_string()),
        }
        while let Ok(l) = rx.try_recv() { flog(&dir, "info", &format!(">pc {}", short(&l))); if ws.send(Message::text(l)).is_err() { break } }
    };
    kill(&mut child);
    res
}
