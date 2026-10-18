//! asteria-encode — Phase 4 HW sidecar (C-RD-HW). Milestone 1: --selftest.
mod capture;
mod encoder;
mod bench;
mod desk;
mod media;
mod rtc;
mod loopback;
mod agent;
mod relay;
use serde_json::json;
use windows::core::*;
use windows::Win32::Graphics::Dxgi::*;
use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::*;
use windows::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;

fn outputs() -> Vec<serde_json::Value> {
    let mut v = vec![];
    unsafe {
        let f: IDXGIFactory1 = match CreateDXGIFactory1() { Ok(f) => f, Err(_) => return v };
        let mut ai = 0;
        while let Ok(a) = f.EnumAdapters1(ai) {
            let d = a.GetDesc1().unwrap_or_default();
            let name = String::from_utf16_lossy(&d.Description).trim_end_matches('\0').to_string();
            let mut oi = 0;
            while let Ok(o) = a.EnumOutputs(oi) {
                if let Ok(od) = o.GetDesc() {
                    let r = od.DesktopCoordinates;
                    v.push(json!({"adapter":name,"i":v.len(),"x":r.left,"y":r.top,"w":r.right-r.left,"h":r.bottom-r.top}));
                }
                oi += 1;
            }
            ai += 1;
        }
    }
    v
}

fn h264_encoders(flags: MFT_ENUM_FLAG) -> Vec<String> {
    let mut out = vec![];
    unsafe {
        let info = MFT_REGISTER_TYPE_INFO { guidMajorType: MFMediaType_Video, guidSubtype: MFVideoFormat_H264 };
        let mut acts: *mut Option<IMFActivate> = std::ptr::null_mut();
        let mut n = 0u32;
        if MFTEnumEx(MFT_CATEGORY_VIDEO_ENCODER, flags, None, Some(&info), &mut acts, &mut n).is_ok() && !acts.is_null() {
            for a in std::slice::from_raw_parts(acts, n as usize) {
                if let Some(a) = a {
                    let mut p = PWSTR::null(); let mut len = 0;
                    if a.GetAllocatedString(&MFT_FRIENDLY_NAME_Attribute, &mut p, &mut len).is_ok() {
                        out.push(p.to_string().unwrap_or_default()); CoTaskMemFree(Some(p.0 as _));
                    }
                }
            }
            CoTaskMemFree(Some(acts as _));
        }
    }
    out
}

/// Hybrid GPUs: DXGI only lets the power-saving adapter duplicate the desktop; Windows pins the GPU at
/// process start from HKCU UserGpuPreferences. Write our own entry (per user, so SYSTEM too) and re-exec once.
fn ensure_igpu_pref(args: &[String]) -> Option<i32> {
    use std::process::Command;
    let exe = std::env::current_exe().ok()?.to_string_lossy().to_string();
    let key = r"HKCU\Software\Microsoft\DirectX\UserGpuPreferences";
    let q = Command::new("reg").args(["query", key, "/v", &exe]).output().ok()?;
    if q.status.success() && String::from_utf8_lossy(&q.stdout).contains("GpuPreference=1;") { return None; }
    if std::env::var("ASTERIA_GPU_REEXEC").is_ok() { return None; }
    let ok = Command::new("reg").args(["add", key, "/v", &exe, "/t", "REG_SZ", "/d", "GpuPreference=1;", "/f"]).output().ok()?.status.success();
    if !ok { return None; }
    let st = Command::new(&exe).args(&args[1..]).env("ASTERIA_GPU_REEXEC", "1").status().ok()?;
    Some(st.code().unwrap_or(1))
}

/// `--session N|console`: when started as SYSTEM in session 0, hop into the console session.
/// Loops on child exit so lock-screen capture survives and logout → new login screen is re-attached
/// (C-RD-SESS-1). WebRTC stays in the session child; the page auto-renegotiates on pc_online.
fn session_hop(args: &[String]) -> Option<i32> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
    use windows::Win32::Security::*;
    use windows::Win32::System::Threading::*;
    use windows::Win32::System::RemoteDesktop::{ProcessIdToSessionId, WTSGetActiveConsoleSessionId};
    if !args.iter().any(|a| a == "--session") { return None; }
    let i = args.iter().position(|a| a == "--session").unwrap();
    let target = args.get(i + 1).map(|s| s.as_str()).unwrap_or("console");
    let mut cur = 0u32;
    unsafe { let _ = ProcessIdToSessionId(GetCurrentProcessId(), &mut cur); }
    // Already in a real session (not 0): run in-process.
    if cur != 0 && target != "0" { return None; }
    if cur != 0 { return None; } // session 0 parent only
    crate::desk::sas_broker(); // session-0 SYSTEM parent owns SendSAS
    let rest: Vec<String> = args.iter().enumerate().filter(|(j,_)| *j != i && *j != i+1).map(|(_,a)| a.clone()).collect();
    loop {
        let want = if target == "console" { unsafe { WTSGetActiveConsoleSessionId() } } else { target.parse().unwrap_or(1) };
        if want == 0 { eprintln!("session hop: console session 0, wait"); std::thread::sleep(std::time::Duration::from_secs(2)); continue; }
        let mut cmd: Vec<u16> = rest.iter().map(|a| format!("\"{a}\"")).collect::<Vec<_>>().join(" ").encode_utf16().chain([0]).collect();
        let mut desk: Vec<u16> = "winsta0\\default".encode_utf16().chain([0]).collect();
        unsafe {
            let (mut tok, mut dup) = (HANDLE::default(), HANDLE::default());
            if let Err(e) = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut tok) { eprintln!("session hop: OpenProcessToken {e}"); return Some(1); }
            if let Err(e) = DuplicateTokenEx(tok, TOKEN_ALL_ACCESS, None, SecurityImpersonation, TokenPrimary, &mut dup) { eprintln!("session hop: DuplicateTokenEx {e}"); return Some(1); }
            if let Err(e) = SetTokenInformation(dup, TokenSessionId, &want as *const u32 as *const _, 4) { eprintln!("session hop: TokenSessionId {e}"); return Some(1); }
            let si = STARTUPINFOW { cb: std::mem::size_of::<STARTUPINFOW>() as u32, lpDesktop: PWSTR(desk.as_mut_ptr()), ..Default::default() };
            let mut pi = PROCESS_INFORMATION::default();
            if let Err(e) = CreateProcessAsUserW(dup, None, PWSTR(cmd.as_mut_ptr()), None, None, false, CREATE_NO_WINDOW, None, None, &si, &mut pi) {
                eprintln!("session hop: CreateProcessAsUser {e}"); let _ = (CloseHandle(dup), CloseHandle(tok)); std::thread::sleep(std::time::Duration::from_secs(2)); continue;
            }
            eprintln!("session hop: {cur} -> {want} pid {}", pi.dwProcessId);
            let _ = (CloseHandle(dup), CloseHandle(tok));
            WaitForSingleObject(pi.hProcess, INFINITE);
            let mut code = 0u32; let _ = GetExitCodeProcess(pi.hProcess, &mut code);
            let _ = (CloseHandle(pi.hProcess), CloseHandle(pi.hThread));
            eprintln!("session hop: child exit {code}, re-hop in 1s");
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
}

fn require_media_foundation() {
    use windows::Win32::Media::MediaFoundation::*;
    use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        if let Err(e) = MFStartup(MF_VERSION, MFSTARTUP_FULL) {
            eprintln!("error: MFStartup failed ({e}). On Windows Server run: Install-WindowsFeature Server-Media-Foundation  (then reboot).");
            std::process::exit(3);
        }
    }
    let hw = h264_encoders(MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER);
    let sw = h264_encoders(MFT_ENUM_FLAG_SYNCMFT | MFT_ENUM_FLAG_SORTANDFILTER);
    if hw.is_empty() && sw.is_empty() {
        eprintln!("error: no H.264 Media Foundation encoder (MFT). On Windows Server run: Install-WindowsFeature Server-Media-Foundation  (then reboot). On desktop, install a GPU driver; software MFT (H264 Encoder MFT) ships with MF.");
        std::process::exit(3);
    }
    if outputs().is_empty() {
        eprintln!("warn: no DXGI outputs yet (headless/Basic Display?). Capture will retry after session hop / desktop attach.");
    }
}

fn main() {

    unsafe { let _ = windows::Win32::UI::HiDpi::SetProcessDpiAwarenessContext(windows::Win32::UI::HiDpi::DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2); }
    let args: Vec<String> = std::env::args().collect();
    if let Some(code) = session_hop(&args) { std::process::exit(code); }
    if let Some(code) = ensure_igpu_pref(&args) { std::process::exit(code); }
    if args.iter().any(|a| a == "--version") { println!("{}", env!("CARGO_PKG_VERSION")); return; }
    if args.iter().any(|a| matches!(a.as_str(), "--agent" | "--relay" | "--loopback" | "--bench")) { require_media_foundation(); }
    if args.iter().any(|a| a == "--agent") { std::process::exit(agent::run(&args)); }
    if args.iter().any(|a| a == "--relay") { std::process::exit(relay::run(&args)); }
    if args.iter().any(|a| a == "--loopback") { std::process::exit(loopback::run(&args)); }
    if args.iter().any(|a| a == "--bench") { std::process::exit(bench::run(&args)); }
    if !args.iter().any(|a| a == "--selftest") { eprintln!("usage: asteria-encode --selftest|--bench|--loopback|--agent|--relay <url> [--session console] [--debug]|--version"); std::process::exit(2); }
    unsafe { let _ = CoInitializeEx(None, COINIT_MULTITHREADED); let _ = MFStartup(MF_VERSION, MFSTARTUP_FULL); }
    let hw = h264_encoders(MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER);
    let sw = h264_encoders(MFT_ENUM_FLAG_SYNCMFT | MFT_ENUM_FLAG_SORTANDFILTER);
    let mut enc = vec![];
    for n in &hw { let l = n.to_lowercase();
        enc.push(if l.contains("nvidia") {"nvenc"} else if l.contains("intel") || l.contains("quick") {"qsv"} else if l.contains("amd") {"amf"} else {"hw_other"}); }
    if !sw.is_empty() { enc.push("mf_sw"); }
    enc.dedup();
    let outs = outputs();
    let r = json!({"t":"selftest","version":env!("CARGO_PKG_VERSION"),
        "console_session": unsafe { WTSGetActiveConsoleSessionId() },
        "outputs":outs,"hw_mft":hw,"sw_mft":sw,"encoders":enc});
    println!("{}", r);
    std::process::exit(if enc.is_empty() || outs.is_empty() { 1 } else { 0 });
}
