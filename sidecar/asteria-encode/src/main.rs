//! asteria-encode — Phase 4 HW sidecar (C-RD-HW). Milestone 1: --selftest.
mod capture;
mod encoder;
mod bench;
mod desk;
mod media;
mod rtc;
mod loopback;
mod agent;
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

fn main() {
    unsafe { let _ = windows::Win32::UI::HiDpi::SetProcessDpiAwarenessContext(windows::Win32::UI::HiDpi::DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2); }
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version") { println!("{}", env!("CARGO_PKG_VERSION")); return; }
    if args.iter().any(|a| a == "--agent") { std::process::exit(agent::run(&args)); }
    if args.iter().any(|a| a == "--loopback") { std::process::exit(loopback::run(&args)); }
    if args.iter().any(|a| a == "--bench") { std::process::exit(bench::run(&args)); }
    if !args.iter().any(|a| a == "--selftest") { eprintln!("usage: asteria-encode --selftest|--bench|--loopback|--agent|--version"); std::process::exit(2); }
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
