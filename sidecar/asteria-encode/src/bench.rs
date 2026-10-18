//! --bench: capture + HW encode measurement (C-RD-HW-SUP-3 numbers).
use crate::capture::*;
use crate::encoder::*;
use serde_json::json;
use std::io::Write;
use std::time::{Duration, Instant};
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::*;
use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::*;

pub fn arg<T: std::str::FromStr>(args: &[String], k: &str, d: T) -> T {
    args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).and_then(|v| v.parse().ok()).unwrap_or(d)
}
fn pct(v: &mut Vec<f64>, p: f64) -> f64 { if v.is_empty() { return 0.0 } v.sort_by(|a, b| a.partial_cmp(b).unwrap()); v[((v.len() - 1) as f64 * p) as usize] }

pub fn run(args: &[String]) -> i32 {
    unsafe { let _ = CoInitializeEx(None, COINIT_MULTITHREADED); let _ = MFStartup(MF_VERSION, MFSTARTUP_FULL); }
    if args.iter().any(|a| a == "--synthetic") { return run_synth(args); }
    let secs: f64 = arg(args, "--seconds", 10.0);
    let fps: u32 = arg(args, "--fps", 60);
    let br: u32 = arg(args, "--bitrate", 8_000_000);
    let motion: String = arg(args, "--motion", "scroll".to_string());
    let outp: String = arg(args, "--out", String::new());
    let mut dup = match Dup::new(arg(args, "--output", 0)) { Ok(d) => d, Err(e) => { println!("{}", json!({"t":"bench","error":format!("dxgi: {e}")})); return 1 } };
    let mut enc = match Enc::new(&dup.device, &dup.ctx, &dup.adapter_name, dup.w, dup.h, fps, br) {
        Ok(e) => e, Err(e) => { println!("{}", json!({"t":"bench","error":format!("mft: {e}")})); return 1 } };
    let mut file = if outp.is_empty() { None } else { std::fs::File::create(&outp).ok() };
    // wait for a first desktop image
    let t0 = Instant::now();
    while !dup.have_frame && t0.elapsed() < Duration::from_secs(2) { let _ = dup.next(100); }
    let snap = bgra_texture(&dup.device, dup.w, dup.h, DXGI_FORMAT_B8G8R8A8_UNORM, D3D11_BIND_SHADER_RESOURCE.0 as u32).unwrap();
    let work = bgra_texture(&dup.device, dup.w, dup.h, DXGI_FORMAT_B8G8R8A8_UNORM, (D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0) as u32).unwrap();
    unsafe { dup.ctx.CopyResource(&snap, &dup.tex); }
    let (w, h) = (dup.w, dup.h);
    let mut enc_ms = vec![]; let mut cap_ms = vec![];
    let (mut frames, mut bytes, mut keys, mut idle_ticks, mut cap_updates, mut first_key) = (0u64, 0u64, 0u64, 0u64, 0u64, None);
    let tick = Duration::from_secs_f64(1.0 / fps as f64);
    let start = Instant::now(); let mut next = start; let mut off = 0u32;
    enc.force_keyframe();
    let pipelined = !args.iter().any(|a| a == "--sync");
    let mut submitted: std::collections::HashMap<i64, Instant> = Default::default();
    while start.elapsed().as_secs_f64() < secs {
        let tc = Instant::now();
        let fi = dup.next(0).ok().flatten();
        let updated = fi.as_ref().map(|f| f.updated).unwrap_or(false);
        if updated { cap_updates += 1; cap_ms.push(tc.elapsed().as_secs_f64() * 1000.0); }
        let src = match motion.as_str() {
            "scroll" => unsafe {
                off = (off + 8) % h;
                let a = D3D11_BOX { left: 0, top: 0, front: 0, right: w, bottom: h - off, back: 1 };
                dup.ctx.CopySubresourceRegion(&work, 0, 0, off, 0, &snap, 0, Some(&a));
                if off > 0 { let b = D3D11_BOX { left: 0, top: h - off, front: 0, right: w, bottom: h, back: 1 };
                    dup.ctx.CopySubresourceRegion(&work, 0, 0, 0, 0, &snap, 0, Some(&b)); }
                Some(&work)
            },
            _ => if updated { Some(&dup.tex) } else { None }, // VFR: real desktop only
        };
        if let Some(s) = src {
            let ts = (start.elapsed().as_nanos() / 100) as i64;
            submitted.insert(ts, Instant::now());
            match enc.encode(s, ts).and_then(|mut v| { v.extend(enc.poll(if pipelined {0} else {50})?); Ok(v) }) {
                Ok(v) => {
                    for e in v {
                        if let Some(t) = submitted.remove(&e.ts100ns) { enc_ms.push(t.elapsed().as_secs_f64() * 1000.0); } frames += 1; bytes += e.data.len() as u64; if e.key { keys += 1; if first_key.is_none() { first_key = Some(frames) } }
                        if let Some(f) = file.as_mut() { let _ = f.write_all(&e.data); } }
                }
                Err(e) => { println!("{}", json!({"t":"bench","error":format!("encode: {e}")})); return 1 }
            }
        } else { idle_ticks += 1; }
        next += tick;
        let now = Instant::now(); if next > now { std::thread::sleep(next - now); } else { next = now; }
    }
    let el = start.elapsed().as_secs_f64();
    println!("{}", json!({"t":"bench","encoder":enc.name,"adapter":dup.adapter_name,"w":w,"h":h,"motion":motion,
        "target_fps":fps,"target_kbps":br/1000,"seconds":(el*10.0).round()/10.0,
        "frames":frames,"fps":(frames as f64/el*10.0).round()/10.0,"kbps":((bytes*8) as f64/el/1000.0).round(),
        "avg_frame_bytes": if frames>0 {bytes/frames} else {0},"keyframes":keys,"first_key_frame":first_key,
        "encode_ms_p50":(pct(&mut enc_ms.clone(),0.5)*100.0).round()/100.0,"encode_ms_p95":(pct(&mut enc_ms.clone(),0.95)*100.0).round()/100.0,
        "encode_ms_max":(pct(&mut enc_ms,1.0)*100.0).round()/100.0,
        "capture_updates":cap_updates,"capture_copy_ms_p50":(pct(&mut cap_ms,0.5)*100.0).round()/100.0,"idle_ticks":idle_ticks}));
    0
}

/// --bench --synthetic: encoder-only test without desktop duplication (works while locked).
fn run_synth(args: &[String]) -> i32 {
    use windows::Win32::Graphics::Direct3D::*;
    use windows::Win32::Graphics::Dxgi::*;
    let secs: f64 = arg(args, "--seconds", 4.0);
    let fps: u32 = arg(args, "--fps", 30);
    let br: u32 = arg(args, "--bitrate", 4_000_000);
    let (w, h) = (1280u32, 720u32);
    let (adapter_name, mut dev, mut ctx) = unsafe {
        let f: IDXGIFactory1 = match CreateDXGIFactory1() {
            Ok(f) => f,
            Err(e) => { println!("{}", json!({"t":"bench","error":format!("dxgi factory: {e}")})); return 1 },
        };
        let a = match f.EnumAdapters1(0) {
            Ok(a) => a,
            Err(e) => { println!("{}", json!({"t":"bench","error":format!("adapter: {e}")})); return 1 },
        };
        let d = a.GetDesc1().unwrap_or_default();
        let name = String::from_utf16_lossy(&d.Description).trim_end_matches('\0').to_string();
        let mut dev = None; let mut ctx = None;
        if let Err(e) = D3D11CreateDevice(
            &a, D3D_DRIVER_TYPE_UNKNOWN, None,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
            None, D3D11_SDK_VERSION, Some(&mut dev), None, Some(&mut ctx),
        ) {
            println!("{}", json!({"t":"bench","error":format!("d3d: {e}")})); return 1;
        }
        (name, dev, ctx)
    };
    let (dev, ctx) = (dev.unwrap(), ctx.unwrap());
    let mut enc = match Enc::new(&dev, &ctx, &adapter_name, w, h, fps, br) {
        Ok(e) => e,
        Err(e) => { println!("{}", json!({"t":"bench","error":format!("mft: {e}")})); return 1 },
    };
    let tex = bgra_texture(&dev, w, h, DXGI_FORMAT_B8G8R8A8_UNORM, (D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0) as u32).unwrap();
    let mut rtv = None;
    unsafe { dev.CreateRenderTargetView(&tex, None, Some(&mut rtv)).unwrap(); }
    let rtv = rtv.unwrap();
    let start = Instant::now();
    let (mut frames, mut bytes, mut keys, mut i) = (0u64, 0u64, 0u64, 0u64);
    enc.force_keyframe();
    while start.elapsed().as_secs_f64() < secs {
        let c = (i % 60) as f32 / 60.0;
        i += 1;
        unsafe { ctx.ClearRenderTargetView(&rtv, &[c, 1.0 - c, 0.5, 1.0]); }
        let ts = (start.elapsed().as_nanos() / 100) as i64;
        match enc.encode(&tex, ts).and_then(|mut v| { v.extend(enc.poll(20)?); Ok(v) }) {
            Ok(v) => {
                for e in v {
                    frames += 1;
                    bytes += e.data.len() as u64;
                    if e.key { keys += 1; }
                }
            }
            Err(e) => {
                println!("{}", json!({"t":"bench","error":format!("encode: {e}"),"encoder":enc.name}));
                return 1;
            }
        }
        std::thread::sleep(Duration::from_millis((1000 / fps.max(1)) as u64));
    }
    let el = start.elapsed().as_secs_f64();
    println!("{}", json!({
        "t":"bench","synthetic":true,"encoder":enc.name,"software":enc.sw,"adapter":adapter_name,
        "w":w,"h":h,"frames":frames,"fps":(frames as f64/el*10.0).round()/10.0,
        "kbps":((bytes*8) as f64/el/1000.0).round(),"keyframes":keys
    }));
    if frames > 0 { 0 } else { 1 }
}
