//! Capture + encode worker thread with input-desktop following (C-RD-HW-3/4, CON-3).
use crate::capture::*;
use crate::encoder::*;
use crate::desk;
use serde_json::{json, Value};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::*;

pub enum Ctl { Keyframe, Bitrate(u32), Monitor(u32), Stop }
pub enum MediaOut { Frame(Encoded), Event(Value) }

#[derive(Clone)]
pub struct MediaCfg { pub fps: u32, pub bitrate: u32, pub output: u32, pub stamp: bool, pub scroll: bool }

pub fn now_ms() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0) }

pub fn spawn(cfg: MediaCfg, ctl: Receiver<Ctl>, out: Sender<MediaOut>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || { if let Err(e) = run(cfg, ctl, &out) { let _ = out.send(MediaOut::Event(json!({"t":"error","where":"media","msg":e}))); } })
}

fn run(mut cfg: MediaCfg, ctl: Receiver<Ctl>, out: &Sender<MediaOut>) -> Result<(), String> {
    desk::com_init();
    let mut desktop = desk::follow_input_desktop();
    let mut dup = open_dup(cfg.output)?;
    let mut enc = Enc::new(&dup.device, &dup.ctx, &dup.adapter_name, dup.w, dup.h, cfg.fps, cfg.bitrate).map_err(|e| format!("mft: {e}"))?;
    let _ = out.send(MediaOut::Event(json!({"t":"media","encoder":enc.name,"adapter":dup.adapter_name,"capture":dup.method,"w":dup.w,"h":dup.h,"desktop":desktop})));
    let _ = out.send(MediaOut::Event(json!({"t":"mons","list":desk::monitors()})));
    let mut work: Option<ID3D11Texture2D> = None;
    let mut snap: Option<ID3D11Texture2D> = None;
    let tick = Duration::from_secs_f64(1.0 / cfg.fps as f64);
    let mut next = Instant::now(); let mut last_desk_check = Instant::now(); let mut last_sent = Instant::now();
    let mut off = 0u32; let mut force_key = true;
    let start = Instant::now();
    loop {
        loop {
            match ctl.try_recv() {
                Ok(Ctl::Keyframe) => force_key = true,
                Ok(Ctl::Bitrate(b)) => enc.set_bitrate(b),
                Ok(Ctl::Monitor(m)) if m != cfg.output => { cfg.output = m; dup = open_dup(m)?; enc = Enc::new(&dup.device, &dup.ctx, &dup.adapter_name, dup.w, dup.h, cfg.fps, enc.bitrate).map_err(|e| format!("mft: {e}"))?; work = None; snap = None; force_key = true;
                    let _ = out.send(MediaOut::Event(json!({"t":"media","encoder":enc.name,"w":dup.w,"h":dup.h,"monitor":m}))); }
                Ok(Ctl::Monitor(_)) => {}
                Ok(Ctl::Stop) | Err(TryRecvError::Disconnected) => return Ok(()),
                Err(TryRecvError::Empty) => break,
            }
        }
        // desktop switch detection (Winlogon <-> Default, UAC secure desktop)
        if last_desk_check.elapsed() > Duration::from_millis(250) {
            last_desk_check = Instant::now();
            let cur = desk::input_desktop_name();
            if cur.is_some() && cur != desktop {
                desktop = desk::follow_input_desktop();
                let _ = out.send(MediaOut::Event(json!({"t":"desktop","name":desktop})));
                match open_dup(cfg.output) {
                    Ok(d) => {
                        let resized = d.w != dup.w || d.h != dup.h;
                        dup = d; work = None; snap = None; force_key = true;
                        enc = Enc::new(&dup.device, &dup.ctx, &dup.adapter_name, dup.w, dup.h, cfg.fps, enc.bitrate).map_err(|e| format!("mft: {e}"))?; // new D3D device => new MFT (old one is bound to the lost device)
                        prime_frame(&mut dup, out);
                        let _ = out.send(MediaOut::Event(json!({"t":"media","encoder":enc.name,"adapter":dup.adapter_name,"capture":dup.method,"w":dup.w,"h":dup.h,"desktop":desktop,"resized":resized})));
                    }
                    Err(e) => { let _ = out.send(MediaOut::Event(json!({"t":"warn","msg":format!("desk switch: {e}")}))); }
                }
            }
        }
        // Lock/Winlogon or stall: force IDR every 2s so a static curtain still refreshes the viewer
        let lockish = desktop.as_deref().map(|d| d.eq_ignore_ascii_case("Winlogon") || d.to_ascii_lowercase().contains("secure")).unwrap_or(false);
        if lockish || last_sent.elapsed() > Duration::from_secs(2) { force_key = true; }
        let wait = if !dup.have_frame || force_key { 50u32 } else { 0u32 };
        let fi = match dup.next(wait) {
            Ok(f) => f,
            Err(_) => { // ACCESS_LOST: secure desktop / mode change — follow input desktop, backoff, never exit
                let _ = out.send(MediaOut::Event(json!({"t":"warn","msg":"dxgi ACCESS_LOST, reopening"})));
                for backoff in [50u64, 100, 200, 400, 800] {
                    std::thread::sleep(Duration::from_millis(backoff));
                    desktop = desk::follow_input_desktop();
                    match open_dup(cfg.output) {
                        Ok(d) => {
                            let resized = d.w != dup.w || d.h != dup.h;
                            dup = d; work = None; snap = None; force_key = true;
                            enc = Enc::new(&dup.device, &dup.ctx, &dup.adapter_name, dup.w, dup.h, cfg.fps, enc.bitrate).map_err(|e| format!("mft: {e}"))?; // new D3D device => new MFT (old one is bound to the lost device)
                            prime_frame(&mut dup, out);
                            let _ = out.send(MediaOut::Event(json!({"t":"desktop","name":desktop})));
                            let _ = out.send(MediaOut::Event(json!({"t":"media","encoder":enc.name,"adapter":dup.adapter_name,"capture":dup.method,"w":dup.w,"h":dup.h,"desktop":desktop,"resized":resized})));
                            break;
                        }
                        Err(e) => { let _ = out.send(MediaOut::Event(json!({"t":"warn","msg":format!("reopen: {e}")}))); }
                    }
                }
                None
            }
        };
        if let Some(f) = &fi {
            // cp now sent by rtc (GetCursorPos 30 Hz); DXGI pointer_pos only updates on frame changes
            if let Some(s) = &f.pointer_shape { if let Some(j) = desk::cursor_json(s) { let _ = out.send(MediaOut::Event(j)); } }
        }
        let updated = fi.as_ref().map(|f| f.updated).unwrap_or(false);
        // VFR: encode only when the desktop changed (or forced keyframe / stamp / scroll test, or 1 fps keepalive)
        let need = updated || force_key || cfg.stamp || cfg.scroll || last_sent.elapsed() > Duration::from_secs(1);
        if need && dup.have_frame {
            let mut src = dup.tex.clone();
            if cfg.stamp || cfg.scroll {
                if work.is_none() {
                    work = crate::capture::bgra_texture(&dup.device, dup.w, dup.h, DXGI_FORMAT_B8G8R8A8_UNORM, (D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0) as u32).ok();
                    snap = crate::capture::bgra_texture(&dup.device, dup.w, dup.h, DXGI_FORMAT_B8G8R8A8_UNORM, D3D11_BIND_SHADER_RESOURCE.0 as u32).ok();
                    if let Some(s) = &snap { unsafe { dup.ctx.CopyResource(s, &dup.tex) } }
                }
                let w = work.clone().unwrap();
                unsafe {
                    if cfg.scroll {
                        let s = snap.clone().unwrap(); let (ww, hh) = (dup.w, dup.h); off = (off + 8) % hh;
                        let a = D3D11_BOX { left: 0, top: 0, front: 0, right: ww, bottom: hh - off, back: 1 };
                        dup.ctx.CopySubresourceRegion(&w, 0, 0, off, 0, &s, 0, Some(&a));
                        if off > 0 { let b = D3D11_BOX { left: 0, top: hh - off, front: 0, right: ww, bottom: hh, back: 1 }; dup.ctx.CopySubresourceRegion(&w, 0, 0, 0, 0, &s, 0, Some(&b)); }
                    } else { dup.ctx.CopyResource(&w, &dup.tex); }
                    if cfg.stamp { desk::stamp(&dup.device, &dup.ctx, &w, (now_ms() & 0xFF_FFFF) as u32); }
                }
                src = w;
            }
            if force_key { enc.force_keyframe(); force_key = false; }
            let ts = (start.elapsed().as_nanos() / 100) as i64;
            let t0 = Instant::now();
            let mut v = enc.encode(&src, ts).map_err(|e| format!("encode: {e}"))?;
            v.extend(enc.poll(50).map_err(|e| format!("encode: {e}"))?);
            let ms = t0.elapsed().as_secs_f64() * 1000.0;
            for e in v { let _ = out.send(MediaOut::Event(json!({"t":"enc","ms":ms,"bytes":e.data.len(),"key":e.key}))); if out.send(MediaOut::Frame(e)).is_err() { return Ok(()); } }
            last_sent = Instant::now();
        }
        next += tick;
        let now = Instant::now();
        if next > now { std::thread::sleep(next - now) } else { next = now }
    }
}


fn prime_frame(dup: &mut Dup, out: &Sender<MediaOut>) {
    // After DuplicateOutput, have_frame is false until a Present; lock screen may be static — wait up to ~1s.
    for _ in 0..20 {
        match dup.next(50) {
            Ok(_) if dup.have_frame => {
                let _ = out.send(MediaOut::Event(json!({"t":"warn","msg":"prime_frame ok"})));
                return;
            }
            Ok(_) => {}
            Err(e) => { let _ = out.send(MediaOut::Event(json!({"t":"warn","msg":format!("prime: {e}")}))); return; }
        }
    }
    let _ = out.send(MediaOut::Event(json!({"t":"warn","msg":"prime_frame timeout (no Present yet)"})));
}

fn open_dup(i: u32) -> Result<Dup, String> {
    let mut last = String::new();
    for _ in 0..20 { match Dup::new(i) { Ok(d) => return Ok(d), Err(e) => { last = format!("dxgi: {e}"); std::thread::sleep(Duration::from_millis(100)); } } }
    Err(tr_dxgi(&last))
}

/// Raw DXGI HRESULTs -> clear Turkish reason (keeps the code for support).
pub(crate) fn tr_dxgi(e: &str) -> String {
    let u = e.to_uppercase();
    let why = if u.contains("0X80004002") { "Ekran yakalama aray\u{fc}z\u{fc} bu Windows s\u{fc}r\u{fc}m\u{fc}nde yok (DXGI) ve GDI yedek yakalama da ba\u{15f}ar\u{131}s\u{131}z" }
        else if u.contains("0X887A0004") { "Bu makinede ekran yakalama (DXGI masa\u{fc}st\u{fc} \u{e7}o\u{11f}altma) desteklenmiyor" }
        else if u.contains("0X887A0022") || u.contains("0X887A0029") { "Konsol oturumu ba\u{11f}l\u{131} de\u{11f}il (makineye RDP ile ba\u{11f}lan\u{131}lm\u{131}\u{15f} olabilir); RDP oturumunu konsola aktar\u{131}n veya kapat\u{131}n" }
        else if u.contains("0X80070005") { "Ekran yakalamaya eri\u{15f}im reddedildi (kilit/UAC ekran\u{131} veya oturum yok)" }
        else { return e.to_string() };
    format!("{why} [{e}]")
}

#[cfg(test)]
mod tests {
    use super::tr_dxgi;
    #[test]
    fn tr_dxgi_explains_e_nointerface() {
        let m = tr_dxgi("dxgi: No such interface supported (0x80004002)");
        assert!(m.contains("GDI") && m.contains("0x80004002"));
    }
    #[test]
    fn tr_dxgi_passes_unknown_through() {
        assert_eq!(tr_dxgi("dxgi: boom"), "dxgi: boom");
    }
}
