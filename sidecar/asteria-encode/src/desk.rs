//! Desktop/session helpers: input-desktop following, monitors, cursor, input, clipboard, SAS.
use crate::capture::PointerShape;
use serde_json::{json, Value};
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::System::StationsAndDesktops::*;
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::Input::KeyboardAndMouse::*;
use windows::Win32::UI::WindowsAndMessaging::*;

pub fn com_init() {
    unsafe {
        let _ = windows::Win32::System::Com::CoInitializeEx(None, windows::Win32::System::Com::COINIT_MULTITHREADED);
        let _ = windows::Win32::Media::MediaFoundation::MFStartup(
            windows::Win32::Media::MediaFoundation::MF_VERSION,
            windows::Win32::Media::MediaFoundation::MFSTARTUP_FULL,
        );
    }
}

unsafe fn desk_name(h: HDESK) -> Option<String> {
    let mut buf = [0u16; 128];
    let mut need = 0u32;
    GetUserObjectInformationW(HANDLE(h.0), UOI_NAME, Some(buf.as_mut_ptr() as *mut _), (buf.len() * 2) as u32, Some(&mut need)).ok()?;
    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..n]))
}

pub fn input_desktop_name() -> Option<String> {
    unsafe {
        let h = OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_ACCESS_FLAGS(0x0001)).ok()?;
        let n = desk_name(h);
        let _ = CloseDesktop(h);
        n
    }
}

pub fn follow_input_desktop() -> Option<String> {
    unsafe {
        let h = OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_ACCESS_FLAGS(0x10000000)).ok()?;
        let n = desk_name(h);
        if SetThreadDesktop(h).is_err() {
            let _ = CloseDesktop(h);
            return current_thread_desktop();
        }
        n
    }
}

pub fn current_thread_desktop() -> Option<String> {
    unsafe { GetThreadDesktop(GetCurrentThreadId()).ok().and_then(|h| desk_name(h)) }
}

pub fn ensure_input_desktop(cache: &mut Option<String>) {
    let cur = input_desktop_name();
    if cur.is_some() && cur != *cache {
        *cache = follow_input_desktop();
    }
}

pub fn monitors() -> Vec<Value> {
    unsafe extern "system" fn cb(h: HMONITOR, _: HDC, _: *mut RECT, l: LPARAM) -> BOOL {
        let v = &mut *(l.0 as *mut Vec<Value>);
        let mut mi = MONITORINFO { cbSize: std::mem::size_of::<MONITORINFO>() as u32, ..Default::default() };
        if GetMonitorInfoW(h, &mut mi).as_bool() {
            let r = mi.rcMonitor;
            v.push(json!({"i":v.len(),"x":r.left,"y":r.top,"w":r.right-r.left,"h":r.bottom-r.top,"primary":(mi.dwFlags & 1)!=0}));
        }
        TRUE
    }
    let mut v: Vec<Value> = vec![];
    unsafe { let _ = EnumDisplayMonitors(HDC::default(), None, Some(cb), LPARAM(&mut v as *mut _ as isize)); }
    v
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
pub fn b64(d: &[u8]) -> String {
    let mut s = String::with_capacity(d.len() * 4 / 3 + 4);
    for c in d.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        s.push(B64[(n >> 18) as usize & 63] as char);
        s.push(B64[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        s.push(if c.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    s
}

pub fn cursor_json(s: &PointerShape) -> Option<Value> {
    let (w, p) = (s.w as usize, s.pitch as usize);
    let mut rgba;
    let h;
    match s.kind {
        1 => {
            h = (s.h / 2) as usize;
            rgba = vec![0u8; w * h * 4];
            for y in 0..h {
                for x in 0..w {
                    let bit = 0x80 >> (x % 8);
                    let a = s.data.get(y * p + x / 8)? & bit != 0;
                    let xr = s.data.get((y + h) * p + x / 8)? & bit != 0;
                    let o = (y * w + x) * 4;
                    let (c, al) = match (a, xr) {
                        (false, false) => (0, 255),
                        (false, true) => (255, 255),
                        (true, false) => (0, 0),
                        (true, true) => (0, 255),
                    };
                    rgba[o] = c; rgba[o + 1] = c; rgba[o + 2] = c; rgba[o + 3] = al;
                }
            }
        }
        2 | 4 => {
            h = s.h as usize;
            rgba = vec![0u8; w * h * 4];
            for y in 0..h {
                for x in 0..w {
                    let i = y * p + x * 4;
                    let o = (y * w + x) * 4;
                    let px = s.data.get(i..i + 4)?;
                    rgba[o] = px[2]; rgba[o + 1] = px[1]; rgba[o + 2] = px[0];
                    rgba[o + 3] = if s.kind == 4 { if px[3] == 0 { 255 } else { 0 } } else { px[3] };
                }
            }
        }
        _ => return None,
    }
    Some(json!({"t":"cur","w":w,"h":h,"hx":s.hx,"hy":s.hy,"rgba":b64(&rgba)}))
}

pub unsafe fn stamp(dev: &ID3D11Device, ctx: &ID3D11DeviceContext, tex: &ID3D11Texture2D, v: u32) {
    let Ok(ctx1) = ctx.cast::<ID3D11DeviceContext1>() else { return };
    let mut rtv = None;
    if dev.CreateRenderTargetView(tex, None, Some(&mut rtv)).is_err() { return }
    let rtv: ID3D11RenderTargetView = rtv.unwrap();
    let bg = RECT { left: 0, top: 0, right: 16 * 26, bottom: 16 };
    ctx1.ClearView(&rtv, &[0.0, 0.0, 0.0, 1.0], Some(&[bg]));
    let mut rects = vec![RECT { left: 0, top: 0, right: 16, bottom: 16 }];
    for b in 0..24 {
        if v >> (23 - b) & 1 == 1 {
            let l = 16 * (b as i32 + 1);
            rects.push(RECT { left: l, top: 0, right: l + 16, bottom: 16 });
        }
    }
    ctx1.ClearView(&rtv, &[1.0, 1.0, 1.0, 1.0], Some(&rects));
}

pub struct Injector {
    pub mons: Vec<Value>,
    pub monitor: usize,
    desk: Option<String>,
    down_keys: Vec<(u16, bool)>,
    down_btn: Vec<u8>,
    pub last: std::cell::Cell<u32>,
}

impl Injector {
    pub fn new() -> Self {
        Injector { mons: monitors(), monitor: 0, desk: None, down_keys: vec![], down_btn: vec![], last: Default::default() }
    }

    fn abs(&self, x: f64, y: f64) -> (i32, i32) {
        unsafe {
            let m = self.mons.get(self.monitor).or(self.mons.first());
            let (ox, oy) = m.map(|m| (m["x"].as_i64().unwrap_or(0) as f64, m["y"].as_i64().unwrap_or(0) as f64)).unwrap_or((0.0, 0.0));
            let (vx, vy) = (GetSystemMetrics(SM_XVIRTUALSCREEN) as f64, GetSystemMetrics(SM_YVIRTUALSCREEN) as f64);
            let (vw, vh) = (GetSystemMetrics(SM_CXVIRTUALSCREEN).max(2) as f64, GetSystemMetrics(SM_CYVIRTUALSCREEN).max(2) as f64);
            ((((x + ox - vx) * 65535.0) / (vw - 1.0)).round() as i32, (((y + oy - vy) * 65535.0) / (vh - 1.0)).round() as i32)
        }
    }
    fn mouse(&self, dx: i32, dy: i32, data: i32, flags: MOUSE_EVENT_FLAGS) {
        let i = INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 { mi: MOUSEINPUT { dx, dy, mouseData: data as u32, dwFlags: flags, time: 0, dwExtraInfo: 0 } },
        };
        self.last.set(self.last.get() + unsafe { SendInput(&[i], std::mem::size_of::<INPUT>() as i32) });
    }
    fn key(&self, sc: u16, ext: bool, down: bool) {
        let mut f = KEYEVENTF_SCANCODE;
        if ext { f |= KEYEVENTF_EXTENDEDKEY }
        if !down { f |= KEYEVENTF_KEYUP }
        let i = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk: VIRTUAL_KEY(0), wScan: sc, dwFlags: f, time: 0, dwExtraInfo: 0 } },
        };
        self.last.set(self.last.get() + unsafe { SendInput(&[i], std::mem::size_of::<INPUT>() as i32) });
    }

    pub fn apply(&mut self, m: &Value) -> Option<Value> {
        ensure_input_desktop(&mut self.desk);
        let f = |k: &str| m[k].as_f64().unwrap_or(0.0);
        match m["t"].as_str()? {
            "mm" => {
                let (x, y) = self.abs(f("x"), f("y"));
                self.mouse(x, y, 0, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK);
            }
            "mb" => {
                let (x, y) = self.abs(f("x"), f("y"));
                self.mouse(x, y, 0, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK);
                let b = m["b"].as_u64().unwrap_or(0) as u8;
                let d = m["d"].as_u64().unwrap_or(0) == 1;
                let (fl, data) = match (b, d) {
                    (0, true) => (MOUSEEVENTF_LEFTDOWN, 0), (0, false) => (MOUSEEVENTF_LEFTUP, 0),
                    (1, true) => (MOUSEEVENTF_MIDDLEDOWN, 0), (1, false) => (MOUSEEVENTF_MIDDLEUP, 0),
                    (2, true) => (MOUSEEVENTF_RIGHTDOWN, 0), (2, false) => (MOUSEEVENTF_RIGHTUP, 0),
                    (3, true) => (MOUSEEVENTF_XDOWN, 1), (3, false) => (MOUSEEVENTF_XUP, 1),
                    (4, true) => (MOUSEEVENTF_XDOWN, 2), _ => (MOUSEEVENTF_XUP, 2),
                };
                if d { self.down_btn.push(b) } else { self.down_btn.retain(|&x| x != b) }
                self.mouse(0, 0, data, fl);
            }
            "wh" => {
                let (dx, dy) = (f("dx"), f("dy"));
                if dy != 0.0 { self.mouse(0, 0, (-dy * 1.2).round() as i32, MOUSEEVENTF_WHEEL); }
                if dx != 0.0 { self.mouse(0, 0, (dx * 1.2).round() as i32, MOUSEEVENTF_HWHEEL); }
            }
            "k" => {
                let sc = m["sc"].as_u64().unwrap_or(0) as u16;
                let e = m["e"].as_u64().unwrap_or(0) == 1;
                let d = m["d"].as_u64().unwrap_or(0) == 1;
                if sc == 0 { return None }
                if d { self.down_keys.push((sc, e)) } else { self.down_keys.retain(|&k| k != (sc, e)) }
                self.key(sc, e, d);
            }
            "txt" => {
                for u in m["s"].as_str().unwrap_or("").encode_utf16() {
                    for up in [false, true] {
                        let mut fl = KEYEVENTF_UNICODE;
                        if up { fl |= KEYEVENTF_KEYUP }
                        let i = INPUT {
                            r#type: INPUT_KEYBOARD,
                            Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk: VIRTUAL_KEY(0), wScan: u, dwFlags: fl, time: 0, dwExtraInfo: 0 } },
                        };
                        self.last.set(self.last.get() + unsafe { SendInput(&[i], std::mem::size_of::<INPUT>() as i32) });
                    }
                }
            }
            "rel" => {
                for (sc, e) in std::mem::take(&mut self.down_keys) { self.key(sc, e, false); }
                for b in std::mem::take(&mut self.down_btn) {
                    let fl = match b { 0 => MOUSEEVENTF_LEFTUP, 1 => MOUSEEVENTF_MIDDLEUP, 2 => MOUSEEVENTF_RIGHTUP, _ => MOUSEEVENTF_XUP };
                    self.mouse(0, 0, if b == 3 { 1 } else if b == 4 { 2 } else { 0 }, fl);
                }
            }
            "sas" => return Some(json!({"t":"sas_result","ok":send_sas()})),
            "clip" => set_clipboard(m["s"].as_str().unwrap_or("")),
            "ping" => return Some(json!({"t":"pong","ts":m["ts"].clone()})),
            _ => {}
        }
        None
    }
}

pub fn send_sas() -> bool {
    unsafe {
        let Ok(lib) = windows::Win32::System::LibraryLoader::LoadLibraryW(w!("sas.dll")) else { return false };
        let Some(p) = windows::Win32::System::LibraryLoader::GetProcAddress(lib, s!("SendSAS")) else { return false };
        let f: extern "system" fn(BOOL) = std::mem::transmute(p);
        f(FALSE);
        true
    }
}

pub fn clipboard_seq() -> u32 {
    unsafe { windows::Win32::System::DataExchange::GetClipboardSequenceNumber() }
}

pub fn get_clipboard() -> Option<String> {
    use windows::Win32::System::DataExchange::*;
    use windows::Win32::System::Memory::*;
    unsafe {
        OpenClipboard(HWND::default()).ok()?;
        let r = (|| {
            let h = GetClipboardData(13 /*CF_UNICODETEXT*/).ok()?;
            let p = GlobalLock(HGLOBAL(h.0));
            if p.is_null() { return None; }
            let s = PCWSTR(p as *const u16).to_string().ok()?;
            let _ = GlobalUnlock(HGLOBAL(h.0));
            Some(s)
        })();
        let _ = CloseClipboard();
        r
    }
}

pub fn set_clipboard(s: &str) {
    use windows::Win32::System::DataExchange::*;
    use windows::Win32::System::Memory::*;
    unsafe {
        if OpenClipboard(HWND::default()).is_err() { return }
        let _ = EmptyClipboard();
        let mut u: Vec<u16> = s.encode_utf16().collect();
        u.push(0);
        let bytes = u.len() * 2;
        if let Ok(h) = GlobalAlloc(GMEM_MOVEABLE, bytes) {
            let p = GlobalLock(h);
            if !p.is_null() {
                std::ptr::copy_nonoverlapping(u.as_ptr(), p as *mut u16, u.len());
                let _ = GlobalUnlock(h);
                let _ = SetClipboardData(13, HANDLE(h.0));
            }
        }
        let _ = CloseClipboard();
    }
}
