//! DXGI Desktop Duplication (C-RD-HW-3) with automatic GDI BitBlt fallback (C-RD-GDI-1).
//!
//! * `IDXGIFactory6` (GPU preference ordering) only exists on Windows 10 1803+ / Server 2019+.
//!   On Server 2016 (14393) and older it fails with E_NOINTERFACE (0x80004002); we then
//!   enumerate with plain `IDXGIFactory1::EnumAdapters1`.
//! * When Desktop Duplication itself is unavailable (E_NOINTERFACE, DXGI_ERROR_UNSUPPORTED,
//!   no DXGI output for the monitor, ...) the same `Dup` switches to a GDI BitBlt source that
//!   uploads into the same D3D11 BGRA texture, so the encoder path is unchanged.
//!   `ASTERIA_CAPTURE=gdi` forces it (test switch), `ASTERIA_CAPTURE=dxgi` disables it.
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Direct3D::*;
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::*;
use windows::Win32::Graphics::Dxgi::*;
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::UI::WindowsAndMessaging::*;

pub struct Dup {
    pub device: ID3D11Device,
    pub ctx: ID3D11DeviceContext,
    pub adapter_name: String,
    dup: Option<IDXGIOutputDuplication>,
    output: Option<IDXGIOutput1>,
    gdi: Option<GdiSrc>,
    /// "dxgi" or "gdi" (reported to the viewer in the media event).
    pub method: &'static str,
    pub w: u32,
    pub h: u32,
    /// Latest desktop image (BGRA), always valid after first frame.
    pub tex: ID3D11Texture2D,
    pub have_frame: bool,
}

#[derive(Default, Debug, Clone)]
pub struct FrameInfo {
    pub updated: bool,
    pub dirty_rects: u32,
    pub move_rects: u32,
    pub pointer_pos: Option<(i32, i32, bool)>,
    pub pointer_shape: Option<PointerShape>,
}

#[derive(Debug, Clone)]
pub struct PointerShape { pub kind: u32, pub w: u32, pub h: u32, pub pitch: u32, pub hx: i32, pub hy: i32, pub data: Vec<u8> }

pub fn bgra_texture(dev: &ID3D11Device, w: u32, h: u32, fmt: DXGI_FORMAT, bind: u32) -> Result<ID3D11Texture2D> {
    let d = D3D11_TEXTURE2D_DESC {
        Width: w, Height: h, MipLevels: 1, ArraySize: 1, Format: fmt,
        SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
        Usage: D3D11_USAGE_DEFAULT, BindFlags: bind, CPUAccessFlags: 0, MiscFlags: 0,
    };
    let mut t = None;
    unsafe { dev.CreateTexture2D(&d, None, Some(&mut t))? };
    Ok(t.unwrap())
}

const E_NOINTERFACE_HR: i32 = 0x80004002u32 as i32;
const DXGI_UNSUPPORTED_HR: i32 = 0x887A0004u32 as i32;
const DXGI_NOT_FOUND_HR: i32 = 0x887A0002u32 as i32;
const DXGI_NOT_CURRENTLY_AVAILABLE_HR: i32 = 0x887A0022u32 as i32;
const E_NOTIMPL_HR: i32 = 0x80004001u32 as i32;

/// DXGI failures where Desktop Duplication can never work on this machine/session, so GDI
/// BitBlt is the right answer. Transient ones (ACCESS_LOST, ACCESS_DENIED on the secure
/// desktop, WAIT_TIMEOUT) are NOT included: those keep the existing DXGI retry/reopen logic.
pub fn gdi_fallback_eligible(hr: i32) -> bool {
    matches!(hr, E_NOINTERFACE_HR | DXGI_UNSUPPORTED_HR | DXGI_NOT_FOUND_HR | DXGI_NOT_CURRENTLY_AVAILABLE_HR | E_NOTIMPL_HR)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CaptureMode { Auto, ForceGdi, DxgiOnly }

pub fn capture_mode_from(v: Option<&str>) -> CaptureMode {
    match v.map(|x| x.trim().to_ascii_lowercase()) {
        Some(ref x) if x == "gdi" => CaptureMode::ForceGdi,
        Some(ref x) if x == "dxgi" => CaptureMode::DxgiOnly,
        _ => CaptureMode::Auto,
    }
}

fn capture_mode() -> CaptureMode { capture_mode_from(std::env::var("ASTERIA_CAPTURE").ok().as_deref()) }

/// Adapters in low-power-first order when IDXGIFactory6 exists (Win10 1803+), else plain DXGI 1.1 order.
unsafe fn enum_adapters() -> Result<Vec<IDXGIAdapter1>> {
    let mut adapters: Vec<IDXGIAdapter1> = vec![];
    if let Ok(f6) = CreateDXGIFactory1::<IDXGIFactory6>() {
        let mut i = 0;
        while let Ok(a) = f6.EnumAdapterByGpuPreference::<IDXGIAdapter1>(i, DXGI_GPU_PREFERENCE_MINIMUM_POWER) { adapters.push(a); i += 1; }
        if !adapters.is_empty() { return Ok(adapters); }
    }
    let f1: IDXGIFactory1 = CreateDXGIFactory1()?;
    let mut i = 0;
    while let Ok(a) = f1.EnumAdapters1(i) { adapters.push(a); i += 1; }
    Ok(adapters)
}

/// D3D11 device for the GDI path: hardware (default adapter) with/without video support, then WARP.
unsafe fn make_device() -> Result<(ID3D11Device, ID3D11DeviceContext, String)> {
    let fl = [D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_1, D3D_FEATURE_LEVEL_10_0, D3D_FEATURE_LEVEL_9_3, D3D_FEATURE_LEVEL_9_1];
    let bgra = D3D11_CREATE_DEVICE_BGRA_SUPPORT;
    let warp_only = std::env::var("ASTERIA_D3D_WARP").map(|v| v == "1").unwrap_or(false);
    let mut last = Error::new(E_FAIL, "D3D11CreateDevice");
    for (ty, fl_) in [(D3D_DRIVER_TYPE_HARDWARE, bgra | D3D11_CREATE_DEVICE_VIDEO_SUPPORT), (D3D_DRIVER_TYPE_HARDWARE, bgra), (D3D_DRIVER_TYPE_WARP, bgra)].into_iter().skip(if warp_only { 2 } else { 0 }) {
        let (mut device, mut ctx) = (None, None);
        match D3D11CreateDevice(None, ty, HMODULE::default(), fl_, Some(&fl), D3D11_SDK_VERSION, Some(&mut device), None, Some(&mut ctx)) {
            Ok(()) => {
                let device: ID3D11Device = device.unwrap();
                let name = device.cast::<IDXGIDevice>().ok().and_then(|d| d.GetAdapter().ok()).and_then(|a| a.GetDesc().ok())
                    .map(|d| String::from_utf16_lossy(&d.Description).trim_end_matches('\0').to_string()).unwrap_or_else(|| "WARP".into());
                if let Ok(mt) = device.cast::<ID3D11Multithread>() { let _ = mt.SetMultithreadProtected(true); }
                return Ok((device, ctx.unwrap(), name));
            }
            Err(e) => last = Error::new(e.code(), format!("D3D11CreateDevice: {}", e.message())),
        }
    }
    Err(last)
}

/// Monitor rectangles, primary first, then enumeration order (matches desk::monitors indices after primary).
pub fn monitor_rects() -> Vec<RECT> {
    unsafe extern "system" fn cb(h: HMONITOR, _: HDC, _: *mut RECT, l: LPARAM) -> BOOL {
        let v = &mut *(l.0 as *mut Vec<(bool, RECT)>);
        let mut mi = MONITORINFO { cbSize: std::mem::size_of::<MONITORINFO>() as u32, ..Default::default() };
        if GetMonitorInfoW(h, &mut mi).as_bool() { v.push(((mi.dwFlags & 1) != 0, mi.rcMonitor)); }
        TRUE
    }
    let mut v: Vec<(bool, RECT)> = vec![];
    unsafe { let _ = EnumDisplayMonitors(HDC::default(), None, Some(cb), LPARAM(&mut v as *mut _ as isize)); }
    v.sort_by_key(|(p, _)| !*p); // stable: primary first
    v.into_iter().map(|(_, r)| r).collect()
}

/// Even-sized capture size for a monitor rect (H.264 needs even dimensions).
pub fn even_size(r: &RECT) -> (u32, u32) {
    (((r.right - r.left).max(2) as u32) & !1, ((r.bottom - r.top).max(2) as u32) & !1)
}

/// FNV-1a over 8-byte words: cheap change detection so static desktops don't re-upload/encode.
pub fn frame_hash(b: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    let mut it = b.chunks_exact(8);
    for c in &mut it { h ^= u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]); h = h.wrapping_mul(0x100000001b3); }
    for &x in it.remainder() { h ^= x as u64; h = h.wrapping_mul(0x100000001b3); }
    h
}

/// GDI BitBlt screen source (works on Server 2016, Basic Display Adapter, RDP-backed consoles).
pub struct GdiSrc { pub rect: RECT, buf: Vec<u8>, last_hash: u64 }

impl GdiSrc {
    unsafe fn grab(&mut self, w: u32, h: u32) -> Result<bool> {
        let screen = GetDC(HWND::default());
        if screen.is_invalid() { return Err(Error::new(E_ACCESSDENIED, "GetDC(screen) failed")); }
        let mem = CreateCompatibleDC(screen);
        let mut bi = BITMAPINFO::default();
        bi.bmiHeader = BITMAPINFOHEADER { biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32, biWidth: w as i32, biHeight: -(h as i32), biPlanes: 1, biBitCount: 32, biCompression: BI_RGB.0, ..Default::default() };
        let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
        let dib = match CreateDIBSection(screen, &bi, DIB_RGB_COLORS, &mut bits, HANDLE::default(), 0) {
            Ok(b) => b,
            Err(e) => { let _ = DeleteDC(mem); ReleaseDC(HWND::default(), screen); return Err(e); }
        };
        let old = SelectObject(mem, dib);
        let r = BitBlt(mem, 0, 0, w as i32, h as i32, screen, self.rect.left, self.rect.top, ROP_CODE(SRCCOPY.0 | CAPTUREBLT.0));
        if r.is_ok() { draw_cursor(mem, &self.rect); }
        let _ = GdiFlush();
        let n = (w * h * 4) as usize;
        if r.is_ok() && !bits.is_null() {
            self.buf.resize(n, 0);
            std::ptr::copy_nonoverlapping(bits as *const u8, self.buf.as_mut_ptr(), n);
        }
        SelectObject(mem, old);
        let _ = DeleteObject(dib);
        let _ = DeleteDC(mem);
        ReleaseDC(HWND::default(), screen);
        r.map_err(|e| Error::new(e.code(), format!("BitBlt: {}", e.message())))?;
        let hh = frame_hash(&self.buf);
        let changed = hh != self.last_hash;
        self.last_hash = hh;
        Ok(changed)
    }
}

unsafe fn draw_cursor(mem: HDC, rect: &RECT) {
    let mut ci = CURSORINFO { cbSize: std::mem::size_of::<CURSORINFO>() as u32, ..Default::default() };
    if GetCursorInfo(&mut ci).is_err() || (ci.flags.0 & CURSOR_SHOWING.0) == 0 || ci.hCursor.is_invalid() { return; }
    let icon = HICON(ci.hCursor.0);
    let mut ii = ICONINFO::default();
    let (mut hx, mut hy) = (0i32, 0i32);
    if GetIconInfo(icon, &mut ii).is_ok() {
        hx = ii.xHotspot as i32; hy = ii.yHotspot as i32;
        if !ii.hbmMask.is_invalid() { let _ = DeleteObject(ii.hbmMask); }
        if !ii.hbmColor.is_invalid() { let _ = DeleteObject(ii.hbmColor); }
    }
    let _ = DrawIconEx(mem, ci.ptScreenPos.x - rect.left - hx, ci.ptScreenPos.y - rect.top - hy, icon, 0, 0, 0, HBRUSH::default(), DI_NORMAL);
}

impl Dup {
    /// DXGI first (unless forced), GDI BitBlt when duplication can't work here.
    pub fn new(output_index: u32) -> Result<Self> {
        match capture_mode() {
            CaptureMode::ForceGdi => Self::new_gdi(output_index),
            CaptureMode::DxgiOnly => Self::new_dxgi(output_index),
            CaptureMode::Auto => match Self::new_dxgi(output_index) {
                Ok(d) => Ok(d),
                Err(e) if gdi_fallback_eligible(e.code().0) => Self::new_gdi(output_index)
                    .map_err(|g| Error::new(e.code(), format!("{} (GDI fallback: {})", e.message(), g.message()))),
                Err(e) => Err(e),
            },
        }
    }

    pub fn new_gdi(output_index: u32) -> Result<Self> {
        unsafe {
            let rects = monitor_rects();
            let rect = *rects.get(output_index as usize).or(rects.first()).ok_or_else(|| Error::new(DXGI_ERROR_NOT_FOUND, "no monitor"))?;
            let (w, h) = even_size(&rect);
            let (device, ctx, name) = make_device()?;
            let tex = bgra_texture(&device, w, h, DXGI_FORMAT_B8G8R8A8_UNORM, (D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0) as u32)?;
            Ok(Dup { device, ctx, adapter_name: format!("{name} [GDI]"), dup: None, output: None,
                     gdi: Some(GdiSrc { rect, buf: vec![], last_hash: 0 }), method: "gdi", w, h, tex, have_frame: false })
        }
    }

    /// `output_index` counts unique monitors. Hybrid GPUs (Optimus) may list the same monitor under
    /// the dGPU where DuplicateOutput returns DXGI_ERROR_UNSUPPORTED, so every adapter exposing the
    /// monitor is tried, low-power adapter first.
    pub fn new_dxgi(output_index: u32) -> Result<Self> {
        unsafe {
            let adapters = enum_adapters()?;
            let mut monitors: Vec<isize> = vec![];
            let mut cands: Vec<(isize, IDXGIAdapter1, IDXGIOutput)> = vec![];
            for a in &adapters {
                let mut oi = 0;
                while let Ok(o) = a.EnumOutputs(oi) {
                    if let Ok(od) = o.GetDesc() {
                        let m = od.Monitor.0 as isize;
                        if !monitors.contains(&m) { monitors.push(m); }
                        cands.push((m, a.clone(), o));
                    }
                    oi += 1;
                }
            }
            let target = *monitors.get(output_index as usize).ok_or_else(|| Error::new(DXGI_ERROR_NOT_FOUND, "output index not found"))?;
            let mut last = Error::new(DXGI_ERROR_NOT_FOUND, "no adapter could duplicate output");
            for (m, a, o) in cands.into_iter().filter(|c| c.0 == target) {
                let _ = m;
                match Self::open_on(&a, &o) { Ok(s) => return Ok(s), Err(e) => { let d = a.GetDesc1().unwrap_or_default(); last = Error::new(e.code(), format!("{} on {}", e.message(), String::from_utf16_lossy(&d.Description).trim_end_matches('\0'))) } }
            }
            Err(last)
        }
    }

    unsafe fn open_on(a: &IDXGIAdapter1, o: &IDXGIOutput) -> Result<Self> {
        let d = a.GetDesc1()?;
        let name = String::from_utf16_lossy(&d.Description).trim_end_matches('\0').to_string();
        // GPU-less servers (Microsoft Basic Render Driver / WARP) reject VIDEO_SUPPORT and FL 11_0-only requests:
        // try the output's adapter with video support, then without, then WARP; feature levels down to 9_1.
        let fl = [D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_1, D3D_FEATURE_LEVEL_10_0, D3D_FEATURE_LEVEL_9_3, D3D_FEATURE_LEVEL_9_1];
        let bgra = D3D11_CREATE_DEVICE_BGRA_SUPPORT;
        let mut made: Option<(ID3D11Device, ID3D11DeviceContext)> = None;
        let mut last = Error::new(E_FAIL, "D3D11CreateDevice");
        let warp_only = std::env::var("ASTERIA_D3D_WARP").map(|v| v == "1").unwrap_or(false); // test switch: emulate GPU-less server
        for (ad, ty, fl_) in [(Some(a), D3D_DRIVER_TYPE_UNKNOWN, bgra | D3D11_CREATE_DEVICE_VIDEO_SUPPORT), (Some(a), D3D_DRIVER_TYPE_UNKNOWN, bgra), (None, D3D_DRIVER_TYPE_WARP, bgra)].into_iter().skip(if warp_only { 1 } else { 0 }) {
            let (mut device, mut ctx) = (None, None);
            let ia: Option<IDXGIAdapter> = ad.and_then(|x| x.cast().ok());
            match D3D11CreateDevice(ia.as_ref(), ty, HMODULE::default(), fl_, Some(&fl), D3D11_SDK_VERSION, Some(&mut device), None, Some(&mut ctx)) {
                Ok(()) => { made = Some((device.unwrap(), ctx.unwrap())); break; }
                Err(e) => last = Error::new(e.code(), format!("D3D11CreateDevice: {}", e.message())),
            }
        }
        let (device, ctx) = made.ok_or(last)?;
        let ctx = Some(ctx);
        if let Ok(mt) = device.cast::<ID3D11Multithread>() { let _ = mt.SetMultithreadProtected(true); }
        let output: IDXGIOutput1 = o.cast()?;
        let od = o.GetDesc()?;
        let r = od.DesktopCoordinates;
        let (w, h) = (((r.right - r.left) as u32) & !1, ((r.bottom - r.top) as u32) & !1);
        let tex = bgra_texture(&device, w, h, DXGI_FORMAT_B8G8R8A8_UNORM,
            (D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0) as u32)?;
        let mut s = Dup { device, ctx: ctx.unwrap(), adapter_name: name, dup: None, output: Some(output), gdi: None, method: "dxgi", w, h, tex, have_frame: false };
        s.reopen()?;
        Ok(s)
    }

    /// Re-create duplication (after ACCESS_LOST / desktop switch). Caller re-attaches thread desktop first.
    pub fn reopen(&mut self) -> Result<()> {
        self.dup = None;
        let output = match &self.output { Some(o) => o.clone(), None => return Ok(()) }; // GDI: a fresh screen DC is taken per frame
        unsafe {
            // Prefer DuplicateOutput1 (DXGI 1.5, needs per-monitor DPI awareness), fall back to DuplicateOutput.
            if let Ok(o5) = output.cast::<IDXGIOutput5>() {
                if let Ok(d) = o5.DuplicateOutput1(&self.device, 0, &[DXGI_FORMAT_B8G8R8A8_UNORM]) { self.dup = Some(d); return Ok(()); }
            }
            self.dup = Some(output.DuplicateOutput(&self.device).map_err(|e| Error::new(e.code(), format!("DuplicateOutput: {}", e.message())))?);
        }
        Ok(())
    }

    pub fn next(&mut self, timeout_ms: u32) -> Result<Option<FrameInfo>> {
        if self.gdi.is_some() { return self.next_gdi(timeout_ms); }
        let dup = match &self.dup { Some(d) => d.clone(), None => { self.reopen()?; self.dup.clone().unwrap() } };
        let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut res: Option<IDXGIResource> = None;
        unsafe {
            if let Err(e) = dup.AcquireNextFrame(timeout_ms, &mut info, &mut res) {
                if e.code() == DXGI_ERROR_WAIT_TIMEOUT { return Ok(None); }
                self.dup = None;
                return Err(e);
            }
            let mut fi = FrameInfo::default();
            if info.LastPresentTime != 0 {
                if let Some(r) = &res {
                    let t: ID3D11Texture2D = r.cast()?;
                    let mut d = D3D11_TEXTURE2D_DESC::default(); t.GetDesc(&mut d);
                    let bx = D3D11_BOX { left: 0, top: 0, front: 0, right: self.w.min(d.Width), bottom: self.h.min(d.Height), back: 1 };
                    self.ctx.CopySubresourceRegion(&self.tex, 0, 0, 0, 0, &t, 0, Some(&bx));
                    fi.updated = true; self.have_frame = true;
                }
                if info.TotalMetadataBufferSize > 0 {
                    let mut buf = vec![0u8; info.TotalMetadataBufferSize as usize];
                    let mut used = 0u32;
                    if dup.GetFrameMoveRects(buf.len() as u32, buf.as_mut_ptr() as *mut _, &mut used).is_ok() {
                        fi.move_rects = used / std::mem::size_of::<DXGI_OUTDUPL_MOVE_RECT>() as u32;
                    }
                    if dup.GetFrameDirtyRects(buf.len() as u32, buf.as_mut_ptr() as *mut _, &mut used).is_ok() {
                        fi.dirty_rects = used / std::mem::size_of::<RECT>() as u32;
                    }
                }
            }
            if info.LastMouseUpdateTime != 0 {
                fi.pointer_pos = Some((info.PointerPosition.Position.x, info.PointerPosition.Position.y, info.PointerPosition.Visible.as_bool()));
                if info.PointerShapeBufferSize > 0 {
                    let mut data = vec![0u8; info.PointerShapeBufferSize as usize];
                    let mut used = 0u32; let mut si = DXGI_OUTDUPL_POINTER_SHAPE_INFO::default();
                    if dup.GetFramePointerShape(data.len() as u32, data.as_mut_ptr() as *mut _, &mut used, &mut si).is_ok() {
                        data.truncate(used as usize);
                        fi.pointer_shape = Some(PointerShape { kind: si.Type, w: si.Width, h: si.Height, pitch: si.Pitch, hx: si.HotSpot.x, hy: si.HotSpot.y, data });
                    }
                }
            }
            let _ = dup.ReleaseFrame();
            Ok(Some(fi))
        }
    }

    fn next_gdi(&mut self, timeout_ms: u32) -> Result<Option<FrameInfo>> {
        let (w, h) = (self.w, self.h);
        let g = self.gdi.as_mut().unwrap();
        let changed = unsafe { g.grab(w, h)? };
        let mut fi = FrameInfo::default();
        if changed || !self.have_frame {
            unsafe { self.ctx.UpdateSubresource(&self.tex, 0, None, g.buf.as_ptr() as *const _, w * 4, 0); }
            self.have_frame = true;
            fi.updated = true;
        } else if timeout_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(timeout_ms.min(50) as u64)); // mimic AcquireNextFrame wait
        }
        let mut p = POINT::default();
        if unsafe { GetCursorPos(&mut p) }.is_ok() {
            fi.pointer_pos = Some((p.x - g.rect.left, p.y - g.rect.top, true));
        }
        Ok(Some(fi))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e_nointerface_falls_back_to_gdi() {
        // Server 2016: CreateDXGIFactory1::<IDXGIFactory6>() / duplication -> 0x80004002
        assert!(gdi_fallback_eligible(0x80004002u32 as i32));
        assert!(gdi_fallback_eligible(0x887A0004u32 as i32)); // DXGI_ERROR_UNSUPPORTED
        assert!(gdi_fallback_eligible(0x887A0002u32 as i32)); // DXGI_ERROR_NOT_FOUND (no DXGI output)
        assert!(gdi_fallback_eligible(0x887A0022u32 as i32)); // NOT_CURRENTLY_AVAILABLE (RDP-owned console)
    }

    #[test]
    fn transient_errors_keep_dxgi_retry() {
        assert!(!gdi_fallback_eligible(0x887A0026u32 as i32)); // ACCESS_LOST
        assert!(!gdi_fallback_eligible(0x887A0027u32 as i32)); // WAIT_TIMEOUT
        assert!(!gdi_fallback_eligible(0x80070005u32 as i32)); // E_ACCESSDENIED (secure desktop)
        assert!(!gdi_fallback_eligible(0));
    }

    #[test]
    fn capture_mode_parsing() {
        assert_eq!(capture_mode_from(None), CaptureMode::Auto);
        assert_eq!(capture_mode_from(Some("GDI")), CaptureMode::ForceGdi);
        assert_eq!(capture_mode_from(Some(" dxgi ")), CaptureMode::DxgiOnly);
        assert_eq!(capture_mode_from(Some("other")), CaptureMode::Auto);
    }

    #[test]
    fn even_dimensions() {
        let r = RECT { left: -1921, top: 0, right: 0, bottom: 1081 };
        assert_eq!(even_size(&r), (1920, 1080));
        let tiny = RECT { left: 0, top: 0, right: 1, bottom: 1 };
        assert_eq!(even_size(&tiny), (2, 2));
    }

    #[test]
    fn frame_hash_detects_change() {
        let a = vec![7u8; 4 * 64 * 64 + 3];
        let mut b = a.clone();
        assert_eq!(frame_hash(&a), frame_hash(&b));
        b[1234] ^= 1;
        assert_ne!(frame_hash(&a), frame_hash(&b));
        b[1234] ^= 1; let n = b.len() - 1; b[n] ^= 0x80; // remainder bytes count too
        assert_ne!(frame_hash(&a), frame_hash(&b));
    }

    /// Live smoke (Windows only, needs an interactive desktop): `cargo test -- --ignored gdi_live`
    #[test]
    #[ignore]
    fn gdi_live_capture_produces_frame() {
        let mut d = Dup::new_gdi(0).expect("gdi init");
        assert_eq!(d.method, "gdi");
        let f = d.next(0).expect("grab").expect("frame");
        assert!(f.updated && d.have_frame && d.w >= 2 && d.h >= 2);
    }
}
