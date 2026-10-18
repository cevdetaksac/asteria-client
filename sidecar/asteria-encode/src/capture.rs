//! DXGI Desktop Duplication (C-RD-HW-3).
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Direct3D::*;
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::*;
use windows::Win32::Graphics::Dxgi::*;

pub struct Dup {
    pub device: ID3D11Device,
    pub ctx: ID3D11DeviceContext,
    pub adapter_name: String,
    dup: Option<IDXGIOutputDuplication>,
    output: IDXGIOutput1,
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

impl Dup {
    /// `output_index` counts unique monitors. Hybrid GPUs (Optimus) may list the same monitor under
    /// the dGPU where DuplicateOutput returns DXGI_ERROR_UNSUPPORTED, so every adapter exposing the
    /// monitor is tried, low-power adapter first.
    pub fn new(output_index: u32) -> Result<Self> {
        unsafe {
            let f6: IDXGIFactory6 = CreateDXGIFactory1()?;
            let mut adapters: Vec<IDXGIAdapter1> = vec![];
            let mut i = 0;
            while let Ok(a) = f6.EnumAdapterByGpuPreference::<IDXGIAdapter1>(i, DXGI_GPU_PREFERENCE_MINIMUM_POWER) { adapters.push(a); i += 1; }
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
        let mut device = None; let mut ctx = None;
        D3D11CreateDevice(a, D3D_DRIVER_TYPE_UNKNOWN, HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
            Some(&[D3D_FEATURE_LEVEL_11_0]), D3D11_SDK_VERSION,
            Some(&mut device), None, Some(&mut ctx)).map_err(|e| Error::new(e.code(), format!("D3D11CreateDevice: {}", e.message())))?;
        let device: ID3D11Device = device.unwrap();
        if let Ok(mt) = device.cast::<ID3D11Multithread>() { let _ = mt.SetMultithreadProtected(true); }
        let output: IDXGIOutput1 = o.cast()?;
        let od = o.GetDesc()?;
        let r = od.DesktopCoordinates;
        let (w, h) = (((r.right - r.left) as u32) & !1, ((r.bottom - r.top) as u32) & !1);
        let tex = bgra_texture(&device, w, h, DXGI_FORMAT_B8G8R8A8_UNORM,
            (D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0) as u32)?;
        let mut s = Dup { device, ctx: ctx.unwrap(), adapter_name: name, dup: None, output, w, h, tex, have_frame: false };
        s.reopen()?;
        Ok(s)
    }

    /// Re-create duplication (after ACCESS_LOST / desktop switch). Caller re-attaches thread desktop first.
    pub fn reopen(&mut self) -> Result<()> {
        self.dup = None;
        unsafe {
            // Prefer DuplicateOutput1 (DXGI 1.5, needs per-monitor DPI awareness), fall back to DuplicateOutput.
            if let Ok(o5) = self.output.cast::<IDXGIOutput5>() {
                if let Ok(d) = o5.DuplicateOutput1(&self.device, 0, &[DXGI_FORMAT_B8G8R8A8_UNORM]) { self.dup = Some(d); return Ok(()); }
            }
            self.dup = Some(self.output.DuplicateOutput(&self.device).map_err(|e| Error::new(e.code(), format!("DuplicateOutput: {}", e.message())))?);
        }
        Ok(())
    }

    pub fn next(&mut self, timeout_ms: u32) -> Result<Option<FrameInfo>> {
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
}
