//! Media Foundation H.264 encoder (C-RD-HW-4). Hardware async MFT with D3D11 NV12 input.
use std::mem::ManuallyDrop;
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::*;
use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::CoTaskMemFree;

use crate::capture::bgra_texture;

pub struct Encoded { pub data: Vec<u8>, pub key: bool, pub ts100ns: i64 }

pub struct Enc {
    pub name: String,
    mft: IMFTransform,
    events: Option<IMFMediaEventGenerator>,
    codec: Option<ICodecAPI>,
    vdev: ID3D11VideoDevice,
    vctx: ID3D11VideoContext,
    vpe: ID3D11VideoProcessorEnumerator,
    vp: ID3D11VideoProcessor,
    ring: Vec<(ID3D11Texture2D, ID3D11VideoProcessorOutputView)>,
    ring_i: usize,
    in_view: Option<(usize, ID3D11VideoProcessorInputView)>,
    ctx: ID3D11DeviceContext,
    need_input: u32,
    provides_samples: bool,
    out_size: u32,
    pub w: u32, pub h: u32, pub fps: u32, pub bitrate: u32,
    _mgr: IMFDXGIDeviceManager,
    pub sw: bool,
    staging: Option<ID3D11Texture2D>,
}

unsafe fn friendly(a: &IMFActivate) -> String {
    let mut p = PWSTR::null(); let mut len = 0;
    if a.GetAllocatedString(&MFT_FRIENDLY_NAME_Attribute, &mut p, &mut len).is_ok() {
        let s = p.to_string().unwrap_or_default(); CoTaskMemFree(Some(p.0 as _)); s
    } else { String::new() }
}

fn vendor_hint(adapter: &str) -> &'static str {
    let l = adapter.to_lowercase();
    if l.contains("nvidia") { "nvidia" } else if l.contains("intel") { "intel" } else if l.contains("amd") || l.contains("radeon") { "amd" } else { "" }
}

fn var_u32(v: u32) -> VARIANT { VARIANT::from(v) }

impl Enc {
    pub fn new(device: &ID3D11Device, ctx: &ID3D11DeviceContext, adapter_name: &str, w: u32, h: u32, fps: u32, bitrate: u32) -> Result<Self> {
        unsafe {
            // --- pick HW MFT matching capture adapter vendor
            let info_out = MFT_REGISTER_TYPE_INFO { guidMajorType: MFMediaType_Video, guidSubtype: MFVideoFormat_H264 };
            let mut acts: *mut Option<IMFActivate> = std::ptr::null_mut(); let mut n = 0u32;
            // Prefer hardware MFT (QSV/NVENC/AMF); fall back to Microsoft software H.264 MFT.
            MFTEnumEx(MFT_CATEGORY_VIDEO_ENCODER, MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER, None, Some(&info_out), &mut acts, &mut n)?;
            let mut list: Vec<IMFActivate> = std::slice::from_raw_parts(acts, n as usize).iter().filter_map(|a| a.clone()).collect();
            CoTaskMemFree(Some(acts as _));
            let force_sw = std::env::var("ASTERIA_ENC_FORCE_SW").map(|v| v == "1").unwrap_or(false);
            if force_sw { list.clear(); }
            let mut hardware = !list.is_empty();
            if list.is_empty() {
                acts = std::ptr::null_mut(); n = 0;
                MFTEnumEx(
                    MFT_CATEGORY_VIDEO_ENCODER,
                    MFT_ENUM_FLAG_SYNCMFT | MFT_ENUM_FLAG_ASYNCMFT | MFT_ENUM_FLAG_SORTANDFILTER,
                    None,
                    Some(&info_out),
                    &mut acts,
                    &mut n,
                )?;
                list = std::slice::from_raw_parts(acts, n as usize).iter().filter_map(|a| a.clone()).collect();
                CoTaskMemFree(Some(acts as _));
                hardware = false;
            }
            let hint = vendor_hint(adapter_name);
            let chosen = if hardware {
                list.iter().find(|a| friendly(a).to_lowercase().contains(hint)).or(list.first())
            } else {
                // Prefer Microsoft software encoder name when present
                list.iter().find(|a| {
                    let n = friendly(a).to_lowercase();
                    n.contains("microsoft") || n.contains("h264") || n.contains("h.264")
                }).or(list.first())
            }
                .ok_or_else(|| Error::new(E_FAIL, "no H.264 MFT (hardware or software)"))?;
            let name = format!("{}{}", friendly(chosen), if hardware { "" } else { " (software)" });
            let mft: IMFTransform = chosen.ActivateObject()?;
            if let Ok(attrs) = mft.GetAttributes() {
                if hardware {
                    let _ = attrs.SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1);
                }
                let _ = attrs.SetUINT32(&MF_LOW_LATENCY, 1);
            }

            // --- D3D manager (HW path). Software MFT may reject D3D manager.
            let mut token = 0u32; let mut mgr = None;
            MFCreateDXGIDeviceManager(&mut token, &mut mgr)?;
            let mgr: IMFDXGIDeviceManager = mgr.unwrap();
            mgr.ResetDevice(device, token)?;
            if hardware {
                mft.ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, mgr.as_raw() as usize)?;
            }

            let codec: Option<ICodecAPI> = mft.cast().ok();
            if let Some(c) = &codec {
                let _ = c.SetValue(&CODECAPI_AVLowLatencyMode, &var_u32(1));
                let _ = c.SetValue(&CODECAPI_AVEncCommonRateControlMode, &var_u32(eAVEncCommonRateControlMode_CBR.0 as u32));
                let _ = c.SetValue(&CODECAPI_AVEncCommonMeanBitRate, &var_u32(bitrate));
                let _ = c.SetValue(&CODECAPI_AVEncMPVDefaultBPictureCount, &var_u32(0));
                let _ = c.SetValue(&CODECAPI_AVEncMPVGOPSize, &var_u32(0)); // infinite GOP, IDR on demand
                let _ = c.SetValue(&CODECAPI_AVEncCommonQualityVsSpeed, &var_u32(0)); // 0 = fastest
            }

            // --- output type then input type
            let ot = MFCreateMediaType()?;
            ot.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
            ot.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264)?;
            ot.SetUINT32(&MF_MT_AVG_BITRATE, bitrate)?;
            ot.SetUINT64(&MF_MT_FRAME_SIZE, ((w as u64) << 32) | h as u64)?;
            ot.SetUINT64(&MF_MT_FRAME_RATE, ((fps as u64) << 32) | 1)?;
            ot.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, (1u64 << 32) | 1)?;
            ot.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
            ot.SetUINT32(&MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_ConstrainedBase.0 as u32)?;
            if mft.SetOutputType(0, &ot, 0).is_err() {
                ot.SetUINT32(&MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_Base.0 as u32)?;
                mft.SetOutputType(0, &ot, 0)?;
            }
            let it = MFCreateMediaType()?;
            it.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
            it.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12)?;
            it.SetUINT64(&MF_MT_FRAME_SIZE, ((w as u64) << 32) | h as u64)?;
            it.SetUINT64(&MF_MT_FRAME_RATE, ((fps as u64) << 32) | 1)?;
            it.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
            mft.SetInputType(0, &it, 0)?;

            let si = mft.GetOutputStreamInfo(0)?;
            let provides_samples = (si.dwFlags & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32 | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES.0 as u32)) != 0;
            let events: Option<IMFMediaEventGenerator> = mft.cast().ok();

            if hardware { mft.ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0)?; } else { let _ = mft.ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0); }
            mft.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)?;
            mft.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)?;

            // --- BGRA -> NV12 video processor
            let vdev: ID3D11VideoDevice = device.cast()?;
            let vctx: ID3D11VideoContext = ctx.cast()?;
            let cd = D3D11_VIDEO_PROCESSOR_CONTENT_DESC {
                InputFrameFormat: D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
                InputFrameRate: DXGI_RATIONAL { Numerator: fps, Denominator: 1 }, InputWidth: w, InputHeight: h,
                OutputFrameRate: DXGI_RATIONAL { Numerator: fps, Denominator: 1 }, OutputWidth: w, OutputHeight: h,
                Usage: D3D11_VIDEO_USAGE_OPTIMAL_SPEED,
            };
            let vpe = vdev.CreateVideoProcessorEnumerator(&cd)?;
            let vp = vdev.CreateVideoProcessor(&vpe, 0)?;
            // BT.709 limited output, full-range RGB input
            let cs_in = D3D11_VIDEO_PROCESSOR_COLOR_SPACE { _bitfield: 0 };
            let cs_out = D3D11_VIDEO_PROCESSOR_COLOR_SPACE { _bitfield: 0b10 | (1 << 4) }; // YCbCr_Matrix=1(709), Nominal_Range=16-235
            vctx.VideoProcessorSetStreamColorSpace(&vp, 0, &cs_in);
            vctx.VideoProcessorSetOutputColorSpace(&vp, &cs_out);
            vctx.VideoProcessorSetStreamAutoProcessingMode(&vp, 0, false);
            let mut ring = vec![];
            for _ in 0..4 {
                let t = bgra_texture(device, w, h, DXGI_FORMAT_NV12, D3D11_BIND_RENDER_TARGET.0 as u32)?;
                let od = D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC {
                    ViewDimension: D3D11_VPOV_DIMENSION_TEXTURE2D,
                    Anonymous: D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0 { Texture2D: D3D11_TEX2D_VPOV { MipSlice: 0 } },
                };
                let mut ov = None;
                vdev.CreateVideoProcessorOutputView(&t, &vpe, &od, Some(&mut ov))?;
                ring.push((t, ov.unwrap()));
            }
            let staging = if hardware { None } else {
                let d = D3D11_TEXTURE2D_DESC { Width: w, Height: h, MipLevels: 1, ArraySize: 1, Format: DXGI_FORMAT_NV12,
                    SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 }, Usage: D3D11_USAGE_STAGING,
                    BindFlags: 0, CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32, MiscFlags: 0 };
                let mut st = None; device.CreateTexture2D(&d, None, Some(&mut st))?; st
            };
            Ok(Enc { name, mft, events, codec, vdev, vctx, vpe, vp, ring, ring_i: 0, in_view: None, ctx: ctx.clone(),
                need_input: 0, provides_samples, out_size: si.cbSize.max(1 << 20), w, h, fps, bitrate, _mgr: mgr,
                sw: !hardware, staging })
        }
    }

    /// Collect outputs that became ready without submitting input (blocking up to `wait_ms` for the first).
    pub fn poll(&mut self, wait_ms: u64) -> Result<Vec<Encoded>> {
        let mut out = vec![];
        if self.events.is_none() { return Ok(out); }
        let t0 = std::time::Instant::now();
        unsafe {
            loop {
                while self.pump(false, &mut out)? {}
                if !out.is_empty() || t0.elapsed().as_millis() as u64 >= wait_ms { break; }
                std::thread::sleep(std::time::Duration::from_micros(300));
            }
        }
        Ok(out)
    }

    pub fn set_bitrate(&mut self, bps: u32) {
        self.bitrate = bps;
        if let Some(c) = &self.codec { unsafe { let _ = c.SetValue(&CODECAPI_AVEncCommonMeanBitRate, &var_u32(bps)); } }
    }

    pub fn force_keyframe(&self) {
        if let Some(c) = &self.codec { unsafe { let _ = c.SetValue(&CODECAPI_AVEncVideoForceKeyFrame, &var_u32(1)); } }
    }

    /// Convert `src` (BGRA, w x h) and submit. Returns encoded access units that became available
    /// (usually exactly the one for this frame with low-latency HW encoders).
    pub fn encode(&mut self, src: &ID3D11Texture2D, ts100ns: i64) -> Result<Vec<Encoded>> {
        let mut out = vec![];
        unsafe {
            // wait for NeedInput
            while self.events.is_some() && self.need_input == 0 { self.pump(true, &mut out)?; }
            let key = src.as_raw() as usize;
            let iv = match &self.in_view {
                Some((k, v)) if *k == key => v.clone(),
                _ => {
                    let d = D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC {
                        FourCC: 0, ViewDimension: D3D11_VPIV_DIMENSION_TEXTURE2D,
                        Anonymous: D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0 { Texture2D: D3D11_TEX2D_VPIV { MipSlice: 0, ArraySlice: 0 } },
                    };
                    let mut v = None;
                    self.vdev.CreateVideoProcessorInputView(src, &self.vpe, &d, Some(&mut v))?;
                    let v = v.unwrap(); self.in_view = Some((key, v.clone())); v
                }
            };
            let (tex, ov) = self.ring[self.ring_i].clone();
            self.ring_i = (self.ring_i + 1) % self.ring.len();
            let mut stream = D3D11_VIDEO_PROCESSOR_STREAM { Enable: TRUE, ..Default::default() };
            stream.pInputSurface = ManuallyDrop::new(Some(iv));
            let r = self.vctx.VideoProcessorBlt(&self.vp, &ov, 0, &[stream.clone()]);
            ManuallyDrop::drop(&mut stream.pInputSurface);
            r?;
            let buf = if let Some(st) = &self.staging {
                // Software MFT: GPU NV12 -> CPU memory buffer
                self.ctx.CopyResource(st, &tex);
                let mut m = D3D11_MAPPED_SUBRESOURCE::default();
                self.ctx.Map(st, 0, D3D11_MAP_READ, 0, Some(&mut m))?;
                let (w, h) = (self.w as usize, self.h as usize);
                let total = w * h * 3 / 2;
                let mb = MFCreateMemoryBuffer(total as u32)?;
                let mut dst = std::ptr::null_mut(); mb.Lock(&mut dst, None, None)?;
                let src = m.pData as *const u8; let pitch = m.RowPitch as usize;
                for r in 0..h { std::ptr::copy_nonoverlapping(src.add(r * pitch), dst.add(r * w), w); }
                let uv = src.add(pitch * h);
                for r in 0..h / 2 { std::ptr::copy_nonoverlapping(uv.add(r * pitch), dst.add(w * h + r * w), w); }
                mb.Unlock()?; self.ctx.Unmap(st, 0);
                mb.SetCurrentLength(total as u32)?;
                mb
            } else {
                let b = MFCreateDXGISurfaceBuffer(&ID3D11Texture2D::IID, &tex, 0, false)?;
                if let Ok(b2) = b.cast::<IMF2DBuffer>() { if let Ok(l) = b2.GetContiguousLength() { let _ = b.SetCurrentLength(l); } }
                b
            };
            let s = MFCreateSample()?;
            s.AddBuffer(&buf)?;
            s.SetSampleTime(ts100ns)?;
            s.SetSampleDuration(10_000_000 / self.fps as i64)?;
            self.mft.ProcessInput(0, &s, 0)?;
            if self.need_input > 0 { self.need_input -= 1; }
            let _ = &self.ctx;
            // wait for output of this frame (or a new NeedInput meaning the MFT buffers more)
            if self.events.is_some() {
                // pipelined: never wait for this frame's output here (latency is measured by ts match)
                while self.pump(false, &mut out)? {}
            } else {
                self.drain_sync(&mut out)?;
            }
        }
        Ok(out)
    }

    /// Handle one event. Returns false if none (non-blocking).
    unsafe fn pump(&mut self, block: bool, out: &mut Vec<Encoded>) -> Result<bool> {
        let ev = self.events.as_ref().unwrap();
        let flags = if block { MEDIA_EVENT_GENERATOR_GET_EVENT_FLAGS(0) } else { MF_EVENT_FLAG_NO_WAIT };
        let e = match ev.GetEvent(flags) {
            Ok(e) => e,
            Err(e) if e.code() == MF_E_NO_EVENTS_AVAILABLE => return Ok(false),
            Err(e) => return Err(e),
        };
        let t = e.GetType()?;
        if t == METransformNeedInput.0 as u32 { self.need_input += 1; }
        else if t == METransformHaveOutput.0 as u32 { self.pull(out)?; }
        Ok(true)
    }

    unsafe fn drain_sync(&mut self, out: &mut Vec<Encoded>) -> Result<()> {
        loop { if !self.pull(out)? { return Ok(()); } }
    }

    unsafe fn pull(&mut self, out: &mut Vec<Encoded>) -> Result<bool> {
        let sample = if self.provides_samples { None } else {
            let s = MFCreateSample()?; let b = MFCreateMemoryBuffer(self.out_size)?; s.AddBuffer(&b)?; Some(s)
        };
        let mut db = [MFT_OUTPUT_DATA_BUFFER { dwStreamID: 0, pSample: ManuallyDrop::new(sample), dwStatus: 0, pEvents: ManuallyDrop::new(None) }];
        let mut status = 0u32;
        let r = self.mft.ProcessOutput(0, &mut db, &mut status);
        let s = ManuallyDrop::take(&mut db[0].pSample);
        let _ev = ManuallyDrop::take(&mut db[0].pEvents);
        match r {
            Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(false),
            Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                let t = self.mft.GetOutputAvailableType(0, 0)?; self.mft.SetOutputType(0, &t, 0)?; return Ok(true);
            }
            Err(e) => return Err(e),
            Ok(()) => {}
        }
        if let Some(s) = s {
            let b = s.ConvertToContiguousBuffer()?;
            let mut p = std::ptr::null_mut(); let mut len = 0u32;
            b.Lock(&mut p, None, Some(&mut len))?;
            let data = std::slice::from_raw_parts(p, len as usize).to_vec();
            b.Unlock()?;
            let key = s.GetUINT32(&MFSampleExtension_CleanPoint).unwrap_or(0) != 0;
            let ts = s.GetSampleTime().unwrap_or(0);
            out.push(Encoded { data, key, ts100ns: ts });
        }
        Ok(true)
    }
}
