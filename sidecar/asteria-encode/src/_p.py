from pathlib import Path
p = Path("media.rs")
s = p.read_text(encoding="utf-8")
helper = '''
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
'''
# Insert before fn open_dup or after spawn
if "fn prime_frame" not in s:
    s = s.replace("fn open_dup(", helper + "\nfn open_dup(", 1)
# After every successful open_dup assign, call prime_frame
# Pattern 1: desk switch Ok(d)
old1 = '''                    Ok(d) => {
                        let resized = d.w != dup.w || d.h != dup.h;
                        dup = d; work = None; snap = None; force_key = true;
                        if resized { enc = Enc::new(&dup.device, &dup.ctx, &dup.adapter_name, dup.w, dup.h, cfg.fps, enc.bitrate).map_err(|e| format!("mft: {e}"))?; }
                        let _ = out.send(MediaOut::Event(json!({"t":"media","encoder":enc.name,"adapter":dup.adapter_name,"w":dup.w,"h":dup.h,"desktop":desktop,"resized":resized})));
                    }'''
new1 = '''                    Ok(d) => {
                        let resized = d.w != dup.w || d.h != dup.h;
                        dup = d; work = None; snap = None; force_key = true;
                        if resized { enc = Enc::new(&dup.device, &dup.ctx, &dup.adapter_name, dup.w, dup.h, cfg.fps, enc.bitrate).map_err(|e| format!("mft: {e}"))?; }
                        prime_frame(&mut dup, out);
                        let _ = out.send(MediaOut::Event(json!({"t":"media","encoder":enc.name,"adapter":dup.adapter_name,"w":dup.w,"h":dup.h,"desktop":desktop,"resized":resized})));
                    }'''
if old1 not in s: raise SystemExit('desk switch block missing')
s = s.replace(old1, new1, 1)
# ACCESS_LOST block - same Ok(d)
old2 = '''                        Ok(d) => {
                            let resized = d.w != dup.w || d.h != dup.h;
                            dup = d; work = None; snap = None; force_key = true;
                            if resized { enc = Enc::new(&dup.device, &dup.ctx, &dup.adapter_name, dup.w, dup.h, cfg.fps, enc.bitrate).map_err(|e| format!("mft: {e}"))?; }
                            let _ = out.send(MediaOut::Event(json!({"t":"desktop","name":desktop})));
                            let _ = out.send(MediaOut::Event(json!({"t":"media","encoder":enc.name,"adapter":dup.adapter_name,"w":dup.w,"h":dup.h,"desktop":desktop,"resized":resized})));
                            break;
                        }'''
new2 = '''                        Ok(d) => {
                            let resized = d.w != dup.w || d.h != dup.h;
                            dup = d; work = None; snap = None; force_key = true;
                            if resized { enc = Enc::new(&dup.device, &dup.ctx, &dup.adapter_name, dup.w, dup.h, cfg.fps, enc.bitrate).map_err(|e| format!("mft: {e}"))?; }
                            prime_frame(&mut dup, out);
                            let _ = out.send(MediaOut::Event(json!({"t":"desktop","name":desktop})));
                            let _ = out.send(MediaOut::Event(json!({"t":"media","encoder":enc.name,"adapter":dup.adapter_name,"w":dup.w,"h":dup.h,"desktop":desktop,"resized":resized})));
                            break;
                        }'''
if old2 not in s: raise SystemExit('access_lost Ok missing')
s = s.replace(old2, new2, 1)
# Periodic IDR on Winlogon / stall: before next()
old3 = '''        let fi = match dup.next(0) {'''
new3 = '''        // Lock/Winlogon or stall: force IDR every 2s so a static curtain still refreshes the viewer
        let lockish = desktop.as_deref().map(|d| d.eq_ignore_ascii_case("Winlogon") || d.to_ascii_lowercase().contains("secure")).unwrap_or(false);
        if lockish || last_sent.elapsed() > Duration::from_secs(2) { force_key = true; }
        let wait = if !dup.have_frame || force_key { 50u32 } else { 0u32 };
        let fi = match dup.next(wait) {'''
if old3 not in s: raise SystemExit('next(0) missing')
s = s.replace(old3, new3, 1)
# Need Dup import in scope - prime_frame uses Dup from capture via use
if "use crate::capture::*" not in s and "Dup" not in s[:500]:
    pass  # already use crate::capture::*
p.write_text(s, encoding="utf-8", newline="\n")
print("media patched", "prime_frame" in s, "lockish" in s)
