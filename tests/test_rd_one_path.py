"""C-RD-ONE: single WebRTC path — no helper JPEG live."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_hw_early_return_skips_helper_jpeg():
    src = (ROOT / "client_remote_desktop.py").read_text(encoding="utf-8")
    assert "transport=webrtc_hw signaling=ws" in src
    assert "remote stream started (webrtc_hw)" in src
    assert "jpeg-ws fallback" not in src or src.count("jpeg-ws fallback") == 0


def test_sidecar_exit_stops_stream():
    src = (ROOT / "client_remote_desktop.py").read_text(encoding="utf-8")
    assert 'self.stop(reason="VIDEO_ENCODER_FAILED")' in src


def test_capture_loop_skips_when_hw_active():
    src = (ROOT / "client_remote_desktop.py").read_text(encoding="utf-8")
    assert '_transport == "webrtc_hw"' in src
    assert "self._stop.wait(0.25)" in src


def test_sidecar_single_ctrl_channel():
    src = (ROOT / "sidecar/asteria-encode/src/rtc.rs").read_text(encoding="utf-8")
    assert 'add_channel("ctrl"' in src
    assert "input-u" not in src
    assert "input-r" not in src


def test_contract_one_path():
    croot = ROOT.parent / "asteria-contract"
    ver = (croot / "VERSION").read_text(encoding="utf-8").strip()
    assert ver == "1.4.100"
    hw = (croot / "features/remote-desktop-hw.md").read_text(encoding="utf-8")
    assert "C-RD-ONE-1" in hw and "C-RD-ONE-2" in hw
