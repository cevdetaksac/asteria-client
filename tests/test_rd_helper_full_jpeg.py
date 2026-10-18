"""C-RD-HELPER-JPEG: helper must emit a full JPEG on every tick of a static screen."""
from PIL import Image
import client_remote_desktop as r


def test_static_frame_full_jpeg_when_tiles_disabled():
    s = r.RemoteDesktopStreamer()
    s._disable_tiles = True
    s._capture_screen_image = lambda: (Image.new("RGB", (640, 360), (30, 60, 90)), "printwindow-logonui")
    s._capture_w, s._capture_h = 640, 360
    sizes = [len(s._grab_jpeg()[0] or b"") for _ in range(3)]
    assert all(n >= r.MIN_JPEG_BYTES for n in sizes), sizes
    assert sizes[0] == sizes[1] == sizes[2]


def test_session_helper_disables_tiles():
    src = open("client_rd_session_helper.py", encoding="utf-8").read()
    assert "rd._disable_tiles = True" in src
