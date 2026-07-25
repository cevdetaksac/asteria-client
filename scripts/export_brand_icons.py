#!/usr/bin/env python3
"""Export logo_set artwork into certs/ (ICO + NSIS welcome) for installer/tray/exe.

Naming (logo_set README):
  *_light = bright ink for dark backgrounds (our GUI/tray default)
  icon_online / offline / disabled / stay = status tray variants
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
LOGO = ROOT / "logo_set"
CERTS = ROOT / "certs"
SIZES = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]


def load_rgba(name: str) -> Image.Image:
    return Image.open(LOGO / name).convert("RGBA")


def square(img: Image.Image) -> Image.Image:
    if img.width == img.height:
        return img
    side = max(img.width, img.height)
    canvas = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    canvas.paste(img, ((side - img.width) // 2, (side - img.height) // 2), img)
    return canvas


def save_ico(src: Image.Image, dest: Path) -> None:
    square(src).save(dest, format="ICO", sizes=SIZES)
    print(f"wrote {dest.name} ({dest.stat().st_size} bytes)")


def save_sized(src: Image.Image, dest: Path, size: int) -> None:
    square(src).resize((size, size), Image.Resampling.LANCZOS).save(
        dest, format="ICO", sizes=[(size, size)]
    )
    print(f"wrote {dest.name}")


def main() -> int:
    if not LOGO.is_dir():
        raise SystemExit(f"logo_set missing: {LOGO}")
    CERTS.mkdir(exist_ok=True)

    # App / installer mark — light-ink for dark taskbar
    mark = load_rgba("favicon_light.png")
    save_ico(mark, CERTS / "asteria.ico")
    for s in (16, 32, 64, 128, 256):
        save_sized(mark, CERTS / f"asteria_{s}.ico", s)

    status = {
        "online": "icon_online.png",
        "offline": "icon_offline.png",
        "disabled": "icon_disabled.png",
        "stay": "icon_stay.png",
    }
    for key, fname in status.items():
        im = load_rgba(fname)
        save_ico(im, CERTS / f"asteria_{key}.ico")
        for s in (16, 32, 64):
            save_sized(im, CERTS / f"asteria_{key}_{s}.ico", s)
        square(im).resize((64, 64), Image.Resampling.LANCZOS).save(
            CERTS / f"asteria_{key}_64.png"
        )

    # Legacy honeypot_* paths keep working (aliases of Asteria art)
    legacy = {
        "honeypot.ico": "asteria.ico",
        "honeypot_16.ico": "asteria_16.ico",
        "honeypot_32.ico": "asteria_32.ico",
        "honeypot_64.ico": "asteria_64.ico",
        "honeypot_128.ico": "asteria_128.ico",
        "honeypot_256.ico": "asteria_256.ico",
        "honeypot_active.ico": "asteria_online.ico",
        "honeypot_active_16.ico": "asteria_online_16.ico",
        "honeypot_active_32.ico": "asteria_online_32.ico",
        "honeypot_active_64.ico": "asteria_online_64.ico",
        "honeypot_active_128.ico": "asteria_online.ico",
        "honeypot_active_256.ico": "asteria_online.ico",
        "honeypot_inactive.ico": "asteria_offline.ico",
        "honeypot_inactive_16.ico": "asteria_offline_16.ico",
        "honeypot_inactive_32.ico": "asteria_offline_32.ico",
        "honeypot_inactive_64.ico": "asteria_offline_64.ico",
        "honeypot_inactive_128.ico": "asteria_offline.ico",
        "honeypot_inactive_256.ico": "asteria_offline.ico",
        "honeypot_warning_16.ico": "asteria_stay_16.ico",
        "honeypot_warning_32.ico": "asteria_stay_32.ico",
    }
    for dst, src in legacy.items():
        (CERTS / dst).write_bytes((CERTS / src).read_bytes())
        print(f"alias {dst} <- {src}")

    # NSIS MUI welcome bitmap (164x314)
    welcome = Image.new("RGBA", (164, 314), (8, 13, 20, 255))
    sq = load_rgba("logo_square_light.png").resize((120, 120), Image.Resampling.LANCZOS)
    welcome.paste(sq, ((164 - 120) // 2, 40), sq)
    welcome.convert("RGB").save(CERTS / "welcome.bmp")
    welcome.convert("RGB").save(CERTS / "welcome.png")
    print("wrote welcome.bmp")
    print("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
