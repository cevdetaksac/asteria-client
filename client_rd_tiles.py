# -*- coding: utf-8 -*-
"""Dirty-tile JPEG packing for remote desktop (contract 1.4.93 / client 4.9.127).

Binary packet (viewer detects via magic ASTT, else treats as full JPEG SOI):
  ASTT | ver:u8 | flags:u8 | w:u16 | h:u16 | tw:u16 | th:u16 | count:u16
  then count × (x:u16 y:u16 w:u16 h:u16 len:u32 + jpeg bytes)

flags bit0 = keyframe (single full-frame tile).
"""
from __future__ import annotations

import io
import struct
from typing import List, Tuple

MAGIC = b"ASTT"
VERSION = 1
FLAG_KEYFRAME = 0x01
DEFAULT_TILE = 128
KEYFRAME_EVERY = 45


def pack_header(w: int, h: int, tw: int, th: int, flags: int, count: int) -> bytes:
    return MAGIC + struct.pack(">BBHHHHH", VERSION, flags, w, h, tw, th, count)


def encode_jpeg(img, quality: int) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=int(quality), optimize=False)
    return buf.getvalue()


class DirtyTileEncoder:
    def __init__(self, tile: int = DEFAULT_TILE, keyframe_every: int = KEYFRAME_EVERY):
        self.tile = max(32, int(tile))
        self.keyframe_every = max(5, int(keyframe_every))
        self._prev_img = None
        self._frame_i = 0
        self._prev_size = (0, 0)

    def reset(self) -> None:
        self._prev_img = None
        self._frame_i = 0
        self._prev_size = (0, 0)

    def encode(self, img, quality: int = 55) -> Tuple[bytes, dict]:
        if img.mode != "RGB":
            img = img.convert("RGB")
        w, h = img.size
        self._frame_i += 1
        force_kf = (
            self._prev_img is None
            or self._prev_size != (w, h)
            or (self._frame_i % self.keyframe_every == 1)
        )
        tw = th = self.tile
        tiles: List[Tuple[int, int, int, int, bytes]] = []

        if force_kf:
            tiles.append((0, 0, w, h, encode_jpeg(img, quality)))
            flags = FLAG_KEYFRAME
        else:
            flags = 0
            cur = img.load()
            prev_px = self._prev_img.load()
            for y in range(0, h, th):
                for x in range(0, w, tw):
                    cw = min(tw, w - x)
                    ch = min(th, h - y)
                    changed = False
                    for sy in (0, ch // 3, (2 * ch) // 3, ch - 1):
                        for sx in (0, cw // 3, (2 * cw) // 3, cw - 1):
                            if cur[x + sx, y + sy] != prev_px[x + sx, y + sy]:
                                changed = True
                                break
                        if changed:
                            break
                    if changed:
                        crop = img.crop((x, y, x + cw, y + ch))
                        tiles.append((x, y, cw, ch, encode_jpeg(crop, quality)))

            total_tiles = ((w + tw - 1) // tw) * ((h + th - 1) // th)
            if not tiles:
                # identical frame — send empty dirty set (1-byte keep-alive via tiny header)
                pass
            elif total_tiles and len(tiles) > total_tiles * 0.65:
                tiles = [(0, 0, w, h, encode_jpeg(img, quality))]
                flags = FLAG_KEYFRAME

        parts = [pack_header(w, h, tw, th, flags, len(tiles))]
        for x, y, cw, ch, jpeg in tiles:
            parts.append(struct.pack(">HHHHI", x, y, cw, ch, len(jpeg)))
            parts.append(jpeg)
        payload = b"".join(parts)
        self._prev_img = img.copy()
        self._prev_size = (w, h)
        meta = {
            "encoding": "jpeg-tiles-v1",
            "keyframe": bool(flags & FLAG_KEYFRAME),
            "tile": tw,
            "tiles": len(tiles),
            "width": w,
            "height": h,
            "payload_bytes": len(payload),
        }
        return payload, meta
