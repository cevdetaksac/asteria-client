import time, io, statistics, json
from PIL import ImageGrab, Image

def bench_full(n=45, quality=55, max_w=1280):
    times, sizes = [], []
    ImageGrab.grab()
    for _ in range(n):
        t0 = time.perf_counter()
        img = ImageGrab.grab()
        w, h = img.size
        if w > max_w:
            nh = int(h * max_w / w)
            img = img.resize((max_w, nh), Image.BILINEAR)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=quality, optimize=False)
        times.append((time.perf_counter() - t0) * 1000)
        sizes.append(buf.tell())
    return {
        "mode": "full_jpeg",
        "frames": n,
        "encode_ms_avg": round(statistics.mean(times), 2),
        "encode_ms_p50": round(statistics.median(times), 2),
        "encode_ms_p95": round(sorted(times)[int(0.95 * n) - 1], 2),
        "fps_cap_est": round(1000 / statistics.mean(times), 2),
        "jpeg_kb_avg": round(statistics.mean(sizes) / 1024, 1),
    }

def bench_tiles(n=45, quality=55, max_w=1280, tile=64, keyframe_every=30):
    """Simulate dirty-tile encode: only re-encode changed tiles + periodic keyframe."""
    times, sizes, dirty_counts = [], [], []
    prev = None
    ImageGrab.grab()
    for i in range(n):
        t0 = time.perf_counter()
        img = ImageGrab.grab().convert("RGB")
        w, h = img.size
        if w > max_w:
            nh = int(h * max_w / w)
            img = img.resize((max_w, nh), Image.BILINEAR)
            w, h = img.size
        px = img.load()
        keyframe = (i % keyframe_every == 0) or prev is None
        tiles = []
        dirty = 0
        for y in range(0, h, tile):
            for x in range(0, w, tile):
                tw = min(tile, w - x)
                th = min(tile, h - y)
                changed = keyframe
                if not changed and prev is not None:
                    # sample 16 points
                    for sy in (0, th // 3, 2 * th // 3, th - 1):
                        for sx in (0, tw // 3, 2 * tw // 3, tw - 1):
                            if px[x + sx, y + sy] != prev[x + sx, y + sy]:
                                changed = True
                                break
                        if changed:
                            break
                if changed:
                    dirty += 1
                    crop = img.crop((x, y, x + tw, y + th))
                    buf = io.BytesIO()
                    crop.save(buf, format="JPEG", quality=quality, optimize=False)
                    tiles.append(buf.tell())
        if keyframe:
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=quality, optimize=False)
            total = buf.tell()
        else:
            total = sum(tiles)
        times.append((time.perf_counter() - t0) * 1000)
        sizes.append(total)
        dirty_counts.append(dirty)
        prev = px
    return {
        "mode": "dirty_tiles_sim",
        "frames": n,
        "tile": tile,
        "encode_ms_avg": round(statistics.mean(times), 2),
        "encode_ms_p50": round(statistics.median(times), 2),
        "encode_ms_p95": round(sorted(times)[int(0.95 * n) - 1], 2),
        "fps_cap_est": round(1000 / statistics.mean(times), 2),
        "payload_kb_avg": round(statistics.mean(sizes) / 1024, 1),
        "dirty_tiles_avg": round(statistics.mean(dirty_counts), 1),
    }

before = bench_full()
print(json.dumps({"before_full": before}, indent=2))
open(r"C:\Users\caksac\p2\rd_bench_before.json", "w").write(json.dumps({"before_full": before}, indent=2))
