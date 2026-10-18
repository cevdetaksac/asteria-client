import time, io, statistics, json
from PIL import ImageGrab, Image
from client_rd_tiles import DirtyTileEncoder

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
        "encode_ms_avg": round(statistics.mean(times), 2),
        "encode_ms_p50": round(statistics.median(times), 2),
        "encode_ms_p95": round(sorted(times)[int(0.95 * n) - 1], 2),
        "fps_cap_est": round(1000 / statistics.mean(times), 2),
        "jpeg_kb_avg": round(statistics.mean(sizes) / 1024, 1),
    }

def bench_tiles(n=45, quality=55, max_w=1280):
    enc = DirtyTileEncoder(tile=128, keyframe_every=30)
    times, sizes, tiles_n = [], [], []
    ImageGrab.grab()
    for _ in range(n):
        t0 = time.perf_counter()
        img = ImageGrab.grab().convert("RGB")
        w, h = img.size
        if w > max_w:
            nh = int(h * max_w / w)
            img = img.resize((max_w, nh), Image.BILINEAR)
        payload, meta = enc.encode(img, quality=quality)
        times.append((time.perf_counter() - t0) * 1000)
        sizes.append(len(payload))
        tiles_n.append(meta["tiles"])
    return {
        "mode": "dirty_tiles_ASTT",
        "encode_ms_avg": round(statistics.mean(times), 2),
        "encode_ms_p50": round(statistics.median(times), 2),
        "encode_ms_p95": round(sorted(times)[int(0.95 * n) - 1], 2),
        "fps_cap_est": round(1000 / statistics.mean(times), 2),
        "payload_kb_avg": round(statistics.mean(sizes) / 1024, 1),
        "tiles_avg": round(statistics.mean(tiles_n), 1),
    }

before = json.load(open(r"C:\Users\caksac\p2\rd_bench_before.json"))
after_full = bench_full()
after_tiles = bench_tiles()
out = {"before": before, "after_full": after_full, "after_tiles": after_tiles}
print(json.dumps(out, indent=2))
open(r"C:\Users\caksac\p2\rd_bench_after.json", "w").write(json.dumps(out, indent=2))
