import io, struct, unittest
from PIL import Image
from client_rd_tiles import DirtyTileEncoder, MAGIC, FLAG_KEYFRAME

class TestDirtyTiles(unittest.TestCase):
    def test_keyframe_and_dirty(self):
        enc = DirtyTileEncoder(tile=64, keyframe_every=10)
        img = Image.new("RGB", (128, 128), (10, 20, 30))
        payload, meta = enc.encode(img, quality=40)
        self.assertTrue(payload.startswith(MAGIC))
        self.assertTrue(meta["keyframe"])
        # second identical frame → 0 dirty tiles
        payload2, meta2 = enc.encode(img, quality=40)
        self.assertFalse(meta2["keyframe"])
        self.assertEqual(meta2["tiles"], 0)
        # change one pixel region
        img2 = img.copy()
        img2.putpixel((0, 0), (255, 0, 0))
        payload3, meta3 = enc.encode(img2, quality=40)
        self.assertGreaterEqual(meta3["tiles"], 1)
        self.assertTrue(payload3.startswith(MAGIC))

if __name__ == "__main__":
    unittest.main()
