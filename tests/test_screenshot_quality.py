import unittest
from io import BytesIO

from PIL import Image, ImageDraw

from osint.evidence_capture import assess_screenshot_quality


def png_bytes(image: Image.Image) -> bytes:
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


class ScreenshotQualityTests(unittest.TestCase):
    def test_rejects_single_color_capture(self):
        accepted, reason = assess_screenshot_quality(
            png_bytes(Image.new("RGB", (1440, 900), "#999aa8"))
        )
        self.assertFalse(accepted)
        self.assertIn("empty", reason)

    def test_rejects_near_uniform_loading_capture(self):
        image = Image.new("RGB", (1440, 900), "#999aa8")
        ImageDraw.Draw(image).rectangle((620, 0, 980, 900), fill="#2d0038")
        accepted, reason = assess_screenshot_quality(png_bytes(image))
        self.assertFalse(accepted)
        self.assertIn("near-uniform", reason)

    def test_accepts_page_with_visible_detail(self):
        image = Image.new("RGB", (1440, 900), "white")
        draw = ImageDraw.Draw(image)
        for row in range(20):
            draw.rectangle((50, 30 + row * 40, 1200, 48 + row * 40), fill=(20 + row * 7, 40, 120))
            draw.line((50, 55 + row * 40, 900, 55 + row * 40), fill="black", width=3)
        accepted, reason = assess_screenshot_quality(png_bytes(image))
        self.assertTrue(accepted, reason)


if __name__ == "__main__":
    unittest.main()
