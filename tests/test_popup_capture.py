import tempfile
import unittest

from core.playwright_session import close_browser_session, launch_browser_session
from osint.evidence_capture import SERPEvidenceCapturePipeline


class PopupCaptureTests(unittest.IsolatedAsyncioTestCase):
    async def test_captures_and_closes_off_center_and_bottom_popups(self):
        resources = await launch_browser_session(headless=True)
        try:
            page = await resources.context.new_page()
            await page.set_content("""
                <style>
                  body { min-height: 900px; background: linear-gradient(45deg,#fff,#ccd); }
                  #side-popup { position: fixed; right: 12px; top: 80px; width: 320px;
                    height: 420px; z-index: 100; background: #43136b; color: white; }
                  #bottom-sheet { position: fixed; left: 20px; bottom: 10px; width: 520px;
                    height: 100px; z-index: 90; background: #173f7a; color: white; }
                </style>
                <main><h1>Target page</h1><p>Normal page content remains visible.</p></main>
                <aside id="side-popup" class="promotion-popup">
                  <button aria-label="Close" onclick="this.parentElement.remove()">×</button>
                  <p>Side promotion</p>
                </aside>
                <section id="bottom-sheet" role="dialog" aria-modal="true">
                  <button title="Dismiss" onclick="this.parentElement.remove()">Dismiss</button>
                  <p>Bottom notice</p>
                </section>
            """)
            with tempfile.TemporaryDirectory() as directory:
                pipeline = SERPEvidenceCapturePipeline(directory)
                captures = await pipeline._capture_and_dismiss_popups(page)
            self.assertEqual(len(captures), 2)
            self.assertTrue(all(item["bytes"] for item in captures))
            self.assertEqual(await page.locator("#side-popup").count(), 0)
            self.assertEqual(await page.locator("#bottom-sheet").count(), 0)
        finally:
            await close_browser_session(resources)


if __name__ == "__main__":
    unittest.main()
