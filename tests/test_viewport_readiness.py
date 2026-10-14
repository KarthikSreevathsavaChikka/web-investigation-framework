import unittest

from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from core.playwright_session import close_browser_session, launch_browser_session
from core.screenshot_readiness import wait_for_viewport_readiness


class ViewportReadinessTests(unittest.IsolatedAsyncioTestCase):
    async def test_waits_for_loader_and_new_content_after_scroll(self):
        resources = await launch_browser_session(headless=True)
        try:
            page = await resources.context.new_page()
            await page.set_content('''
                <article>Loading post</article><div role="progressbar">Loading</div>
                <script>setTimeout(() => {
                    document.querySelector('article').textContent = 'Ready post';
                    document.querySelector('[role="progressbar"]').remove();
                }, 200);</script>
            ''')
            await wait_for_viewport_readiness(page, 'article', timeout=3000)
            self.assertEqual(await page.locator('article').inner_text(), 'Ready post')
            await page.evaluate('''() => {
                document.body.style.height = '2400px';
                document.querySelector('article').style.marginTop = '1200px';
            }''')
            with self.assertRaises(PlaywrightTimeoutError):
                await wait_for_viewport_readiness(page, 'article', timeout=700)
            await page.evaluate('window.scrollTo(0, 1100)')
            await wait_for_viewport_readiness(page, 'article', timeout=3000)
            await page.evaluate('''() => {
                const loader = document.createElement('div');
                loader.setAttribute('role', 'progressbar');
                loader.textContent = 'Loading';
                document.querySelector('article').append(loader);
            }''')
            with self.assertRaises(PlaywrightTimeoutError):
                await wait_for_viewport_readiness(page, 'article', timeout=700)
        finally:
            await close_browser_session(resources)
