from __future__ import annotations

import asyncio

from core.playwright_session import close_browser_session, launch_browser_session
from osint.collectors.x_authenticated import configured_x_session_path


async def setup() -> None:
    destination = configured_x_session_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    resources = None
    try:
        resources = await launch_browser_session(headless=False, viewport={"width": 1440, "height": 1000})
        page = await resources.context.new_page()
        await page.goto("https://x.com/i/flow/login", wait_until="domcontentloaded", timeout=45_000)
        print("Complete X login, OTP, and any challenge in the visible browser.")
        input("After the X home page is visible, return here and press Enter: ")
        cookies = await resources.context.cookies(["https://x.com", "https://twitter.com"])
        cookie_names = {cookie["name"] for cookie in cookies}
        if "auth_token" not in cookie_names:
            raise RuntimeError(
                "X did not issue an authentication cookie. Keep the browser open until the X home "
                "timeline is fully loaded, complete every OTP/challenge, and run this command again."
            )
        await resources.context.storage_state(path=str(destination))
        destination.chmod(0o640)
        print(f"X session saved to {destination}. No password was stored by this application.")
    finally:
        await close_browser_session(resources)


if __name__ == "__main__":
    asyncio.run(setup())
