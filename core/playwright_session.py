from __future__ import annotations

import os
from dataclasses import dataclass

from playwright.async_api import Browser, BrowserContext, Playwright, async_playwright


@dataclass
class BrowserResources:
    playwright: Playwright
    browser: Browser
    context: BrowserContext


async def launch_browser_session(
    *,
    headless: bool,
    viewport: dict[str, int] | None = None,
) -> BrowserResources:
    """Launch Chromium with the project's existing system-browser fallback policy."""
    playwright = await async_playwright().start()
    launch_args = ["--start-maximized", "--disable-blink-features=AutomationControlled"]
    browser_executable = next(
        (
            candidate
            for candidate in (
                "/usr/bin/google-chrome",
                "/usr/bin/google-chrome-stable",
                "/usr/bin/chromium",
                "/usr/bin/chromium-browser",
            )
            if os.path.exists(candidate)
        ),
        None,
    )
    try:
        launch_options = {"headless": headless, "args": launch_args}
        if browser_executable:
            launch_options["executable_path"] = browser_executable
        try:
            browser = await playwright.chromium.launch(**launch_options)
        except Exception:
            if not browser_executable:
                raise
            browser = await playwright.chromium.launch(headless=headless, args=launch_args)
        context = await browser.new_context(
            viewport=viewport or {"width": 1440, "height": 900},
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
        )
        return BrowserResources(playwright, browser, context)
    except Exception:
        await playwright.stop()
        raise


async def close_browser_session(resources: BrowserResources | None) -> None:
    if not resources:
        return
    try:
        await resources.context.close()
    finally:
        try:
            await resources.browser.close()
        finally:
            await resources.playwright.stop()
