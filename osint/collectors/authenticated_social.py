from __future__ import annotations

import asyncio
import fcntl
import hashlib
import os
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, quote_plus, urljoin

from config import DATA_DIR, EVIDENCE_DIR
from core.playwright_session import close_browser_session, launch_browser_session
from osint.cancellation import InvestigationCancelled
from osint.collectors.base import Collector, CollectorContext
from osint.collectors.x_authenticated import post_matches_target
from osint.models import NormalizedTarget, Observation
from osint.url_tools import normalize_result_url


@dataclass(frozen=True)
class AuthenticatedSocialPlatform:
    key: str
    label: str
    home_url: str
    search_url: str
    result_selector: str
    link_selector: str
    login_markers: tuple[str, ...]


PLATFORMS = {
    "instagram": AuthenticatedSocialPlatform(
        key="instagram",
        label="Instagram",
        home_url="https://www.instagram.com/",
        search_url="https://www.instagram.com/explore/search/keyword/?q={query}",
        result_selector='article, a[href^="/p/"], a[href^="/reel/"]',
        link_selector='a[href^="/p/"], a[href^="/reel/"], a[href^="/"]',
        login_markers=("/accounts/login",),
    ),
    "facebook": AuthenticatedSocialPlatform(
        key="facebook",
        label="Facebook",
        home_url="https://www.facebook.com/",
        search_url="https://www.facebook.com/search/posts/?q={query}",
        result_selector='div[role="article"]',
        link_selector='a[href*="/posts/"], a[href*="story_fbid="], a[href*="/reel/"]',
        login_markers=("/login", "/checkpoint"),
    ),
    "telegram": AuthenticatedSocialPlatform(
        key="telegram",
        label="Telegram",
        home_url="https://web.telegram.org/k/",
        search_url="",
        result_selector='.message, .chatlist-chat, [data-mid]',
        link_selector='a[href*="t.me/"], a[href^="#"]',
        login_markers=("/auth",),
    ),
    "youtube": AuthenticatedSocialPlatform(
        key="youtube",
        label="YouTube",
        home_url="https://www.youtube.com/",
        search_url="https://www.youtube.com/results?search_query={query}",
        result_selector="ytd-video-renderer, ytd-channel-renderer, ytd-playlist-renderer, ytd-post-renderer",
        link_selector='a#video-title, a[href^="/watch"], a[href^="/shorts/"], a[href^="/@"], a[href^="/channel/"]',
        login_markers=("accounts.google.com",),
    ),
    "quora": AuthenticatedSocialPlatform(
        key="quora",
        label="Quora",
        home_url="https://www.quora.com/",
        search_url="https://www.quora.com/search?q={query}",
        result_selector='div[role="main"] div.q-box.qu-borderBottom, div[role="main"] div.q-box',
        link_selector='a[href^="/"], a[href*="quora.com/"]',
        login_markers=("/login",),
    ),
}


def configured_social_session_path(platform: str) -> Path:
    key = platform.upper()
    default = DATA_DIR / "browser_sessions" / f"{platform}.json"
    return Path(os.getenv(f"{key}_STORAGE_STATE_PATH", str(default)))


class AuthenticatedSocialCollector(Collector):
    platform_key = ""

    def __init__(self, session_path: Path | None = None):
        self.platform = PLATFORMS[self.platform_key]
        self.session_path = session_path or configured_social_session_path(self.platform_key)
        self.name = f"{self.platform_key}_authenticated_playwright"

    @property
    def available(self) -> bool:
        return self.session_path.is_file()

    def collect(self, target: NormalizedTarget, context: CollectorContext) -> list[Observation]:
        if not self.available:
            raise RuntimeError(
                f"{self.platform.label} authenticated session is not configured. Run "
                f"`python -m scripts.setup_{self.platform_key}_session`, complete login/OTP "
                "in the visible browser, then retry."
            )
        lock_path = EVIDENCE_DIR / "social" / self.platform_key / ".collector.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("w") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                return asyncio.run(self._collect(target, context))
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    async def _collect(self, target: NormalizedTarget, context: CollectorContext) -> list[Observation]:
        resources = None
        query = target.brand.strip() or target.domain
        prefix = self.platform_key.upper()
        max_scrolls = max(1, min(int(os.getenv(f"{prefix}_MAX_SCROLLS", "8")), 50))
        max_items = max(1, min(int(os.getenv(f"{prefix}_MAX_ITEMS", "60")), 300))
        scroll_wait_ms = max(250, min(int(os.getenv(f"{prefix}_SCROLL_WAIT_MS", "900")), 5000))
        run_id = uuid.uuid4().hex[:12]
        output_dir = (
            EVIDENCE_DIR
            / "social"
            / self.platform_key
            / re.sub(r"[^a-zA-Z0-9_.-]+", "_", target.domain)
            / run_id
        )
        output_dir.mkdir(parents=True, exist_ok=True)
        observations: list[Observation] = []
        seen_urls: set[str] = set()

        try:
            resources = await launch_browser_session(
                headless=True,
                viewport={"width": 1440, "height": 1000},
                storage_state=str(self.session_path),
            )
            page = await resources.context.new_page()
            search_url = await self._open_search(page, query)
            await self._validate_session(page)

            stable_scrolls = 0
            previous_height = 0
            for scroll_index in range(max_scrolls):
                if context.cancellation_requested():
                    raise InvestigationCancelled(
                        f"Investigation cancelled during {self.platform.label} collection"
                    )
                screenshot_path = output_dir / f"scroll_{scroll_index + 1:03d}.png"
                await page.screenshot(path=str(screenshot_path), full_page=False)
                screenshot_sha256 = hashlib.sha256(screenshot_path.read_bytes()).hexdigest()
                items = page.locator(self.platform.result_selector)

                for index in range(await items.count()):
                    item = items.nth(index)
                    try:
                        text = await self._result_text(item)
                        matched = post_matches_target(text, target)
                        if not matched:
                            continue
                        href = await item.get_attribute("href")
                        if not href:
                            link = item.locator(self.platform.link_selector)
                            href = await link.first.get_attribute("href") if await link.count() else None
                        if not href:
                            continue
                        item_url = self._normalize_platform_url(href)
                        if item_url in seen_urls:
                            continue
                        seen_urls.add(item_url)
                        title = next(
                            (line.strip() for line in text.splitlines() if line.strip()),
                            f"{self.platform.label} result",
                        )[:300]
                        observations.append(
                            Observation(
                                collector=self.name,
                                category="Automated social and review findings",
                                entity_type="AUTOMATED_SOCIAL_FINDING",
                                value=title,
                                source_url=item_url,
                                confidence=0.9,
                                metadata={
                                    "platform": self.platform.label,
                                    "title": title,
                                    "post_text": text[:10_000],
                                    "matched_target_variant": matched,
                                    "normalized_url": item_url,
                                    "collector_method": self.name,
                                    "search_engine": f"{self.platform_key}_authenticated_browser",
                                    "query_id": f"{prefix}-DIRECT",
                                    "rank": len(seen_urls),
                                    "status": "authenticated_page_captured",
                                    "screenshot_paths": [str(screenshot_path)],
                                    "screenshot_sha256": screenshot_sha256,
                                    "search_url": search_url,
                                    "scroll_index": scroll_index + 1,
                                },
                            )
                        )
                        if len(seen_urls) >= max_items:
                            return observations
                    except Exception:
                        continue

                height = await page.evaluate("document.documentElement.scrollHeight")
                stable_scrolls = stable_scrolls + 1 if height <= previous_height else 0
                if stable_scrolls >= 2:
                    break
                previous_height = height
                await page.evaluate("window.scrollTo(0, document.documentElement.scrollHeight)")
                await page.wait_for_timeout(scroll_wait_ms)
            return observations
        finally:
            await close_browser_session(resources)

    async def _open_search(self, page, query: str) -> str:
        if self.platform_key != "telegram":
            search_url = self.platform.search_url.format(query=quote_plus(query))
            await page.goto(search_url, wait_until="domcontentloaded", timeout=60_000)
            await page.wait_for_timeout(1800)
            return search_url

        await page.goto(self.platform.home_url, wait_until="domcontentloaded", timeout=60_000)
        await page.wait_for_timeout(1800)
        search_inputs = page.locator(
            'input[placeholder*="Search" i], [contenteditable="true"][data-placeholder*="Search" i]'
        )
        if not await search_inputs.count():
            raise RuntimeError(
                "Telegram search control was not found. The saved session may have expired "
                "or Telegram Web changed its interface."
            )
        search_input = search_inputs.first
        await search_input.fill(query)
        await page.wait_for_timeout(1800)
        return f"https://web.telegram.org/k/#?q={quote(query)}"

    async def _validate_session(self, page) -> None:
        current = page.url.casefold()
        if any(marker.casefold() in current for marker in self.platform.login_markers):
            raise RuntimeError(
                f"The saved {self.platform.label} session has expired. Run the session setup command again."
            )
        body = (await page.locator("body").inner_text(timeout=5000)).casefold()[:5000]
        blocked = ("captcha", "too many requests", "verify you are human", "access denied")
        if any(marker in body for marker in blocked):
            raise RuntimeError(
                f"{self.platform.label} blocked or challenged the browser request. "
                "Collection stopped without attempting to bypass the restriction."
            )

    async def _result_text(self, item) -> str:
        parts = [(await item.inner_text(timeout=3000)).strip()]
        images = item.locator("img[alt]")
        for index in range(min(await images.count(), 5)):
            alt = (await images.nth(index).get_attribute("alt") or "").strip()
            if alt:
                parts.append(alt)
        return "\n".join(part for part in parts if part).strip()

    def _normalize_platform_url(self, href: str) -> str:
        if href.startswith("#") and self.platform_key == "telegram":
            absolute = f"https://web.telegram.org/k/{href}"
        else:
            absolute = urljoin(self.platform.home_url, href)
        return normalize_result_url(absolute)


class InstagramAuthenticatedCollector(AuthenticatedSocialCollector):
    platform_key = "instagram"


class FacebookAuthenticatedCollector(AuthenticatedSocialCollector):
    platform_key = "facebook"


class TelegramAuthenticatedCollector(AuthenticatedSocialCollector):
    platform_key = "telegram"


class YouTubeAuthenticatedCollector(AuthenticatedSocialCollector):
    platform_key = "youtube"


class QuoraAuthenticatedCollector(AuthenticatedSocialCollector):
    platform_key = "quora"


AUTHENTICATED_SOCIAL_COLLECTORS = {
    "Instagram authenticated search": InstagramAuthenticatedCollector,
    "Facebook authenticated search": FacebookAuthenticatedCollector,
    "Telegram authenticated search": TelegramAuthenticatedCollector,
    "YouTube authenticated search": YouTubeAuthenticatedCollector,
    "Quora authenticated search": QuoraAuthenticatedCollector,
}
