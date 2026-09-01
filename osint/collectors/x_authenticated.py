from __future__ import annotations

import asyncio
import fcntl
import hashlib
import os
import re
import uuid
from pathlib import Path
from urllib.parse import quote

from config import DATA_DIR, EVIDENCE_DIR
from core.playwright_session import close_browser_session, launch_browser_session
from osint.cancellation import InvestigationCancelled
from osint.collectors.base import Collector, CollectorContext
from osint.models import NormalizedTarget, Observation
from osint.url_tools import normalize_result_url


def configured_x_session_path() -> Path:
    return Path(os.getenv("X_STORAGE_STATE_PATH", str(DATA_DIR / "browser_sessions" / "x.json")))


def target_variants(target: NormalizedTarget) -> tuple[str, ...]:
    values = {target.domain.casefold(), target.domain.split(".")[0].casefold()}
    if target.brand.strip():
        values.add(target.brand.strip().casefold())
    return tuple(value for value in values if len(value) >= 3)


def post_matches_target(text: str, target: NormalizedTarget) -> str:
    # X renders redirect/tracking URLs as visible text. A brand appearing only inside
    # a long spam URL is not evidence that the post discusses the target.
    folded = re.sub(r"https?://\s*\S+", " ", text.casefold())
    for variant in target_variants(target):
        if re.search(rf"(?<![a-z0-9]){re.escape(variant)}(?![a-z0-9])", folded):
            return variant
    return ""


class XAuthenticatedCollector(Collector):
    name = "x_authenticated_playwright"

    def __init__(self, session_path: Path | None = None):
        self.session_path = session_path or configured_x_session_path()

    @property
    def available(self) -> bool:
        return self.session_path.is_file()

    def collect(self, target: NormalizedTarget, context: CollectorContext) -> list[Observation]:
        if not self.available:
            raise RuntimeError(
                "X authenticated session is not configured. Run `python -m scripts.setup_x_session` "
                "on the host, complete login/OTP in the visible browser, then retry."
            )
        lock_path = EVIDENCE_DIR / "social" / "x" / ".collector.lock"
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
        max_scrolls = max(1, min(int(os.getenv("X_MAX_SCROLLS", "12")), 100))
        max_posts = max(1, min(int(os.getenv("X_MAX_POSTS", "100")), 500))
        scroll_wait_ms = max(250, min(int(os.getenv("X_SCROLL_WAIT_MS", "900")), 5000))
        capture_run = uuid.uuid4().hex[:12]
        output_dir = (
            EVIDENCE_DIR / "social" / "x"
            / re.sub(r"[^a-zA-Z0-9_.-]+", "_", target.domain)
            / capture_run
        )
        output_dir.mkdir(parents=True, exist_ok=True)
        observations: list[Observation] = []
        seen_urls: set[str] = set()
        stable_scrolls = 0
        previous_height = 0
        try:
            resources = await launch_browser_session(
                headless=True,
                viewport={"width": 1440, "height": 1000},
                storage_state=str(self.session_path),
            )
            page = await resources.context.new_page()
            search_url = f"https://x.com/search?q={quote(query)}&src=typed_query&f=live"
            await page.goto(search_url, wait_until="domcontentloaded", timeout=45_000)
            await page.wait_for_timeout(2000)
            if "/login" in page.url or "/i/flow/login" in page.url:
                raise RuntimeError("The saved X session has expired. Run the X session setup command again.")

            for scroll_index in range(max_scrolls):
                if context.cancellation_requested():
                    raise InvestigationCancelled("Investigation cancelled during X collection")
                articles = page.locator("article")
                article_count = await articles.count()
                screenshot_path = output_dir / f"scroll_{scroll_index + 1:03d}.png"
                await page.screenshot(path=str(screenshot_path), full_page=False)
                screenshot_sha256 = hashlib.sha256(screenshot_path.read_bytes()).hexdigest()

                for index in range(article_count):
                    article = articles.nth(index)
                    try:
                        text = (await article.inner_text(timeout=3000)).strip()
                        matched = post_matches_target(text, target)
                        if not matched:
                            continue
                        links = article.locator('a[href*="/status/"]')
                        href = await links.first.get_attribute("href") if await links.count() else None
                        if not href:
                            continue
                        post_url = normalize_result_url(f"https://x.com{href.split('?')[0]}")
                        if post_url in seen_urls:
                            continue
                        seen_urls.add(post_url)
                        first_line = next((line.strip() for line in text.splitlines() if line.strip()), "X post")
                        observations.append(
                            Observation(
                                collector=self.name,
                                category="Automated social and review findings",
                                entity_type="AUTOMATED_SOCIAL_FINDING",
                                value=first_line[:300],
                                source_url=post_url,
                                confidence=0.9,
                                metadata={
                                    "platform": "X/Twitter",
                                    "title": first_line[:300],
                                    "post_text": text[:10_000],
                                    "matched_target_variant": matched,
                                    "normalized_url": post_url,
                                    "collector_method": self.name,
                                    "search_engine": "x_authenticated_browser",
                                    "query_id": "X-DIRECT",
                                    "rank": len(seen_urls),
                                    "status": "authenticated_page_captured",
                                    "screenshot_paths": [str(screenshot_path)],
                                    "screenshot_sha256": screenshot_sha256,
                                    "search_url": search_url,
                                    "scroll_index": scroll_index + 1,
                                },
                            )
                        )
                        if len(seen_urls) >= max_posts:
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
