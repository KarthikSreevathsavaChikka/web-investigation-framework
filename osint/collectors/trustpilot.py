from __future__ import annotations

import asyncio
import fcntl
import hashlib
import os
import re
import uuid
from pathlib import Path
from urllib.parse import quote, urljoin, urlsplit

from config import EVIDENCE_DIR
from core.playwright_session import close_browser_session, launch_browser_session
from osint.cancellation import InvestigationCancelled
from osint.collectors.base import Collector, CollectorContext
from osint.models import NormalizedTarget, Observation
from osint.url_tools import normalize_result_url


def trustpilot_target_variants(target: NormalizedTarget) -> tuple[str, ...]:
    values = {
        target.domain.casefold(),
        target.domain.removeprefix("www.").casefold(),
        target.domain.split(".")[0].casefold(),
    }
    if target.brand.strip():
        values.add(target.brand.strip().casefold())
    return tuple(sorted((value for value in values if len(value) >= 3), key=len, reverse=True))


def trustpilot_profile_matches(href: str, text: str, target: NormalizedTarget) -> str:
    """Return the target variant that validates a Trustpilot company result."""
    folded = f"{urlsplit(href).path} {text}".casefold()
    for variant in trustpilot_target_variants(target):
        if re.search(rf"(?<![a-z0-9]){re.escape(variant)}(?![a-z0-9])", folded):
            return variant
    return ""


class TrustpilotCollector(Collector):
    name = "trustpilot_public_playwright"

    def collect(self, target: NormalizedTarget, context: CollectorContext) -> list[Observation]:
        lock_path = EVIDENCE_DIR / "reviews" / "trustpilot" / ".collector.lock"
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
        max_profiles = max(1, min(int(os.getenv("TRUSTPILOT_MAX_PROFILES", "3")), 10))
        max_scrolls = max(1, min(int(os.getenv("TRUSTPILOT_MAX_SCROLLS", "6")), 30))
        max_reviews = max(1, min(int(os.getenv("TRUSTPILOT_MAX_REVIEWS", "50")), 200))
        wait_ms = max(250, min(int(os.getenv("TRUSTPILOT_SCROLL_WAIT_MS", "800")), 5000))
        run_id = uuid.uuid4().hex[:12]
        output_dir = (
            EVIDENCE_DIR
            / "reviews"
            / "trustpilot"
            / re.sub(r"[^a-zA-Z0-9_.-]+", "_", target.domain)
            / run_id
        )
        output_dir.mkdir(parents=True, exist_ok=True)
        observations: list[Observation] = []
        seen_review_urls: set[str] = set()

        try:
            resources = await launch_browser_session(
                headless=True,
                viewport={"width": 1440, "height": 1000},
            )
            page = await resources.context.new_page()
            search_url = f"https://www.trustpilot.com/search?query={quote(query)}"
            await page.goto(search_url, wait_until="domcontentloaded", timeout=45_000)
            await page.wait_for_timeout(1500)
            await self._raise_if_blocked(page)

            profiles: list[tuple[str, str]] = []
            links = page.locator('a[href*="/review/"]')
            for index in range(await links.count()):
                link = links.nth(index)
                href = await link.get_attribute("href")
                if not href:
                    continue
                text = (await link.inner_text(timeout=2000)).strip()
                matched = trustpilot_profile_matches(href, text, target)
                profile_url = normalize_result_url(urljoin("https://www.trustpilot.com", href))
                if matched and profile_url not in {item[0] for item in profiles}:
                    profiles.append((profile_url, matched))
                if len(profiles) >= max_profiles:
                    break

            for profile_index, (profile_url, matched_variant) in enumerate(profiles, start=1):
                if context.cancellation_requested():
                    raise InvestigationCancelled("Investigation cancelled during Trustpilot collection")
                await page.goto(profile_url, wait_until="domcontentloaded", timeout=45_000)
                await page.wait_for_timeout(1200)
                await self._raise_if_blocked(page)

                stable_scrolls = 0
                previous_height = 0
                for scroll_index in range(max_scrolls):
                    if context.cancellation_requested():
                        raise InvestigationCancelled("Investigation cancelled during Trustpilot collection")
                    screenshot_path = output_dir / f"profile_{profile_index:02d}_scroll_{scroll_index + 1:03d}.png"
                    await page.screenshot(path=str(screenshot_path), full_page=False)
                    screenshot_sha256 = hashlib.sha256(screenshot_path.read_bytes()).hexdigest()
                    articles = page.locator("article")

                    for article_index in range(await articles.count()):
                        article = articles.nth(article_index)
                        try:
                            review_text = (await article.inner_text(timeout=2500)).strip()
                            if len(review_text) < 20:
                                continue
                            review_links = article.locator('a[href*="/reviews/"]')
                            href = (
                                await review_links.first.get_attribute("href")
                                if await review_links.count()
                                else None
                            )
                            if href:
                                review_url = normalize_result_url(urljoin("https://www.trustpilot.com", href))
                            else:
                                digest = hashlib.sha256(review_text.encode("utf-8")).hexdigest()[:20]
                                review_url = f"{profile_url}?review={digest}"
                            if review_url in seen_review_urls:
                                continue
                            seen_review_urls.add(review_url)
                            title = next(
                                (line.strip() for line in review_text.splitlines() if line.strip()),
                                "Trustpilot review",
                            )[:300]
                            observations.append(
                                Observation(
                                    collector=self.name,
                                    category="Automated social and review findings",
                                    entity_type="AUTOMATED_SOCIAL_FINDING",
                                    value=title,
                                    source_url=review_url,
                                    confidence=0.9,
                                    metadata={
                                        "platform": "Trustpilot",
                                        "title": title,
                                        "post_text": review_text[:10_000],
                                        "matched_target_variant": matched_variant,
                                        "normalized_url": review_url,
                                        "collector_method": self.name,
                                        "search_engine": "trustpilot_public_browser",
                                        "query_id": "TRUSTPILOT-DIRECT",
                                        "rank": len(seen_review_urls),
                                        "status": "public_review_captured",
                                        "screenshot_paths": [str(screenshot_path)],
                                        "screenshot_sha256": screenshot_sha256,
                                        "search_url": search_url,
                                        "company_profile_url": profile_url,
                                        "scroll_index": scroll_index + 1,
                                    },
                                )
                            )
                            if len(seen_review_urls) >= max_reviews:
                                return observations
                        except Exception:
                            continue

                    height = await page.evaluate("document.documentElement.scrollHeight")
                    stable_scrolls = stable_scrolls + 1 if height <= previous_height else 0
                    if stable_scrolls >= 2:
                        break
                    previous_height = height
                    await page.evaluate("window.scrollTo(0, document.documentElement.scrollHeight)")
                    await page.wait_for_timeout(wait_ms)
            return observations
        finally:
            await close_browser_session(resources)

    @staticmethod
    async def _raise_if_blocked(page) -> None:
        title = (await page.title()).casefold()
        body = (await page.locator("body").inner_text(timeout=5000)).casefold()[:5000]
        blocked_markers = ("captcha", "access denied", "too many requests", "verify you are human")
        if any(marker in title or marker in body for marker in blocked_markers):
            raise RuntimeError(
                "Trustpilot blocked or challenged the public browser request. "
                "Collection stopped without attempting to bypass the restriction."
            )
