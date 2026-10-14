from __future__ import annotations

import asyncio
import fcntl
import hashlib
import os
import re
import uuid
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote, urljoin

import yaml

from config import BASE_DIR, DATA_DIR, EVIDENCE_DIR
from core.screenshot_readiness import wait_for_viewport_readiness
from core.playwright_session import close_browser_session, launch_browser_session
from osint.cancellation import InvestigationCancelled
from osint.collectors.base import Collector, CollectorContext
from osint.collectors.social_capture import (
    acquire_social_lock, enrich_social_findings, install_navigation_guard, validate_social_page,
)
from osint.models import NormalizedTarget, Observation
from osint.url_tools import normalize_result_url


def configured_x_session_path() -> Path:
    return Path(os.getenv("X_STORAGE_STATE_PATH", str(DATA_DIR / "browser_sessions" / "x.json")))


def target_variants(target: NormalizedTarget) -> tuple[str, ...]:
    values = {target.domain.casefold(), target.domain.split(".")[0].casefold()}
    if target.brand.strip():
        values.add(target.brand.strip().casefold())
    return tuple(value for value in values if len(value) >= 3)


def social_search_query(target: NormalizedTarget) -> str:
    """Avoid ambiguous one-word brand searches such as ``Xmax``."""
    label = target.domain.casefold().removeprefix("www.").split(".", 1)[0]
    return target.domain if len(label) <= 5 else (target.brand.strip() or target.domain)


def is_ambiguous_social_target(target: NormalizedTarget) -> bool:
    return len(target.domain.casefold().removeprefix("www.").split(".", 1)[0]) <= 5


SOCIAL_CONTEXT_CATEGORIES = {
    "account_kyc", "applications", "external_complaints", "external_evidence",
    "gambling_activity", "legal_operator", "money_flow", "payment_methods",
    "payment_proof", "promotions", "support_social",
}
SOCIAL_HIGH_SIGNAL_TERMS = (
    "casino", "betting", "gambling", "sportsbook", "wagering", "withdraw",
    "withdrawal", "deposit", "payout", "upi", "payment", "wallet", "bonus",
    "free bet", "kyc", "telegram", "whatsapp",
)


@lru_cache(maxsize=1)
def social_context_keywords() -> tuple[str, ...]:
    """Return high-signal terms configured for target-linked social evidence."""
    config_path = BASE_DIR / "config" / "search_queries.yaml"
    try:
        payload = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return ()
    keywords: list[str] = [
        "official", "verified", "support", "customer support", "help centre",
        "withdraw", "withdrawal", "deposit", "payment", "upi", "payout",
        "casino", "betting", "sportsbook", "bonus", "free bet", "wallet",
        "login", "register", "kyc", "telegram", "whatsapp", "apk", "app",
    ]
    for entry in payload.get("queries", []):
        if entry.get("category") not in SOCIAL_CONTEXT_CATEGORIES:
            continue
        keywords.extend(entry.get("evidence_keywords") or [])
    unique: list[str] = []
    seen: set[str] = set()
    for keyword in keywords:
        cleaned = " ".join(str(keyword).strip().split())
        normalized = cleaned.casefold()
        if len(cleaned) >= 3 and normalized not in seen:
            unique.append(cleaned)
            seen.add(normalized)
    return tuple(unique)


def _term_positions(text: str, term: str) -> list[int]:
    pattern = re.escape(term.casefold()).replace(r"\ ", r"\s+")
    return [match.start() for match in re.finditer(rf"(?<![a-z0-9]){pattern}(?:s|es)?(?![a-z0-9])", text)]


def post_matches_target(text: str, target: NormalizedTarget, max_context_distance: int = 400) -> str:
    """Accept a social post only with target identity and nearby investigation context."""
    # X renders redirect/tracking URLs as visible text. A brand appearing only inside
    # a long spam URL is not evidence that the post discusses the target.
    folded = re.sub(r"https?://\s*\S+", " ", text.casefold())
    domain = target.domain.casefold().removeprefix("www.")
    if domain and domain in folded:
        return domain
    context_positions = [
        position
        for keyword in social_context_keywords()
        for position in _term_positions(folded, keyword)
    ]
    if not context_positions:
        return ""
    if is_ambiguous_social_target(target) and not any(
        _term_positions(folded, term) for term in SOCIAL_HIGH_SIGNAL_TERMS
    ):
        return ""
    for variant in target_variants(target):
        positions = _term_positions(folded, variant)
        if positions and min(abs(target_at - context_at) for target_at in positions for context_at in context_positions) <= max_context_distance:
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
            acquire_social_lock(lock_file, context)
            try:
                return asyncio.run(self._collect(target, context))
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    async def _collect(self, target: NormalizedTarget, context: CollectorContext) -> list[Observation]:
        resources = None
        query = social_search_query(target)
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
        result_cards_seen = 0
        extraction_errors = 0
        try:
            resources = await launch_browser_session(
                headless=True,
                viewport={"width": 1440, "height": 1000},
                storage_state=str(self.session_path),
            )
            page = await resources.context.new_page()
            await install_navigation_guard(page, "x")
            search_url = f"https://x.com/search?q={quote(query)}&src=typed_query&f=live"
            await page.goto(search_url, wait_until="domcontentloaded", timeout=45_000)
            await page.wait_for_timeout(2000)
            await validate_social_page(page, "x", (await page.locator("article").count()) or None)

            for scroll_index in range(max_scrolls):
                if context.cancellation_requested():
                    raise InvestigationCancelled("Investigation cancelled during X collection")
                articles = page.locator("article")
                article_count = await articles.count()
                result_cards_seen += article_count
                screenshot_path = output_dir / f"scroll_{scroll_index + 1:03d}.png"
                await wait_for_viewport_readiness(page, "article")
                await page.screenshot(path=str(screenshot_path), full_page=False, animations="disabled")
                screenshot_sha256 = hashlib.sha256(screenshot_path.read_bytes()).hexdigest()

                for index in range(article_count):
                    if context.cancellation_requested():
                        raise InvestigationCancelled("Investigation cancelled during X extraction")
                    article = articles.nth(index)
                    try:
                        text = (await article.inner_text(timeout=3000)).strip()
                        if not text:
                            extraction_errors += 1
                            continue
                        matched = post_matches_target(text, target)
                        if not matched:
                            continue
                        links = article.locator('a[href*="/status/"]')
                        href = await links.first.get_attribute("href") if await links.count() else None
                        if not href:
                            extraction_errors += 1
                            continue
                        post_url = normalize_result_url(urljoin("https://x.com", href.split('?')[0]))
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
                                confidence=0.65,
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
                                    "status": "search_snippet_captured",
                                    "screenshot_paths": [str(screenshot_path)],
                                    "screenshot_sha256": screenshot_sha256,
                                    "search_url": search_url,
                                    "scroll_index": scroll_index + 1,
                                },
                            )
                        )
                        if len(seen_urls) >= max_posts:
                            break
                    except InvestigationCancelled:
                        raise
                    except Exception:
                        extraction_errors += 1
                        continue

                if len(seen_urls) >= max_posts:
                    break
                height = await page.evaluate("document.documentElement.scrollHeight")
                stable_scrolls = stable_scrolls + 1 if height <= previous_height else 0
                if stable_scrolls >= 2:
                    break
                previous_height = height
                await page.evaluate("window.scrollTo(0, document.documentElement.scrollHeight)")
                await page.wait_for_timeout(scroll_wait_ms)
            diagnostics = await validate_social_page(page, "x", result_cards_seen)
            diagnostics.update({"platform": "X/Twitter", "platform_key": "x",
                                "result_cards_seen": result_cards_seen, "matched_findings": len(observations),
                                "extraction_errors": extraction_errors})
            diagnostics.update(await enrich_social_findings(resources.context, "x", observations, context, output_dir))
            for observation in observations:
                observation.metadata["authentication"] = diagnostics["authentication"]
                if observation.metadata.get("capture_status") == "captured":
                    matched = post_matches_target(observation.metadata["post_text"], target)
                    observation.metadata["detail_matched_target_variant"] = matched
                    if not matched:
                        observation.confidence = 0.5
            observations.append(Observation(
                collector=self.name, category="Collection diagnostics", entity_type="SOCIAL_COLLECTION_DIAGNOSTIC",
                value="X search and post-capture coverage", source_url=search_url,
                confidence=0.0, metadata=diagnostics,
            ))
            return observations
        finally:
            await close_browser_session(resources)
