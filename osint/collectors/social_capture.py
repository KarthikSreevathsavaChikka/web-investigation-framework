"""Bounded, read-only capture of individual social permalinks.

Search snippets remain available when a post is inaccessible. A capture describes
the DOM scope actually read; it never implies that video/audio was transcribed.
"""
from __future__ import annotations

import asyncio
import fcntl
import hashlib
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlsplit

from core.time_utils import now_ist
from osint.cancellation import InvestigationCancelled
from osint.normalizer import DomainNormalizer


PLATFORM_HOSTS = {
    "x": ("x.com", "twitter.com"),
    "instagram": ("instagram.com",),
    "facebook": ("facebook.com",),
    "youtube": ("youtube.com", "youtu.be"),
    "telegram": ("t.me", "web.telegram.org"),
    "quora": ("quora.com",),
}
LOGIN_MARKERS = {
    "x": ("/login", "/i/flow/login", "/account/access"),
    "instagram": ("/accounts/login", "/challenge", "/checkpoint"),
    "facebook": ("/login", "/checkpoint"),
    "youtube": ("accounts.google.com", "/sorry/"),
    "telegram": ("/auth",),
    "quora": ("/login",),
}
AUTH_SELECTORS = {
    "x": '[data-testid="SideNav_AccountSwitcher_Button"], a[href="/messages"]',
    "instagram": 'a[href^="/direct/inbox"]',
    "facebook": '[aria-label="Your profile"], [aria-label="Your account"]',
    "youtube": 'button#avatar-btn img',
    "telegram": '#column-left input[placeholder*="Search" i]',
    "quora": '[aria-label="Your profile"], [aria-label="Profile"]',
}
LOGIN_SELECTORS = 'input[type="password"]:visible, input[name="session[password]"]:visible'
EMPTY_PHRASES = (
    "no results found", "no results for", "we couldn't find any results",
    "we didn’t find any results", "we didn't find any results", "no posts found",
    "no search results", "nothing found", "no matching results",
)


def _setting(name: str, default: int, maximum: int) -> int:
    try:
        return max(0, min(int(os.getenv(name, str(default))), maximum))
    except (ValueError, TypeError):
        return default


def acquire_social_lock(lock_file, context) -> None:
    while True:
        if context.cancellation_requested():
            raise InvestigationCancelled("Investigation cancelled while waiting for a social session")
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            time.sleep(0.2)


def platform_url_allowed(url: str, platform: str) -> bool:
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        return (
            parsed.scheme == "https" and not parsed.username and not parsed.password
            and parsed.port in (None, 443)
            and any(host == base or host.endswith("." + base) for base in PLATFORM_HOSTS[platform])
        )
    except (ValueError, KeyError):
        return False


def post_identity(url: str, platform: str) -> str:
    """Return a stable post identifier, never treating a profile as a post."""
    if not platform_url_allowed(url, platform):
        return ""
    parsed = urlsplit(url)
    path, query = parsed.path, parse_qs(parsed.query)
    if platform == "x":
        match = re.fullmatch(r"/[^/]+/status/(\d+)/?", path)
        return match.group(1) if match else ""
    if platform == "instagram":
        match = re.fullmatch(r"/(?:p|reel|tv)/([\w-]+)/?", path)
        return match.group(1) if match else ""
    if platform == "facebook":
        match = re.search(r"/(?:posts|reel|videos)/(\w+)/?$", path)
        return match.group(1) if match else query.get("story_fbid", query.get("fbid", [""]))[0]
    if platform == "youtube":
        match = re.fullmatch(r"/shorts/([\w-]+)/?", path)
        return query.get("v", [""])[0] if path == "/watch" else (match.group(1) if match else "")
    if platform == "telegram":
        match = re.fullmatch(r"/(?:s/)?([\w]+/\d+)/?", path)
        return match.group(1) if match and parsed.hostname == "t.me" else ""
    if platform == "quora":
        # Search/profile/topic pages cannot stand in for an individual answer.
        return path.rstrip("/") if "/answer/" in path else ""
    return ""


async def install_navigation_guard(page, platform: str) -> None:
    """Validate discovered destinations and redirects before requests proceed."""
    pending_lookups = {}

    async def public_addresses(host):
        # Coalesce simultaneous asset requests, without retaining stale DNS
        # decisions for later requests or redirect destinations.
        task = pending_lookups.get(host)
        if task is None:
            task = asyncio.create_task(asyncio.to_thread(DomainNormalizer.public_addresses, host))
            pending_lookups[host] = task
        try:
            return await task
        finally:
            if task.done() and pending_lookups.get(host) is task:
                pending_lookups.pop(host, None)

    async def guard(route):
        request = route.request
        parsed = urlsplit(request.url)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            await route.abort()
            return
        if request.is_navigation_request() and not platform_url_allowed(request.url, platform):
            await route.abort()
            return
        try:
            addresses = await public_addresses(parsed.hostname)
        except Exception:
            addresses = []
        if not addresses:
            await route.abort()
            return
        await route.continue_()

    await page.route("**/*", guard)


async def validate_social_page(page, platform: str, result_count: int | None = None) -> dict:
    current = page.url.casefold()
    if any(marker in current for marker in LOGIN_MARKERS[platform]):
        raise RuntimeError(f"SESSION_EXPIRED: {platform} redirected to login or account verification.")
    if await page.locator(LOGIN_SELECTORS).count():
        raise RuntimeError(f"SESSION_EXPIRED: {platform} displayed a login form.")
    body = (await page.locator("body").inner_text(timeout=5000))[:12000].casefold()
    # Do not mistake a post discussing a CAPTCHA for a platform challenge.
    challenge = await page.locator('iframe[src*="captcha"], #challenge-form, #captcha-form').count()
    if challenge or (not result_count and any(marker in body for marker in (
        "verify you are human", "too many requests", "access denied", "unusual traffic",
    ))):
        raise RuntimeError(f"ACCESS_CHALLENGED: {platform} blocked or challenged this browser request.")
    authenticated = bool(await page.locator(AUTH_SELECTORS[platform]).count())
    status = "results" if result_count else "unverified"
    if result_count == 0:
        if any(phrase in body for phrase in EMPTY_PHRASES):
            status = "no_results"
        else:
            raise RuntimeError(
                f"SEARCH_LAYOUT_UNRECOGNIZED: {platform} displayed neither readable result cards "
                "nor an explicit no-results message; login, loading, or selectors need checking."
            )
    return {"search_status": status, "authentication": "verified" if authenticated else "unverified"}


async def _first_text(root, selector: str) -> str:
    nodes = root.locator(selector)
    return (await nodes.first.inner_text(timeout=2500)).strip() if await nodes.count() else ""


def post_root_selector(platform: str, identity: str) -> str:
    return {
        "x": 'article[data-testid="tweet"], article',
        "instagram": "article",
        "facebook": 'div[role="article"]',
        "youtube": "ytd-watch-metadata",
        "telegram": f'.tgme_widget_message[data-post="{identity}"]',
        "quora": '[itemprop="acceptedAnswer"], [itemprop="suggestedAnswer"]',
    }[platform]


async def _post_root(page, platform: str, identity: str):
    roots = page.locator(post_root_selector(platform, identity))
    count = await roots.count()
    if platform in {"youtube", "telegram", "quora"}:
        return roots.first if count == 1 else None
    for index in range(min(count, 30)):
        root = roots.nth(index)
        links = root.locator('a[href*="/status/"]:has(time)' if platform == "x" else "a[href]")
        for link_index in range(min(await links.count(), 100)):
            href = await links.nth(link_index).get_attribute("href") or ""
            if post_identity(urljoin(page.url, href), platform) == identity:
                return root
    # Instagram's standalone article sometimes omits its own permalink.
    if platform == "instagram" and count == 1:
        return roots.first
    return None


async def extract_post(page, platform: str, url: str) -> tuple[dict, object]:
    identity = post_identity(url, platform)
    if not identity or post_identity(page.url, platform) != identity:
        raise ValueError("PERMALINK_MISMATCH: destination no longer identifies the requested post.")
    root = await _post_root(page, platform, identity)
    if root is None:
        raise ValueError("POST_SELECTOR_UNAVAILABLE: could not isolate the requested post from replies or navigation.")
    if platform == "youtube":
        expand = root.locator("#description-inline-expander #expand")
        if await expand.count():
            await expand.first.click(timeout=2000)
        title = await _first_text(root, "h1")
        description = await _first_text(root, "#description-inline-expander, #description")
        text, scope = "\n".join(part for part in (title, description) if part), "video_description"
        author = await _first_text(root, "ytd-channel-name")
    else:
        selectors = {
            "x": '[data-testid="tweetText"]',
            "instagram": 'h1, [data-testid="post-caption"]',
            "facebook": '[data-ad-preview="message"], [data-ad-comet-preview="message"]',
            "telegram": ".tgme_widget_message_text",
            "quora": '[itemprop="text"]',
        }
        text, scope = await _first_text(root, selectors[platform]), "post_text"
        author = await _first_text(root, {
            "x": '[data-testid="User-Name"]', "instagram": "header a",
            "facebook": "h2, h3", "telegram": ".tgme_widget_message_author_name",
            "quora": '[itemprop="author"]',
        }[platform])
    if not text.strip():
        raise ValueError("POST_TEXT_UNAVAILABLE: requested post had no extractable caption or description.")
    times = root.locator("time[datetime]")
    published_at = await times.first.get_attribute("datetime") if await times.count() else None
    return {
        "post_text": text[:20000], "content_scope": scope,
        "text_truncated": len(text) > 20000 or text.rstrip().endswith(("…", "...", "See more")),
        "text_completeness": "visible_post_text",
        "author": author[:500], "published_at": published_at,
        "captured_url": page.url, "detail_source_url": page.url,
        "captured_at": now_ist().isoformat(),
        "capture_status": "captured", "capture_reason": "Original permalink text captured from the post container.",
        "extraction_selector_scope": platform,
    }, root


async def enrich_social_findings(browser_context, platform: str, observations, context, output_dir: Path) -> dict:
    limit = _setting("SOCIAL_POST_CAPTURE_LIMIT", 8, 25)
    stage_seconds = _setting("SOCIAL_POST_CAPTURE_STAGE_SECONDS", 60, 300)
    timeout = max(1, _setting("SOCIAL_POST_CAPTURE_TIMEOUT_SECONDS", 12, 45))
    started = time.monotonic()
    attempted = 0
    counts = {"detailed_captures": 0, "unavailable": 0, "budget_skipped": 0, "not_a_post": 0}
    for index, observation in enumerate(observations):
        if context.cancellation_requested():
            raise InvestigationCancelled(f"Investigation cancelled during {platform} post capture")
        metadata = observation.metadata
        metadata.update({
            "search_snippet": metadata.get("post_text", ""),
            "content_scope": "search_snippet", "post_url": observation.source_url,
            "capture_status": "budget_skipped", "capture_reason": "Individual-post capture budget reached.",
            "screenshot_scope": "search_results",
            "screenshot_provenance": [{"path": path, "scope": "search_results",
                "url": metadata.get("search_url", ""), "sha256": metadata.get("screenshot_sha256", "")}
                for path in metadata.get("screenshot_paths", [])],
        })
        observation.confidence = min(observation.confidence, 0.65)
        if not post_identity(observation.source_url, platform):
            metadata.update(capture_status="not_a_post", capture_reason="Search result is not a supported individual-post permalink.")
            counts["not_a_post"] += 1
            continue
        remaining = stage_seconds - (time.monotonic() - started)
        if attempted >= limit or remaining <= 0:
            counts["budget_skipped"] += 1
            continue
        attempted += 1
        page = None
        try:
            async def capture():
                nonlocal page
                page = await browser_context.new_page()
                await install_navigation_guard(page, platform)
                await page.goto(observation.source_url, wait_until="domcontentloaded", timeout=timeout * 1000)
                await validate_social_page(page, platform)
                await page.wait_for_selector(post_root_selector(platform, post_identity(observation.source_url, platform)), timeout=timeout * 1000)
                extracted, root = await extract_post(page, platform, observation.source_url)
                metadata.update(extracted)
                # The screenshot is scoped to the captured post, not the recommendation sidebar.
                screenshot_path = output_dir / f"post_{index + 1:03d}.png"
                try:
                    await root.screenshot(path=str(screenshot_path), timeout=2500)
                    metadata["post_screenshot_path"] = str(screenshot_path)
                    metadata["post_screenshot_sha256"] = hashlib.sha256(screenshot_path.read_bytes()).hexdigest()
                    metadata["screenshot_paths"] = [*metadata.get("screenshot_paths", []), str(screenshot_path)]
                    metadata["screenshot_scope"] = "search_results_and_post"
                    metadata["screenshot_provenance"].append({"path": str(screenshot_path), "scope": "post_container",
                        "url": page.url, "sha256": metadata["post_screenshot_sha256"]})
                except Exception:
                    metadata["post_screenshot_status"] = "unavailable"
            await asyncio.wait_for(capture(), timeout=min(timeout, remaining))
            observation.confidence = 0.8
            metadata["status"] = "post_text_captured"
            counts["detailed_captures"] += 1
        except InvestigationCancelled:
            raise
        except Exception as exc:
            # Do not include browser error URLs: they can contain session identifiers.
            reason = str(exc).split(":", 1)[0] if isinstance(exc, (ValueError, RuntimeError)) else type(exc).__name__
            metadata.update(capture_status="unavailable", capture_reason=f"{reason}: individual post could not be fully captured; search snippet retained.")
            # A timeout during the screenshot must not silently label already extracted text a snippet.
            metadata["post_text"] = metadata["search_snippet"]
            metadata["content_scope"] = "search_snippet"
            counts["unavailable"] += 1
        finally:
            if page is not None:
                try:
                    await asyncio.wait_for(page.close(), timeout=3)
                except Exception:
                    pass
    return counts
