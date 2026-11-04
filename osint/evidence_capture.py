from __future__ import annotations

import asyncio
import hashlib
from io import BytesIO
import json
import os
import re
import math
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from PIL import Image, ImageFilter, ImageStat
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from core.playwright_session import close_browser_session, launch_browser_session
from osint.models import EvidenceScreenshotRecord, NormalizedTarget, PageCaptureRecord
from osint.normalizer import DomainNormalizer
from osint.relevance import RelevanceAssessment, assess_page_relevance, build_target_variants, find_target_reference, target_keyword_proximity
from osint.text_cleanup import clean_evidence_text
from osint.cancellation import InvestigationCancelled
from osint.url_tools import classify_response_content, classify_source_url


HIGHLIGHT_SCRIPT = r"""
({keywords}) => {
  document.querySelectorAll('mark[data-osint-evidence="true"]').forEach((mark) => {
    mark.replaceWith(document.createTextNode(mark.textContent || ''));
  });
  document.body.normalize();

  const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const specs = keywords
    .filter((value) => value && value.trim().length > 1)
    .map((value) => {
      const clean = value.trim();
      const phrase = clean.includes(' ');
      const pattern = phrase
        ? `\\b${escapeRegex(clean).replace(/\\ /g, '\\s+')}\\b`
        : `\\b${escapeRegex(clean)}(?:s|es)?\\b`;
      return {keyword: clean, phrase, regex: new RegExp(pattern, 'gi')};
    })
    .sort((a, b) => b.keyword.length - a.keyword.length);

  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);
  const skipped = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEXTAREA', 'INPUT', 'OPTION', 'SELECT']);

  for (const node of nodes) {
    const parent = node.parentElement;
    if (!parent || skipped.has(parent.tagName) || parent.closest('mark[data-osint-evidence="true"]')) continue;
    const style = getComputedStyle(parent);
    const rect = parent.getBoundingClientRect();
    if (style.display === 'none' || style.visibility === 'hidden' || Number(style.opacity) === 0 || rect.width === 0 || rect.height === 0) continue;
    const text = node.nodeValue || '';
    if (!text.trim()) continue;

    const matches = [];
    for (const spec of specs) {
      spec.regex.lastIndex = 0;
      let match;
      while ((match = spec.regex.exec(text)) !== null) {
        if (!matches.some((item) => match.index < item.end && match.index + match[0].length > item.start)) {
          matches.push({
            start: match.index,
            end: match.index + match[0].length,
            text: match[0],
            keyword: spec.keyword,
            method: spec.phrase ? 'exact_phrase' : (match[0].toLowerCase() === spec.keyword.toLowerCase() ? 'exact_keyword' : 'basic_variant')
          });
        }
        if (match[0].length === 0) spec.regex.lastIndex += 1;
      }
    }
    if (!matches.length) continue;
    matches.sort((a, b) => a.start - b.start);
    const fragment = document.createDocumentFragment();
    let cursor = 0;
    for (const match of matches) {
      fragment.appendChild(document.createTextNode(text.slice(cursor, match.start)));
      const mark = document.createElement('mark');
      mark.dataset.osintEvidence = 'true';
      mark.dataset.keyword = match.keyword;
      mark.dataset.matchMethod = match.method;
      mark.className = 'osint-evidence-primary';
      mark.textContent = match.text;
      fragment.appendChild(mark);
      cursor = match.end;
    }
    fragment.appendChild(document.createTextNode(text.slice(cursor)));
    node.replaceWith(fragment);
  }

  if (!document.getElementById('osint-evidence-style')) {
    const style = document.createElement('style');
    style.id = 'osint-evidence-style';
    style.textContent = `
      mark.osint-evidence-primary {
        background: #fff200 !important; color: #111 !important;
        outline: 3px solid #ff3b30 !important; border-radius: 2px !important;
        padding: 1px 2px !important; box-shadow: 0 0 0 2px rgba(255,255,255,.9) !important;
      }
    `;
    document.head.appendChild(style);
  }

  return Array.from(document.querySelectorAll('mark[data-osint-evidence="true"]')).map((mark, index) => {
    const rect = mark.getBoundingClientRect();
    const contextElement = mark.closest('p, li, blockquote, td, dd, dt') || mark.parentElement;
    return {
      index,
      keyword: mark.dataset.keyword,
      matchedText: mark.textContent || '',
      matchMethod: mark.dataset.matchMethod,
      context: (contextElement?.innerText || mark.parentElement?.innerText || '').trim().slice(0, 1200),
      documentY: Math.round(rect.top + window.scrollY),
    };
  });
}
"""

POPUP_DETECTION_SCRIPT = r"""
() => {
  document.querySelectorAll('[data-osint-popup-candidate], [data-osint-popup-close]').forEach(node => {
    node.removeAttribute('data-osint-popup-candidate');
    node.removeAttribute('data-osint-popup-close');
  });
  const closePattern = /^(close|dismiss|cancel|no thanks|not now|skip|x|×|✕|✖)$/i;
  const visible = element => {
    const style = getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    return style.display !== 'none' && style.visibility !== 'hidden' &&
      Number(style.opacity) > 0 && rect.width > 0 && rect.height > 0;
  };
  const closeControl = root => Array.from(
    root.querySelectorAll('button, [role="button"], [aria-label], [title]')
  ).find(element => {
    if (!visible(element)) return false;
    const rect = element.getBoundingClientRect();
    const label = (
      element.getAttribute('aria-label') ||
      element.getAttribute('title') ||
      element.textContent || ''
    ).trim();
    const identity = `${element.id} ${String(element.className)} ${label}`;
    return closePattern.test(label) ||
      (/close|dismiss/i.test(identity) && rect.width <= 120 && rect.height <= 120);
  });
  const viewportArea = Math.max(innerWidth * innerHeight, 1);
  const candidates = Array.from(document.querySelectorAll('body *'))
    .filter(element => {
      if (!visible(element)) return false;
      const rect = element.getBoundingClientRect();
      const style = getComputedStyle(element);
      const identity = `${element.id} ${String(element.className)}`;
      const semanticModal = element.getAttribute('role') === 'dialog' ||
        element.getAttribute('aria-modal') === 'true';
      const namedOverlay = /modal|popup|overlay|dialog|lightbox|drawer|sheet|banner/i.test(identity);
      const floating = ['fixed', 'sticky'].includes(style.position);
      const usefulSize = rect.width >= 160 && rect.height >= 60;
      const onScreen = rect.right > 0 && rect.bottom > 0 &&
        rect.left < innerWidth && rect.top < innerHeight;
      return onScreen && usefulSize && closeControl(element) &&
        (semanticModal || namedOverlay || floating);
    })
    .map(element => {
      const rect = element.getBoundingClientRect();
      const style = getComputedStyle(element);
      const z = Number.parseInt(style.zIndex, 10) || 0;
      const semantic = element.getAttribute('role') === 'dialog' ||
        element.getAttribute('aria-modal') === 'true';
      const named = /modal|popup|overlay|dialog|lightbox|drawer|sheet|banner/i.test(
        `${element.id} ${String(element.className)}`
      );
      return {
        element,
        area: rect.width * rect.height,
        score: (semantic ? 10000 : 0) + (named ? 5000 : 0) +
          (style.position === 'fixed' ? 2000 : 0) + Math.min(z, 1000)
      };
    })
    .filter(item => item.area < viewportArea * .995)
    .sort((a, b) => b.score - a.score || a.area - b.area);
  if (!candidates.length) return null;
  const popup = candidates[0].element;
  const close = closeControl(popup);
  popup.setAttribute('data-osint-popup-candidate', 'true');
  close?.setAttribute('data-osint-popup-close', 'true');
  return {
    text: (popup.innerText || popup.textContent || '').trim().slice(0, 4000),
    closeLabel: (
      close?.getAttribute('aria-label') ||
      close?.getAttribute('title') ||
      close?.textContent || ''
    ).trim().slice(0, 100)
  };
}
"""


def sanitize_path_component(value: str, limit: int = 80) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "_", value.strip()).strip("._")
    return (cleaned or "unknown")[:limit]


def group_evidence_positions(matches: list[dict], max_distance: int = 500) -> list[list[dict]]:
    groups: list[list[dict]] = []
    for match in sorted(matches, key=lambda item: item["documentY"]):
        if not groups or match["documentY"] - groups[-1][-1]["documentY"] > max_distance:
            groups.append([match])
        else:
            groups[-1].append(match)
    return groups


def first_party_redirect_matches_source(source_url: str, final_url: str) -> bool:
    """Accept a first-party redirect only when its core label is unchanged."""
    source_host = (urlsplit(source_url).hostname or "").casefold().removeprefix("www.")
    final_host = (urlsplit(final_url).hostname or "").casefold().removeprefix("www.")
    source_label = source_host.split(".", 1)[0]
    final_label = final_host.split(".", 1)[0]
    return bool(source_label and len(source_label) >= 4 and source_label == final_label)


def classify_page_access(http_status: int | None, visible_text: str) -> tuple[str | None, str | None]:
    if http_status in {401, 403, 429}:
        return "manual_required", f"HTTP {http_status}"
    if http_status and http_status >= 400:
        return "failed", f"HTTP {http_status}"
    challenge_terms = ("captcha", "verify you are human", "prove your humanity", "cloudflare challenge", "access denied")
    if any(term in visible_text.casefold() for term in challenge_terms):
        return "manual_required", "Anti-bot or CAPTCHA challenge detected"
    return None, None


def assess_screenshot_quality(screenshot_bytes: bytes) -> tuple[bool, str]:
    """Reject empty or near-uniform browser captures before they become evidence."""
    try:
        with Image.open(BytesIO(screenshot_bytes)) as source:
            image = source.convert("RGB")
            if image.width < 200 or image.height < 200:
                return False, "Screenshot dimensions are too small"
            sample = image.resize((160, 90))
            grayscale = sample.convert("L")
            entropy = grayscale.entropy()
            edge_mean = ImageStat.Stat(grayscale.filter(ImageFilter.FIND_EDGES)).mean[0]
            colors = sample.getcolors(maxcolors=160 * 90 + 1) or []
            unique_colors = len(colors)
            dominant_ratio = max((count for count, _ in colors), default=0) / (160 * 90)
    except Exception as exc:
        return False, f"Screenshot could not be decoded: {exc}"

    if unique_colors <= 2 or entropy < 0.20:
        return False, "Screenshot is visually empty"
    if unique_colors < 16:
        return False, "Screenshot is near-uniform and contains no useful visible content"
    if unique_colors < 64 and edge_mean < 2.0:
        return False, "Screenshot is near-uniform and contains no useful visible content"
    if dominant_ratio > 0.985 and edge_mean < 3.0:
        return False, "Screenshot is dominated by a blank background"
    return True, ""


class SERPEvidenceCapturePipeline:
    def __init__(self, evidence_root: Path | str):
        self.evidence_root = Path(evidence_root)
        self.max_screenshots = max(1, min(int(os.getenv("MAX_SCREENSHOTS_PER_SOURCE", "5")), 10))
        self.page_workers = max(1, min(int(os.getenv("PAGE_WORKERS", "3")), 6))
        self.timeout_ms = max(5_000, min(int(os.getenv("OSINT_PAGE_TIMEOUT_MS", "30000")), 120_000))
        self.source_timeout_seconds = max(
            15,
            min(int(os.getenv("OSINT_SOURCE_CAPTURE_TIMEOUT_SECONDS", "90")), 300),
        )
        self.headless = os.getenv("OSINT_EVIDENCE_HEADLESS", "true").lower() not in {"0", "false", "no"}
        self.max_popup_screenshots = max(
            0, min(int(os.getenv("OSINT_POPUP_CAPTURE_LIMIT", "2")), 5)
        )

    async def _wait_for_visual_readiness(self, page) -> None:
        """Allow client-rendered text, fonts, and visible images to settle."""
        try:
            await page.wait_for_function(
                "() => (document.body?.innerText || '').trim().length > 80", timeout=10_000,
            )
        except PlaywrightTimeoutError:
            pass
        try:
            await page.wait_for_load_state("networkidle", timeout=4_000)
        except Exception:
            pass
        try:
            await page.evaluate(
                """async () => {
                    if (document.fonts?.ready) await document.fonts.ready;
                    const images = Array.from(document.images)
                        .filter(img => img.getBoundingClientRect().width > 20 && img.getBoundingClientRect().height > 20)
                        .slice(0, 20);
                    await Promise.all(images.map(img => img.complete ? Promise.resolve() :
                        new Promise(resolve => {
                            img.addEventListener('load', resolve, {once: true});
                            img.addEventListener('error', resolve, {once: true});
                            setTimeout(resolve, 1500);
                        })));
                }"""
            )
        except Exception:
            pass

    async def _capture_quality_screenshot(self, page, locator=None) -> tuple[bytes | None, str]:
        """Capture up to three times and return only visually useful evidence."""
        last_reason = "Screenshot did not contain useful visible content"
        for attempt in range(3):
            if attempt:
                await page.wait_for_timeout(750 * attempt)
            screenshot_bytes = (
                await locator.screenshot()
                if locator is not None
                else await page.screenshot(full_page=False)
            )
            accepted, reason = assess_screenshot_quality(screenshot_bytes)
            if accepted:
                return screenshot_bytes, ""
            last_reason = reason
        return None, last_reason

    async def _capture_and_dismiss_popups(self, page) -> list[dict]:
        """Capture visible overlays before safely dismissing their own close controls."""
        captures = []
        for _ in range(self.max_popup_screenshots):
            popup = await page.evaluate(POPUP_DETECTION_SCRIPT)
            if not popup:
                break
            screenshot_bytes, quality_reason = await self._capture_quality_screenshot(page)
            captures.append({
                **popup,
                "bytes": screenshot_bytes,
                "failure_reason": quality_reason if screenshot_bytes is None else "",
            })
            dismissed = False
            close = page.locator('[data-osint-popup-close="true"]').first
            if await close.count():
                try:
                    await close.click(timeout=2_000)
                    dismissed = True
                except Exception:
                    pass
            if not dismissed:
                await page.keyboard.press("Escape")
            await page.wait_for_timeout(500)
            try:
                still_visible = await page.locator(
                    '[data-osint-popup-candidate="true"]'
                ).is_visible(timeout=500)
            except Exception:
                still_visible = False
            if still_visible:
                break
        return captures

    async def capture(
        self,
        investigation_id: str,
        target_domain: str,
        tasks: list[dict],
        target_brand: str = "",
        cancel_check: Callable[[], bool] | None = None,
    ) -> list[PageCaptureRecord]:
        if not tasks:
            return []
        resources = await launch_browser_session(headless=self.headless)
        semaphore = asyncio.Semaphore(self.page_workers)
        try:
            pending = {
                asyncio.create_task(
                    self._capture_source_with_timeout(
                        resources.context,
                        semaphore,
                        investigation_id,
                        target_domain,
                        task,
                        target_brand,
                    )
                )
                for task in tasks
            }
            completed: list[PageCaptureRecord] = []
            while pending:
                if cancel_check and await asyncio.to_thread(cancel_check):
                    for task in pending:
                        task.cancel()
                    await asyncio.gather(*pending, return_exceptions=True)
                    raise InvestigationCancelled("Investigation cancelled during evidence capture")
                done, pending = await asyncio.wait(
                    pending,
                    timeout=0.5,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in done:
                    completed.append(task.result())
            return completed
        finally:
            await close_browser_session(resources)

    async def _capture_source_with_timeout(
        self,
        context,
        semaphore,
        investigation_id: str,
        target_domain: str,
        task: dict,
        target_brand: str = "",
    ) -> PageCaptureRecord:
        async with semaphore:
            try:
                return await asyncio.wait_for(
                    self._capture_source(
                        context,
                        semaphore,
                        investigation_id,
                        target_domain,
                        task,
                        target_brand,
                    ),
                    timeout=self.source_timeout_seconds,
                )
            except asyncio.TimeoutError:
                return PageCaptureRecord(
                    source_id=task["source_id"],
                    source_url=task["source_url"],
                    accessibility_status="failed",
                    failure_reason=(
                        "Evidence capture exceeded the "
                        f"{self.source_timeout_seconds}-second per-source limit"
                    ),
                )

    async def _capture_source(self, context, semaphore, investigation_id, target_domain, task, target_brand="") -> PageCaptureRecord:
        record = PageCaptureRecord(source_id=task["source_id"], source_url=task["source_url"])
        source_class = classify_source_url(task["source_url"])
        if not source_class.is_content:
            record.accessibility_status = "skipped_non_content"
            record.failure_reason = source_class.reason
            return record
        hostname = urlsplit(task["source_url"]).hostname or ""
        if not await asyncio.to_thread(DomainNormalizer.public_addresses, hostname):
            record.accessibility_status = "manual_required"
            record.failure_reason = "Source does not resolve exclusively to public addresses"
            return record

        page = await context.new_page()
        try:
            response = await self._navigate_page(page, task["source_url"])
            record.http_status = response.status if response else None
            record.final_url = page.url
            access_status, access_reason = classify_page_access(record.http_status, "")
            if access_status:
                record.accessibility_status = access_status
                record.failure_reason = access_reason
                return record
            content_type = response.headers.get("content-type", "") if response else ""
            response_class = classify_response_content(record.final_url, content_type)
            if not response_class.is_content:
                record.accessibility_status = "skipped_non_content"
                record.failure_reason = response_class.reason
                return record
            await self._wait_for_visual_readiness(page)
            record.page_title = await page.title()
            popup_captures = await self._capture_and_dismiss_popups(page)
            body_text = (await page.locator("body").inner_text(timeout=15_000))[:200_000]
            body_sample = (record.page_title + " " + body_text[:4_000]).lower()
            access_status, access_reason = classify_page_access(record.http_status, body_sample)
            if access_status:
                record.accessibility_status = access_status
                record.failure_reason = access_reason
                return record
            if not body_text.strip():
                record.accessibility_status = "failed"
                record.failure_reason = "Page did not render readable content before the capture timeout"
                return record
            canonical_url = await page.locator('link[rel="canonical"]').get_attribute("href") if await page.locator('link[rel="canonical"]').count() else ""
            normalized_target = NormalizedTarget(target_domain, target_domain, f"https://{target_domain}", brand=target_brand)
            page_relevance = assess_page_relevance(
                target=normalized_target,
                visible_text=body_text,
                final_url=record.final_url,
                canonical_url=canonical_url or "",
                page_title=record.page_title,
            )
            if (
                not page_relevance.accepted
                and task.get("first_party_seed")
                and first_party_redirect_matches_source(task["source_url"], record.final_url)
            ):
                page_relevance = RelevanceAssessment(
                    True, (urlsplit(task["source_url"]).hostname or target_domain).casefold(),
                    "first_party_same_label_redirect",
                    "The supplied site redirected to a domain with the same core label",
                )
            if not page_relevance.accepted:
                record.accessibility_status = "rejected_irrelevant"
                record.failure_reason = page_relevance.reason
                return record
            record.matched_target_variant = page_relevance.matched_variant
            record.relevance_field = page_relevance.matched_field

            popup_query = min(task["queries"], key=lambda item: item.get("search_rank", 999999))
            for popup_index, popup in enumerate(popup_captures, start=1):
                screenshot_bytes = popup.get("bytes")
                if screenshot_bytes is None:
                    continue
                screenshot_path = self._screenshot_path(
                    investigation_id,
                    target_domain,
                    "PAGE_POPUP",
                    popup_query.get("search_rank", 0),
                    hostname,
                    popup_index,
                )
                screenshot_path.parent.mkdir(parents=True, exist_ok=True)
                screenshot_path.write_bytes(screenshot_bytes)
                record.screenshots.append(
                    EvidenceScreenshotRecord(
                        query_id="PAGE_POPUP",
                        query_name="Initial page popup",
                        query_category="page_state",
                        search_engine=popup_query.get("search_engine", "direct_browser"),
                        serp_rank=popup_query.get("search_rank", 0),
                        matched_keywords=[],
                        matched_phrases=[],
                        evidence_text="Popup visible when the target page opened.",
                        context_text=clean_evidence_text(
                            popup.get("text") or "Popup contained no readable text.",
                            limit=4_000,
                        ),
                        match_method="popup_before_dismissal",
                        screenshot_path=str(screenshot_path),
                        screenshot_sha256=hashlib.sha256(screenshot_bytes).hexdigest(),
                        confidence=0.75,
                        matched_target_variant=page_relevance.matched_variant,
                    )
                )
            popup_screenshot_count = len(record.screenshots)

            document_queries = [item for item in task["queries"] if item.get("document_type")]
            if task.get("document_priority") and document_queries:
                await self._capture_document_viewer_pages(
                    page, record, investigation_id, target_domain, hostname,
                    document_queries[0], page_relevance.matched_variant,
                )
                if len(record.screenshots) > popup_screenshot_count:
                    record.accessibility_status = "document_viewer_captured"
                    return record

            screenshot_count = 0
            target_variants = build_target_variants(
                normalized_target
            )
            for query in task["queries"]:
                if screenshot_count >= self.max_screenshots:
                    break
                keywords = query.get("evidence_keywords") or []
                proximity = target_keyword_proximity(body_text, target_variants, keywords)
                if proximity is None:
                    continue
                matches = await self.highlight_page(page, list(keywords) + list(target_variants))
                for group in group_evidence_positions(matches):
                    if screenshot_count >= self.max_screenshots:
                        break
                    group_target = find_target_reference(" ".join(item["matchedText"] for item in group), target_variants)
                    group_keywords = [item for item in group if item["keyword"].casefold() not in {variant.casefold() for variant in target_variants}]
                    if not group_target or not group_keywords:
                        continue
                    first = group[0]
                    marks = page.locator('mark[data-osint-evidence="true"]')
                    await marks.nth(first["index"]).scroll_into_view_if_needed()
                    await marks.nth(first["index"]).evaluate(
                        "el => el.scrollIntoView({block: 'center', inline: 'nearest', behavior: 'instant'})"
                    )
                    await page.wait_for_timeout(350)
                    screenshot_path = self._screenshot_path(
                        investigation_id, target_domain, query["query_id"], query["search_rank"], hostname, screenshot_count + 1
                    )
                    screenshot_path.parent.mkdir(parents=True, exist_ok=True)
                    screenshot_bytes, quality_reason = await self._capture_quality_screenshot(page)
                    if screenshot_bytes is None:
                        record.failure_reason = quality_reason
                        continue
                    screenshot_count += 1
                    screenshot_path.write_bytes(screenshot_bytes)
                    matched_keywords = sorted({item["keyword"] for item in group_keywords}, key=str.casefold)
                    matched_phrases = sorted(
                        {item["keyword"] for item in group_keywords if " " in item["keyword"]}, key=str.casefold
                    )
                    contexts = list(dict.fromkeys(item["context"] for item in group if item["context"]))
                    methods = {item["matchMethod"] for item in group_keywords}
                    confidence = 0.95 if "exact_phrase" in methods else 0.82
                    record.screenshots.append(
                        EvidenceScreenshotRecord(
                            query_id=query["query_id"],
                            query_name=query["query_name"],
                            query_category=query["query_category"],
                            search_engine=query["search_engine"],
                            serp_rank=query["search_rank"],
                            matched_keywords=matched_keywords,
                            matched_phrases=matched_phrases,
                            evidence_text=" | ".join(item["matchedText"] for item in group)[:2_000],
                            context_text=clean_evidence_text("\n\n".join(contexts)),
                            match_method=",".join(sorted(methods)),
                            screenshot_path=str(screenshot_path),
                            screenshot_sha256=hashlib.sha256(screenshot_bytes).hexdigest(),
                            confidence=confidence,
                            matched_target_variant=group_target,
                            target_keyword_distance=proximity[2],
                        )
                    )
            if screenshot_count:
                record.accessibility_status = "evidence_found"
            else:
                query = min(task["queries"], key=lambda item: item.get("search_rank", 999999))
                target_matches = await self.highlight_page(page, list(target_variants))
                if target_matches:
                    first = target_matches[0]
                    mark = page.locator('mark[data-osint-evidence="true"]').nth(first["index"])
                    await mark.scroll_into_view_if_needed()
                    await mark.evaluate(
                        "el => el.scrollIntoView({block: 'center', inline: 'nearest', behavior: 'instant'})"
                    )
                    await page.wait_for_timeout(350)
                screenshot_path = self._screenshot_path(
                    investigation_id,
                    target_domain,
                    "TARGET_BASELINE",
                    query.get("search_rank", 0),
                    hostname,
                    1,
                )
                screenshot_path.parent.mkdir(parents=True, exist_ok=True)
                screenshot_bytes, quality_reason = await self._capture_quality_screenshot(page)
                if screenshot_bytes is None:
                    record.accessibility_status = "failed"
                    record.failure_reason = quality_reason
                    return record
                screenshot_path.write_bytes(screenshot_bytes)
                matched_targets = sorted(
                    {item["matchedText"] for item in target_matches if item.get("matchedText")},
                    key=str.casefold,
                )
                contexts = list(dict.fromkeys(item["context"] for item in target_matches if item.get("context")))
                record.screenshots.append(
                    EvidenceScreenshotRecord(
                        query_id="TARGET_BASELINE",
                        query_name="Target-presence baseline",
                        query_category="target_identity",
                        search_engine=query.get("search_engine", "unknown"),
                        serp_rank=query.get("search_rank", 0),
                        matched_keywords=matched_targets,
                        matched_phrases=[item for item in matched_targets if " " in item],
                        evidence_text=(
                            " | ".join(matched_targets)
                            or "Target-relevant page baseline; no visible target term was highlightable."
                        ),
                        context_text=clean_evidence_text("\n\n".join(contexts)),
                        match_method="target_only_baseline" if matched_targets else "page_baseline",
                        screenshot_path=str(screenshot_path),
                        screenshot_sha256=hashlib.sha256(screenshot_bytes).hexdigest(),
                        confidence=0.70 if matched_targets else 0.55,
                        matched_target_variant=page_relevance.matched_variant,
                    )
                )
                record.accessibility_status = "baseline_captured"
            return record
        except Exception as exc:
            record.accessibility_status = "failed"
            record.failure_reason = str(exc)
            return record
        finally:
            await page.close()

    async def _navigate_page(self, page, url):
        for attempt in range(2):
            try:
                response = await page.goto(url, wait_until="commit", timeout=self.timeout_ms)
                if response is None or response.status < 400:
                    try:
                        await page.wait_for_load_state("domcontentloaded", timeout=min(self.timeout_ms, 10_000))
                    except PlaywrightTimeoutError:
                        # Keep the committed document. Slow scripts must not cause
                        # a reload that discards already-rendered evidence.
                        pass
                return response
            except Exception as exc:
                transient = any(token in str(exc) for token in (
                    "ERR_CONNECTION_RESET", "ERR_CONNECTION_CLOSED", "ERR_TIMED_OUT", "Timeout",
                ))
                if attempt or not transient:
                    raise
                await asyncio.sleep(0.5)

    async def _capture_document_viewer_pages(
        self, page, record, investigation_id, target_domain, hostname, query, matched_target_variant
    ) -> None:
        """Capture public HTML document viewers without bypassing access controls."""
        if matched_target_variant:
            await self.highlight_page(page, [matched_target_variant])
        page_locators = None
        for selector in (
            ".page[data-page-number]",
            "[data-page-number]",
            ".pdf-page",
            ".document-page",
            ".outer_page",
        ):
            locator = page.locator(selector)
            if await locator.count():
                page_locators = locator
                break

        captures: list[tuple[int, bytes]] = []
        if page_locators is not None:
            count = await page_locators.count()
            for index in range(count):
                item = page_locators.nth(index)
                try:
                    await item.scroll_into_view_if_needed(timeout=5_000)
                    await page.wait_for_timeout(150)
                    box = await item.bounding_box()
                    if not box or box["width"] < 200 or box["height"] < 200:
                        continue
                    screenshot_bytes, _ = await self._capture_quality_screenshot(page, locator=item)
                    if screenshot_bytes is not None:
                        captures.append((index + 1, screenshot_bytes))
                except Exception:
                    continue

        if not captures:
            embedded_document = await page.locator(
                'embed[type*="pdf" i], object[type*="pdf" i], iframe[src*=".pdf" i]'
            ).count()
            known_viewer_hosts = {
                "acrobat.adobe.com", "docs.google.com", "drive.google.com",
                "issuu.com", "scribd.com", "www.scribd.com", "yumpu.com",
                "www.yumpu.com", "justpaste.it", "anyflip.com", "fliphtml5.com",
                "pubhtml5.com", "calameo.com", "www.calameo.com",
            }
            if not embedded_document and hostname.casefold() not in known_viewer_hosts:
                return
            dimensions = await page.evaluate(
                "() => ({height: Math.max(document.body.scrollHeight, document.documentElement.scrollHeight), "
                "viewport: window.innerHeight || 800})"
            )
            segment_count = max(1, math.ceil(dimensions["height"] / max(dimensions["viewport"], 1)))
            for index in range(segment_count):
                await page.evaluate("y => window.scrollTo(0, y)", index * dimensions["viewport"])
                await page.wait_for_timeout(150)
                screenshot_bytes, _ = await self._capture_quality_screenshot(page)
                if screenshot_bytes is not None:
                    captures.append((index + 1, screenshot_bytes))

        for page_number, screenshot_bytes in captures:
            screenshot_path = self._screenshot_path(
                investigation_id,
                target_domain,
                f"{query['query_id']}_DOCUMENT",
                query.get("search_rank", 0),
                hostname,
                page_number,
            )
            screenshot_path.parent.mkdir(parents=True, exist_ok=True)
            screenshot_path.write_bytes(screenshot_bytes)
            record.screenshots.append(
                EvidenceScreenshotRecord(
                    query_id=query["query_id"],
                    query_name=query.get("query_name") or "Public document viewer",
                    query_category=query.get("query_category") or "documents",
                    search_engine=query.get("search_engine", "unknown"),
                    serp_rank=query.get("search_rank", 0),
                    matched_keywords=[matched_target_variant] if matched_target_variant else [],
                    matched_phrases=[],
                    evidence_text=f"Public document viewer page/segment {page_number}",
                    context_text=(
                        "The source was an accessible HTML document viewer rather than a directly "
                        "downloadable PDF or DOCX."
                    ),
                    match_method="document_viewer_page",
                    screenshot_path=str(screenshot_path),
                    screenshot_sha256=hashlib.sha256(screenshot_bytes).hexdigest(),
                    confidence=0.70,
                    matched_target_variant=matched_target_variant,
                    document_page_number=page_number,
                )
            )

    @staticmethod
    async def highlight_page(page, keywords: list[str]) -> list[dict]:
        return await page.evaluate(HIGHLIGHT_SCRIPT, {"keywords": keywords})

    def _screenshot_path(
        self,
        investigation_id: str,
        target_domain: str,
        query_id: str,
        rank: int,
        source_domain: str,
        sequence: int,
    ) -> Path:
        return (
            self.evidence_root
            / sanitize_path_component(target_domain)
            / sanitize_path_component(investigation_id)
            / sanitize_path_component(query_id)
            / f"rank_{rank:03d}_{sanitize_path_component(source_domain)}"
            / f"evidence_{sequence:03d}.png"
        )
