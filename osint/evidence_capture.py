from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from core.playwright_session import close_browser_session, launch_browser_session
from osint.models import EvidenceScreenshotRecord, NormalizedTarget, PageCaptureRecord
from osint.normalizer import DomainNormalizer
from osint.relevance import assess_page_relevance, build_target_variants, find_target_reference, target_keyword_proximity
from osint.text_cleanup import clean_evidence_text


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


def classify_page_access(http_status: int | None, visible_text: str) -> tuple[str | None, str | None]:
    if http_status in {401, 403, 429}:
        return "manual_required", f"HTTP {http_status}"
    if http_status and http_status >= 400:
        return "failed", f"HTTP {http_status}"
    challenge_terms = ("captcha", "verify you are human", "cloudflare challenge", "access denied")
    if any(term in visible_text.casefold() for term in challenge_terms):
        return "manual_required", "Anti-bot or CAPTCHA challenge detected"
    return None, None


class SERPEvidenceCapturePipeline:
    def __init__(self, evidence_root: Path | str):
        self.evidence_root = Path(evidence_root)
        self.max_screenshots = max(1, min(int(os.getenv("MAX_SCREENSHOTS_PER_SOURCE", "5")), 10))
        self.page_workers = max(1, min(int(os.getenv("PAGE_WORKERS", "3")), 6))
        self.timeout_ms = max(5_000, min(int(os.getenv("OSINT_PAGE_TIMEOUT_MS", "30000")), 120_000))
        self.headless = os.getenv("OSINT_EVIDENCE_HEADLESS", "true").lower() not in {"0", "false", "no"}

    async def capture(
        self,
        investigation_id: str,
        target_domain: str,
        tasks: list[dict],
        target_brand: str = "",
    ) -> list[PageCaptureRecord]:
        if not tasks:
            return []
        resources = await launch_browser_session(headless=self.headless)
        semaphore = asyncio.Semaphore(self.page_workers)
        try:
            return await asyncio.gather(
                *[
                    self._capture_source(resources.context, semaphore, investigation_id, target_domain, task, target_brand)
                    for task in tasks
                ]
            )
        finally:
            await close_browser_session(resources)

    async def _capture_source(self, context, semaphore, investigation_id, target_domain, task, target_brand="") -> PageCaptureRecord:
        record = PageCaptureRecord(source_id=task["source_id"], source_url=task["source_url"])
        hostname = urlsplit(task["source_url"]).hostname or ""
        if not DomainNormalizer.public_addresses(hostname):
            record.accessibility_status = "manual_required"
            record.failure_reason = "Source does not resolve exclusively to public addresses"
            return record

        async with semaphore:
            page = await context.new_page()
            try:
                response = await page.goto(task["source_url"], wait_until="domcontentloaded", timeout=self.timeout_ms)
                record.http_status = response.status if response else None
                record.final_url = page.url
                record.page_title = await page.title()
                body_text = (await page.locator("body").inner_text(timeout=5_000))[:200_000]
                canonical_url = await page.locator('link[rel="canonical"]').get_attribute("href") if await page.locator('link[rel="canonical"]').count() else ""
                normalized_target = NormalizedTarget(target_domain, target_domain, f"https://{target_domain}", brand=target_brand)
                page_relevance = assess_page_relevance(
                    target=normalized_target,
                    visible_text=body_text,
                    final_url=record.final_url,
                    canonical_url=canonical_url or "",
                    page_title=record.page_title,
                )
                if not page_relevance.accepted:
                    record.accessibility_status = "rejected_irrelevant"
                    record.failure_reason = page_relevance.reason
                    return record
                record.matched_target_variant = page_relevance.matched_variant
                record.relevance_field = page_relevance.matched_field
                body_sample = body_text[:4_000].lower()
                access_status, access_reason = classify_page_access(record.http_status, body_sample)
                if access_status:
                    record.accessibility_status = access_status
                    record.failure_reason = access_reason
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
                        screenshot_count += 1
                        screenshot_path = self._screenshot_path(
                            investigation_id, target_domain, query["query_id"], query["search_rank"], hostname, screenshot_count
                        )
                        screenshot_path.parent.mkdir(parents=True, exist_ok=True)
                        screenshot_bytes = await page.screenshot(path=str(screenshot_path), full_page=False)
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
                if record.screenshots:
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
                    screenshot_bytes = await page.screenshot(path=str(screenshot_path), full_page=False)
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
