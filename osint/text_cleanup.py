from __future__ import annotations

import re
from urllib.parse import urlsplit


def social_screenshot_context(finding: dict, screenshot_path: str) -> dict:
    """Keep the text paired with the page that was actually photographed."""
    provenance = next((item for item in finding.get("screenshot_provenance", [])
                       if item.get("path") == screenshot_path), {})
    scope = provenance.get("scope", "search_results")
    text = (finding.get("search_snippet") if scope == "search_results" else finding.get("post_text"))
    if scope == "public_page":
        text = provenance.get("text") or "Public source-page screenshot; finding text was collected separately from search results."
    return {"scope": scope, "text": text or finding.get("post_text") or finding.get("title") or "",
            "url": provenance.get("url") or finding.get("post_url", ""),
            "sha256": provenance.get("sha256", "")}


def evidence_scope(source_url: str, final_url: str, target_domain: str) -> str:
    """Describe a source relationship without confusing a query with its result."""
    target = target_domain.casefold().strip(".").removeprefix("www.")

    def belongs_to_target(url: str) -> bool:
        hostname = (urlsplit(url).hostname or "").casefold().strip(".").removeprefix("www.")
        return bool(target) and (hostname == target or hostname.endswith(f".{target}"))

    source_matches = belongs_to_target(source_url)
    final_matches = belongs_to_target(final_url or source_url)
    if source_matches and final_matches:
        return "Target-domain public page"
    if source_matches and not final_matches:
        return "Target-domain URL redirected to an external page"
    return "External brand-related public page"


def clean_evidence_text(value: str | None, limit: int = 8_000) -> str:
    """Normalize captured prose, remove repeated blocks/sentences, and avoid hard truncation."""
    if not value:
        return ""

    # Extracted PDFs can contain XML-forbidden control characters. Word stores
    # text as XML, so normalize these before report generation.
    value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]", " ", value)

    normalized = re.sub(r"[ \t]+", " ", value.replace("\r", "\n"))
    blocks = [re.sub(r"\s+", " ", item).strip() for item in re.split(r"\n{2,}", normalized)]
    unique_blocks: list[str] = []
    seen_blocks: set[str] = set()
    for block in blocks:
        key = block.casefold()
        if block and key not in seen_blocks:
            unique_blocks.append(block)
            seen_blocks.add(key)

    sentences: list[str] = []
    seen_sentences: set[str] = set()
    for block in unique_blocks:
        parts = re.split(r"(?<=[.!?])\s+(?=[A-Z0-9₹])", block)
        kept: list[str] = []
        for part in parts:
            part = part.strip()
            key = re.sub(r"\s+", " ", part).casefold()
            if part and key not in seen_sentences:
                kept.append(part)
                seen_sentences.add(key)
        if kept:
            sentences.append(" ".join(kept))

    result = "\n\n".join(sentences)
    if len(result) <= limit:
        return result

    bounded = result[:limit]
    sentence_end = max(bounded.rfind(". "), bounded.rfind("! "), bounded.rfind("? "))
    if sentence_end >= int(limit * 0.6):
        return bounded[: sentence_end + 1].rstrip()
    word_end = bounded.rfind(" ")
    return bounded[:word_end].rstrip() + "…" if word_end > 0 else bounded.rstrip() + "…"
