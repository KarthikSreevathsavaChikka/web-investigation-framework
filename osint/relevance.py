from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from osint.models import NormalizedTarget, SearchResult


@dataclass(frozen=True)
class RelevanceAssessment:
    accepted: bool
    matched_variant: str = ""
    matched_field: str = ""
    reason: str = "No target domain or conservative brand variant was found"


def build_target_variants(target: NormalizedTarget) -> tuple[str, ...]:
    domain = target.domain.casefold().removeprefix("www.")
    label = domain.split(".", 1)[0]
    compact_brand = re.sub(r"[^a-z0-9]", "", (target.brand or label).casefold())
    variants = {domain, label, compact_brand}
    match = re.fullmatch(r"([a-z][a-z-]*?)(\d+)", label)
    if match:
        word, digits = match.groups()
        variants.add(f"{word} {digits}")
        if word.endswith("s") and len(word) > 5:
            variants.update({word[:-1], f"{word[:-1]} {digits}"})
    return tuple(sorted((item for item in variants if len(item) >= 5), key=lambda value: (-len(value), value)))


def _variant_in_text(variant: str, text: str) -> bool:
    lowered = text.casefold()
    if "." in variant:
        return variant in lowered
    flexible = r"[\s_-]*".join(re.escape(part) for part in re.findall(r"[a-z]+|\d+", variant))
    return bool(re.search(rf"(?<![a-z0-9]){flexible}(?![a-z0-9])", lowered))


def find_target_reference(text: str, variants: tuple[str, ...]) -> str:
    return next((variant for variant in variants if _variant_in_text(variant, text)), "")


def assess_serp_result(result: SearchResult, target: NormalizedTarget) -> RelevanceAssessment:
    variants = build_target_variants(target)
    hostname = (urlsplit(result.url).hostname or "").casefold().strip(".")
    target_domain = target.domain.casefold().removeprefix("www.")
    if hostname == target_domain or hostname.endswith(f".{target_domain}"):
        return RelevanceAssessment(True, target_domain, "hostname", "Result belongs to the target domain")
    for field, value in (("url", result.url), ("title", result.title), ("snippet", result.snippet)):
        if matched := find_target_reference(value, variants):
            return RelevanceAssessment(True, matched, field, f"Target variant found in result {field}")
    return RelevanceAssessment(False)


def assess_page_relevance(
    *,
    target: NormalizedTarget,
    visible_text: str,
    final_url: str,
    canonical_url: str = "",
    page_title: str = "",
) -> RelevanceAssessment:
    variants = build_target_variants(target)
    target_domain = target.domain.casefold().removeprefix("www.")
    for field, value in (("final_url", final_url), ("canonical_url", canonical_url)):
        hostname = (urlsplit(value).hostname or "").casefold().strip(".")
        if hostname == target_domain or hostname.endswith(f".{target_domain}"):
            return RelevanceAssessment(True, target_domain, field, "Page URL belongs to target domain")
    for field, value in (("page_title", page_title), ("visible_text", visible_text)):
        if matched := find_target_reference(value, variants):
            return RelevanceAssessment(True, matched, field, f"Target variant found in page {field}")
    return RelevanceAssessment(False, reason="Target reference absent from page URL, title, canonical URL, and visible text")


def target_keyword_proximity(
    text: str,
    target_variants: tuple[str, ...],
    evidence_keywords: list[str] | tuple[str, ...],
    max_distance: int = 500,
) -> tuple[str, str, int] | None:
    lowered = text.casefold()
    targets = []
    for variant in target_variants:
        for match in re.finditer(re.escape(variant.casefold()), lowered):
            targets.append((match.start(), variant))
    keywords = []
    for keyword in evidence_keywords:
        pattern = re.escape(keyword.casefold()).replace(r"\ ", r"\s+")
        for match in re.finditer(rf"\b{pattern}(?:s|es)?\b", lowered):
            keywords.append((match.start(), keyword))
    if not targets or not keywords:
        return None
    closest = min(
        ((abs(target_pos - keyword_pos), target, keyword) for target_pos, target in targets for keyword_pos, keyword in keywords),
        key=lambda item: item[0],
    )
    return (closest[1], closest[2], closest[0]) if closest[0] <= max_distance else None
