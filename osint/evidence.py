from __future__ import annotations

import re

from osint.models import NormalizedTarget, Observation, SearchResult
from osint.relevance import build_target_variants, find_target_reference, target_keyword_proximity


class SearchSnippetEvidenceExtractor:
    """Extract evidence indicators from search titles/snippets without overstating confidence."""

    TERMS = {
        "Money flow": (
            "deposit", "withdrawal", "add money", "cash out", "wallet", "balance", "payout", "payment", "upi",
        ),
        "Payment methods": (
            "phonepe", "google pay", "gpay", "paytm", "bank transfer", "imps", "neft", "rtgs", "usdt", "bitcoin",
        ),
        "Gambling activity": (
            "betting", "sportsbook", "live betting", "casino", "aviator", "teen patti", "andar bahar", "roulette", "slots",
        ),
        "Complaints": (
            "complaint", "scam", "fraud", "withdrawal pending", "withdrawal failed", "deposit not credited", "funds frozen",
        ),
        "Legal and operator": (
            "licence", "license", "operator", "registered office", "regulator", "court order", "legal notice", "blocking order",
        ),
        "Applications": ("apk", "android app", "mobile application", "app download"),
        "Support and social": ("whatsapp", "telegram", "support email", "live chat", "contact number"),
    }

    @classmethod
    def extract(cls, result: SearchResult, source_type: str, target: NormalizedTarget) -> list[Observation]:
        variants = build_target_variants(target)
        matched_target = find_target_reference(result.snippet, variants)
        if not matched_target:
            return []
        searchable = result.snippet.lower()
        observations = []
        for category, terms in cls.TERMS.items():
            matched = sorted({term for term in terms if re.search(rf"\b{re.escape(term)}\b", searchable)})
            if not matched:
                continue
            proximity = target_keyword_proximity(result.snippet, variants, matched)
            if proximity is None:
                continue
            observations.append(
                Observation(
                    collector=result.search_engine,
                    category=f"Evidence.{category}",
                    entity_type="SEARCH_SNIPPET_EVIDENCE",
                    value=", ".join(matched),
                    source_url=result.url,
                    confidence=0.65,
                    metadata={
                        "query_id": result.query_id,
                        "query_text": result.query_text,
                        "search_rank": result.rank,
                        "source_title": result.title,
                        "evidence_snippet": result.snippet,
                        "source_type": source_type,
                        "evidence_scope": "search_snippet",
                        "matched_target_variant": matched_target,
                        "target_relevance_confirmed": True,
                        "target_keyword_distance": proximity[2],
                    },
                )
            )
        return observations


class PublicPageEvidenceExtractor(SearchSnippetEvidenceExtractor):
    """Extract exact, bounded snippets from visible public page text."""

    @classmethod
    def extract(
        cls,
        text: str,
        *,
        collector: str,
        source_url: str,
        source_title: str,
        source_type: str,
        target: NormalizedTarget,
    ) -> list[Observation]:
        normalized = " ".join(text.split())
        lowered = normalized.lower()
        variants = build_target_variants(target)
        matched_target = find_target_reference(normalized, variants)
        if not matched_target:
            return []
        observations = []
        for category, terms in cls.TERMS.items():
            matched = sorted({term for term in terms if re.search(rf"\b{re.escape(term)}\b", lowered)})
            if not matched:
                continue
            proximity = target_keyword_proximity(normalized, variants, matched)
            if proximity is None:
                continue
            first_index = min(lowered.find(term) for term in matched if lowered.find(term) >= 0)
            start = max(first_index - 120, 0)
            end = min(first_index + 280, len(normalized))
            observations.append(
                Observation(
                    collector=collector,
                    category=f"Evidence.{category}",
                    entity_type="PUBLIC_PAGE_EVIDENCE",
                    value=", ".join(matched),
                    source_url=source_url,
                    confidence=0.85,
                    metadata={
                        "source_title": source_title,
                        "source_type": source_type,
                        "evidence_snippet": normalized[start:end],
                        "evidence_scope": "public_page",
                        "matched_target_variant": matched_target,
                        "target_relevance_confirmed": True,
                        "target_keyword_distance": proximity[2],
                    },
                )
            )
        return observations
