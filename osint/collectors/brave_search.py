from __future__ import annotations

import os
import time
from urllib.parse import quote_plus

from osint.collectors.base import Collector, CollectorContext
from osint.evidence import SearchSnippetEvidenceExtractor
from osint.models import NormalizedTarget, Observation
from osint.search import BingRSSSearchProvider, BraveSearchProvider, DuckDuckGoSearchProvider, GoogleSearchProvider, SearchProvider
from osint.source_classifier import SourceClassifier
from osint.url_tools import normalize_result_url
from osint.relevance import assess_serp_result


class BraveSearchCollector(Collector):
    name = "brave_search"

    def __init__(self, provider: BraveSearchProvider | None = None):
        self.provider = provider or BraveSearchProvider()

    @property
    def available(self) -> bool:
        return self.provider.available

    def collect(self, target: NormalizedTarget, context: CollectorContext) -> list[Observation]:
        if not self.available:
            return []

        observations = []
        default_delay = "0.25" if self.provider.name == "brave" else "1.5"
        request_delay = max(0.0, min(float(os.getenv("OSINT_SEARCH_REQUEST_DELAY", default_delay)), 5.0))
        selected_queries = list(context.queries)[: context.search_query_budget]
        for index, query in enumerate(selected_queries):
            try:
                results = self.provider.search(
                    query.query,
                    query_id=query.query_id,
                    count=context.results_per_query,
                )
            except Exception as exc:
                observations.append(Observation(
                    collector=self.name,
                    category="Search execution",
                    entity_type="SEARCH_PROVIDER_MANUAL_REQUIRED",
                    value="manual_required",
                    source_url="https://www.google.com/search?q=" + quote_plus(query.query) if self.provider.name == "google" else "",
                    confidence=0.0,
                    metadata={
                        "query_id": query.query_id,
                        "query_text": query.query,
                        "provider": self.provider.name,
                        "status": "manual_required",
                        "error": str(exc),
                    },
                ))
                observations.append(Observation(
                    collector=self.name,
                    category="Search execution",
                    entity_type="QUERY_EXECUTION",
                    value=query.query_id,
                    source_url="",
                    confidence=1.0,
                    metadata={
                        "query_id": query.query_id,
                        "provider": self.provider.name,
                        "raw_results": 0,
                        "accepted_results": 0,
                        "rejected_irrelevant": 0,
                        "provider_semantic_quality": self.provider.capabilities.quality_for(query.query),
                        "status": "manual_required",
                    },
                ))
                continue
            accepted_count = 0
            rejected_count = 0
            for result in results:
                try:
                    normalized_url = normalize_result_url(result.url)
                except ValueError:
                    continue
                source_type = SourceClassifier.classify(normalized_url, target.domain)
                relevance = assess_serp_result(result, target)
                common_metadata = {
                    "query_id": result.query_id,
                    "query_text": result.query_text,
                    "search_engine": result.search_engine,
                    "rank": result.rank,
                    "title": result.title,
                    "snippet": result.snippet,
                    "normalized_url": normalized_url,
                    "source_type": source_type,
                    "relevance_status": "accepted" if relevance.accepted else "rejected_irrelevant",
                    "matched_target_variant": relevance.matched_variant,
                    "relevance_field": relevance.matched_field,
                    "relevance_reason": relevance.reason,
                    "provider_semantic_quality": self.provider.capabilities.quality_for(query.query),
                }
                if not relevance.accepted:
                    rejected_count += 1
                    observations.append(
                        Observation(
                            collector=self.name,
                            category=f"Search diagnostics.{query.category}",
                            entity_type="SEARCH_RESULT_REJECTED",
                            value=result.title,
                            source_url=result.url,
                            confidence=0.0,
                            metadata=common_metadata,
                        )
                    )
                    continue
                accepted_count += 1
                observations.append(
                    Observation(
                        collector=self.name,
                        category=f"Search.{query.category}",
                        entity_type="SEARCH_RESULT",
                        value=result.title,
                        source_url=result.url,
                        confidence=0.7,
                        metadata=common_metadata,
                    )
                )
                observations.extend(SearchSnippetEvidenceExtractor.extract(result, source_type, target))
            observations.append(
                Observation(
                    collector=self.name,
                    category="Search execution",
                    entity_type="QUERY_EXECUTION",
                    value=query.query_id,
                    source_url="",
                    confidence=1.0,
                    metadata={
                        "query_id": query.query_id,
                        "provider": self.provider.name,
                        "raw_results": len(results),
                        "accepted_results": accepted_count,
                        "rejected_irrelevant": rejected_count,
                        "provider_semantic_quality": self.provider.capabilities.quality_for(query.query),
                        "status": "completed",
                    },
                )
            )
            if query.category == "support_social":
                observations.extend(self._manual_social_links(target, query))
            if request_delay and index < len(selected_queries) - 1:
                time.sleep(request_delay)
        return observations

    @staticmethod
    def _manual_social_links(target: NormalizedTarget, query) -> list[Observation]:
        """Provide auditable platform search links when anonymous SERP search is incomplete."""
        search_text = f'"{target.domain}" {target.brand or target.domain}'
        encoded = quote_plus(search_text)
        platform_urls = {
            "X/Twitter": f"https://x.com/search?q={encoded}",
            "Reddit": f"https://www.reddit.com/search/?q={encoded}",
            "Instagram": f"https://www.instagram.com/explore/search/keyword/?q={encoded}",
            "Facebook": f"https://www.facebook.com/search/top?q={encoded}",
            "Telegram": f"https://t.me/s/{quote_plus(target.brand or target.domain)}",
        }
        return [
            Observation(
                collector="manual_social_review",
                category=f"Manual review.{query.category}",
                entity_type="MANUAL_REVIEW_LINK",
                value=platform,
                source_url=url,
                confidence=0.0,
                metadata={
                    "query_id": query.query_id,
                    "query_text": query.query,
                    "platform": platform,
                    "status": "manual_required",
                    "target_domain": target.domain,
                    "instruction": "Open the link manually and record only publicly visible target-related posts.",
                },
            )
            for platform, url in platform_urls.items()
        ]


class DuckDuckGoSearchCollector(BraveSearchCollector):
    name = "duckduckgo_search"

    def __init__(self, provider: SearchProvider | None = None):
        self.provider = provider or DuckDuckGoSearchProvider()


class KeylessSearchCollector(BraveSearchCollector):
    name = "keyless_web_search"

    def __init__(self, provider: SearchProvider | None = None):
        self.provider = provider or BingRSSSearchProvider()


class GoogleSearchCollector(BraveSearchCollector):
    name = "google_search"

    def __init__(self, provider: SearchProvider | None = None):
        self.provider = provider or GoogleSearchProvider()
