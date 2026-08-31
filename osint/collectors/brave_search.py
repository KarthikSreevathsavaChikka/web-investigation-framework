from __future__ import annotations

import os
import time
from urllib.parse import quote_plus

from osint.collectors.base import Collector, CollectorContext
from osint.cancellation import InvestigationCancelled
from osint.evidence import SearchSnippetEvidenceExtractor
from osint.models import NormalizedTarget, Observation
from osint.search import (
    AggregatingSearchProvider,
    BraveSearchProvider,
    DuckDuckGoSearchProvider,
    GoogleSearchProvider,
    SearchProvider,
    SearchProviderExecution,
    build_keyless_search_provider,
)
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
            if context.cancellation_requested():
                raise InvestigationCancelled("Investigation cancelled during search execution")
            try:
                results = self.provider.search(
                    query.query,
                    query_id=query.query_id,
                    count=context.results_per_query,
                )
            except Exception as exc:
                reports = self._execution_reports(query.query_id)
                if reports:
                    for report in reports:
                        observations.extend(self._provider_failure_observations(query, report))
                else:
                    observations.extend(self._provider_failure_observations(
                        query,
                        SearchProviderExecution(
                            query_id=query.query_id,
                            provider=self.provider.name,
                            status="failed",
                            error=str(exc),
                        ),
                    ))
                continue
            reports = self._execution_reports(query.query_id)
            audit_results = [
                result
                for report in reports
                if report.status == "completed"
                for result in report.results
            ] if reports else results
            provider_counts: dict[str, dict[str, int]] = {}
            for report in reports:
                provider_counts[report.provider] = {
                    "raw": len(report.results),
                    "accepted": 0,
                    "rejected": 0,
                }
                if report.status == "failed":
                    observations.extend(self._provider_failure_observations(query, report))
            if not reports:
                provider_counts[self.provider.name] = {
                    "raw": len(results),
                    "accepted": 0,
                    "rejected": 0,
                }

            for result in audit_results:
                try:
                    normalized_url = normalize_result_url(result.url)
                except ValueError:
                    continue
                source_type = SourceClassifier.classify(normalized_url, target.domain)
                relevance = assess_serp_result(result, target)
                counts = provider_counts.setdefault(
                    result.search_engine,
                    {"raw": 0, "accepted": 0, "rejected": 0},
                )
                capabilities = self._capabilities_for(result.search_engine)
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
                    "provider_semantic_quality": capabilities.quality_for(query.query),
                }
                if not relevance.accepted:
                    counts["rejected"] += 1
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
                counts["accepted"] += 1
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
            failed_providers = {report.provider for report in reports if report.status == "failed"}
            for provider_name, counts in provider_counts.items():
                if provider_name in failed_providers:
                    continue
                observations.append(self._query_execution_observation(
                    query,
                    provider_name,
                    raw_results=counts["raw"],
                    accepted_results=counts["accepted"],
                    rejected_irrelevant=counts["rejected"],
                    status="completed",
                ))
            if query.category == "support_social":
                observations.extend(self._manual_social_links(target, query))
            if request_delay and index < len(selected_queries) - 1:
                time.sleep(request_delay)
        return observations

    def _execution_reports(self, query_id: str) -> tuple[SearchProviderExecution, ...]:
        if isinstance(self.provider, AggregatingSearchProvider):
            return self.provider.execution_reports(query_id)
        return ()

    def _capabilities_for(self, provider_name: str):
        if isinstance(self.provider, AggregatingSearchProvider):
            return self.provider.capabilities_for(provider_name)
        return self.provider.capabilities

    def _provider_failure_observations(self, query, report: SearchProviderExecution) -> list[Observation]:
        manual_required = report.provider == "google"
        status = "manual_required" if manual_required else "failed"
        return [
            Observation(
                collector=self.name,
                category="Search execution",
                entity_type="SEARCH_PROVIDER_MANUAL_REQUIRED" if manual_required else "SEARCH_PROVIDER_ERROR",
                value="manual_required" if manual_required else report.provider,
                source_url="https://www.google.com/search?q=" + quote_plus(query.query) if manual_required else "",
                confidence=0.0,
                metadata={
                    "query_id": query.query_id,
                    "query_text": query.query,
                    "provider": report.provider,
                    "status": status,
                    "error": report.error or "Search provider failed",
                },
            ),
            self._query_execution_observation(
                query,
                report.provider,
                raw_results=0,
                accepted_results=0,
                rejected_irrelevant=0,
                status=status,
            ),
        ]

    def _query_execution_observation(
        self,
        query,
        provider_name: str,
        *,
        raw_results: int,
        accepted_results: int,
        rejected_irrelevant: int,
        status: str,
    ) -> Observation:
        return Observation(
            collector=self.name,
            category="Search execution",
            entity_type="QUERY_EXECUTION",
            value=query.query_id,
            source_url="",
            confidence=1.0,
            metadata={
                "query_id": query.query_id,
                "provider": provider_name,
                "raw_results": raw_results,
                "accepted_results": accepted_results,
                "rejected_irrelevant": rejected_irrelevant,
                "provider_semantic_quality": self._capabilities_for(provider_name).quality_for(query.query),
                "status": status,
            },
        )

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
        self.provider = provider or build_keyless_search_provider()


class GoogleSearchCollector(BraveSearchCollector):
    name = "google_search"

    def __init__(self, provider: SearchProvider | None = None):
        self.provider = provider or GoogleSearchProvider()
