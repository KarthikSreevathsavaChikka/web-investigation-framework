from __future__ import annotations

import time
import uuid
import os
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable

from osint.collectors import AUTHENTICATED_SOCIAL_COLLECTORS, BraveSearchCollector, CertificateTransparencyCollector, DNSCollector, GoogleSearchCollector, KeylessSearchCollector, PublicWebCollector, RDAPCollector, TrustpilotCollector, WaybackCDXCollector, XAuthenticatedCollector
from osint.collectors.base import Collector, CollectorContext
from osint.collectors.results import PublicSearchResultCollector
from osint.dorks import DorkGenerator
from osint.models import CollectorResult, NormalizedTarget, TargetResolution
from osint.normalizer import DomainNormalizer
from osint.risk import RiskScorer
from osint.storage import OSINTRepository
from osint.evidence_capture import SERPEvidenceCapturePipeline
from osint.domain_intelligence import DomainIntelligenceService
from osint.cancellation import InvestigationCancelled
from config import EVIDENCE_DIR


class IntelligenceOrchestrator:
    COLLECTORS = {
        "DNS": DNSCollector,
        "RDAP": RDAPCollector,
        "Public website": PublicWebCollector,
        "Brave Search": BraveSearchCollector,
        "Google public search": GoogleSearchCollector,
        "Keyless Web Search (no API key)": KeylessSearchCollector,
        "Certificate Transparency (crt.sh)": CertificateTransparencyCollector,
        "Wayback historical URLs": WaybackCDXCollector,
        "X/Twitter authenticated search": XAuthenticatedCollector,
        "Trustpilot public reviews": TrustpilotCollector,
        **AUTHENTICATED_SOCIAL_COLLECTORS,
    }

    def __init__(self, repository: OSINTRepository | None = None):
        self.repository = repository or OSINTRepository()
        self.dork_generator = DorkGenerator()

    def run(
        self,
        raw_target: str,
        enabled_collectors: Iterable[str],
        *,
        brand: str = "",
        resolution: TargetResolution | None = None,
        query_budget: int | None = None,
        cancel_check: Callable[[], bool] | None = None,
    ) -> str:
        def raise_if_cancelled() -> None:
            if cancel_check and cancel_check():
                if investigation_id:
                    self.repository.cancel(investigation_id)
                raise InvestigationCancelled("Investigation cancelled by operator")

        investigation_id = ""
        target = DomainNormalizer.normalize(raw_target)
        target = NormalizedTarget(target.raw_input, target.domain, target.url, brand=brand or target.brand)
        investigation_id = f"OSINT_{uuid.uuid4().hex[:10].upper()}"
        queries = self.dork_generator.generate(target, brand=brand)
        context = CollectorContext(
            queries=queries,
            request_timeout=max(3, min(int(os.getenv("OSINT_REQUEST_TIMEOUT", "10")), 60)),
            search_query_budget=max(
                1,
                min(
                    int(
                        query_budget
                        if query_budget is not None
                        else os.getenv("OSINT_QUERY_BUDGET", "12")
                    ),
                    len(queries),
                ),
            ),
            results_per_query=max(1, min(int(os.getenv("OSINT_RESULTS_PER_QUERY", "10")), 20)),
            cancel_check=cancel_check,
        )
        self.repository.create_investigation(investigation_id, target, resolution=resolution)
        self.repository.save_queries(investigation_id, queries)
        raise_if_cancelled()

        collectors = [self.COLLECTORS[name]() for name in enabled_collectors if name in self.COLLECTORS]
        all_observations = []
        had_success = False
        try:
            with ThreadPoolExecutor(max_workers=min(max(len(collectors), 1), 4)) as executor:
                future_map = {executor.submit(self._execute, collector, target, context): collector for collector in collectors}
                for future in as_completed(future_map):
                    raise_if_cancelled()
                    result = future.result()
                    self.repository.save_collector_result(investigation_id, result)
                    all_observations.extend(result.observations)
                    had_success = had_success or result.status == "COMPLETED"
        except InvestigationCancelled:
            self.repository.cancel(investigation_id)
            raise

        # CT discoveries are leads, not evidence, but must receive the same safe availability check.
        raise_if_cancelled()
        self.repository.add_candidate_domains(
            investigation_id,
            [item.value for item in all_observations if item.entity_type == "CANDIDATE_DOMAIN"],
            "Certificate Transparency related-domain lead",
        )
        check_started = time.monotonic()
        try:
            candidates = self.repository.get_candidates(investigation_id)
            checks = DomainIntelligenceService().check_many([item["domain"] for item in candidates])
            self.repository.save_domain_checks(investigation_id, checks)
            self.repository.save_collector_result(
                investigation_id, CollectorResult("domain_availability", "COMPLETED", duration_seconds=time.monotonic() - check_started)
            )
        except Exception as exc:
            self.repository.save_collector_result(
                investigation_id, CollectorResult("domain_availability", "PARTIAL", error=str(exc), duration_seconds=time.monotonic() - check_started)
            )

        document_budget = max(0, min(int(os.getenv("OSINT_DOCUMENT_DOWNLOAD_BUDGET", "1000")), 10_000))
        document_sources = self.repository.get_document_sources(investigation_id, document_budget)
        source_budget = max(0, min(int(os.getenv("OSINT_SOURCE_CRAWL_BUDGET", "8")), 25))
        ordinary_sources = self.repository.get_sources(investigation_id)[:source_budget]
        sources = list(
            {
                item["normalized_url"]: item
                for item in document_sources + ordinary_sources
            }.values()
        )
        if sources:
            try:
                source_result = PublicSearchResultCollector().collect(
                    target,
                    sources,
                    timeout=context.request_timeout,
                    investigation_id=investigation_id,
                    cancel_check=cancel_check,
                )
            except InvestigationCancelled:
                self.repository.cancel(investigation_id)
                raise
            self.repository.save_collector_result(investigation_id, source_result)
            all_observations.extend(source_result.observations)

        evidence_budget = max(0, min(int(os.getenv("OSINT_EVIDENCE_SOURCE_BUDGET", "8")), 25))
        evidence_tasks = self.repository.get_evidence_tasks(investigation_id, evidence_budget)
        document_tasks = self.repository.get_document_capture_tasks(investigation_id)
        merged_tasks = {item["source_id"]: item for item in evidence_tasks}
        for document_task in document_tasks:
            existing = merged_tasks.get(document_task["source_id"])
            if existing:
                query_keys = {
                    (item["query_id"], item.get("search_engine"))
                    for item in existing["queries"]
                }
                existing["queries"].extend(
                    item for item in document_task["queries"]
                    if (item["query_id"], item.get("search_engine")) not in query_keys
                )
                existing["document_priority"] = 1
            else:
                merged_tasks[document_task["source_id"]] = document_task
        evidence_tasks = list(merged_tasks.values())
        raise_if_cancelled()
        if evidence_tasks:
            started = time.monotonic()
            try:
                captures = asyncio.run(
                    SERPEvidenceCapturePipeline(EVIDENCE_DIR).capture(
                        investigation_id,
                        target.domain,
                        evidence_tasks,
                        target.brand,
                        cancel_check=cancel_check,
                    )
                )
                self.repository.save_page_captures(investigation_id, captures)
                capture_status = "COMPLETED" if any(
                    item.accessibility_status in {
                        "evidence_found", "baseline_captured", "document_viewer_captured", "no_evidence"
                    } for item in captures
                ) else "PARTIAL"
                capture_error = None
            except InvestigationCancelled:
                self.repository.cancel(investigation_id)
                raise
            except Exception as exc:
                captures = []
                capture_status = "FAILED"
                capture_error = str(exc)
            self.repository.save_collector_result(
                investigation_id,
                CollectorResult(
                    "serp_evidence_capture",
                    capture_status,
                    error=capture_error,
                    duration_seconds=time.monotonic() - started,
                ),
            )

        assessment = RiskScorer.assess(all_observations)
        raise_if_cancelled()
        status = "COMPLETED" if had_success or not collectors else "PARTIAL"
        self.repository.complete(investigation_id, assessment, status)
        return investigation_id

    @staticmethod
    def _execute(collector: Collector, target, context) -> CollectorResult:
        started = time.monotonic()
        try:
            observations = collector.collect(target, context)
            status = "PARTIAL" if any(
                item.entity_type in {"SEARCH_PROVIDER_MANUAL_REQUIRED", "SEARCH_PROVIDER_ERROR"}
                for item in observations
            ) else "COMPLETED"
            return CollectorResult(collector.name, status, observations, duration_seconds=time.monotonic() - started)
        except InvestigationCancelled:
            raise
        except Exception as exc:
            return CollectorResult(collector.name, "FAILED", error=str(exc), duration_seconds=time.monotonic() - started)
