from __future__ import annotations

import time
import uuid
import os
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable

from osint.collectors import BraveSearchCollector, CertificateTransparencyCollector, DNSCollector, GoogleSearchCollector, KeylessSearchCollector, PublicWebCollector, RDAPCollector, WaybackCDXCollector
from osint.collectors.base import Collector, CollectorContext
from osint.collectors.results import PublicSearchResultCollector
from osint.dorks import DorkGenerator
from osint.models import CollectorResult, NormalizedTarget, TargetResolution
from osint.normalizer import DomainNormalizer
from osint.risk import RiskScorer
from osint.storage import OSINTRepository
from osint.evidence_capture import SERPEvidenceCapturePipeline
from osint.domain_intelligence import DomainIntelligenceService
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
    ) -> str:
        target = DomainNormalizer.normalize(raw_target)
        target = NormalizedTarget(target.raw_input, target.domain, target.url, brand=brand or target.brand)
        investigation_id = f"OSINT_{uuid.uuid4().hex[:10].upper()}"
        queries = self.dork_generator.generate(target, brand=brand)
        context = CollectorContext(
            queries=queries,
            request_timeout=max(3, min(int(os.getenv("OSINT_REQUEST_TIMEOUT", "10")), 60)),
            search_query_budget=max(1, min(int(os.getenv("OSINT_QUERY_BUDGET", str(len(queries)))), len(queries))),
            results_per_query=max(1, min(int(os.getenv("OSINT_RESULTS_PER_QUERY", "10")), 20)),
        )
        self.repository.create_investigation(investigation_id, target, resolution=resolution)
        self.repository.save_queries(investigation_id, queries)

        collectors = [self.COLLECTORS[name]() for name in enabled_collectors if name in self.COLLECTORS]
        all_observations = []
        had_success = False
        with ThreadPoolExecutor(max_workers=min(max(len(collectors), 1), 4)) as executor:
            future_map = {executor.submit(self._execute, collector, target, context): collector for collector in collectors}
            for future in as_completed(future_map):
                result = future.result()
                self.repository.save_collector_result(investigation_id, result)
                all_observations.extend(result.observations)
                had_success = had_success or result.status == "COMPLETED"

        # CT discoveries are leads, not evidence, but must receive the same safe availability check.
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

        document_budget = max(0, min(int(os.getenv("OSINT_DOCUMENT_DOWNLOAD_BUDGET", "25")), 100))
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
            source_result = PublicSearchResultCollector().collect(
                target,
                sources,
                timeout=context.request_timeout,
                investigation_id=investigation_id,
            )
            self.repository.save_collector_result(investigation_id, source_result)
            all_observations.extend(source_result.observations)

        evidence_budget = max(0, min(int(os.getenv("OSINT_EVIDENCE_SOURCE_BUDGET", "8")), 25))
        evidence_tasks = self.repository.get_evidence_tasks(investigation_id, evidence_budget)
        if evidence_tasks:
            started = time.monotonic()
            try:
                captures = asyncio.run(
                    SERPEvidenceCapturePipeline(EVIDENCE_DIR).capture(
                        investigation_id, target.domain, evidence_tasks, target.brand
                    )
                )
                self.repository.save_page_captures(investigation_id, captures)
                capture_status = "COMPLETED" if any(
                    item.accessibility_status in {"evidence_found", "baseline_captured", "no_evidence"} for item in captures
                ) else "PARTIAL"
                capture_error = None
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
        except Exception as exc:
            return CollectorResult(collector.name, "FAILED", error=str(exc), duration_seconds=time.monotonic() - started)
