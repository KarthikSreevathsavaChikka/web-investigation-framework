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
from osint.models import CollectorResult, NormalizedTarget, TargetResolution, Observation
from osint.normalizer import DomainNormalizer
from osint.risk import RiskScorer
from osint.llm_review import RelevanceReviewer, review_source, collected_sources
from osint.readiness import run_readiness, llm_readiness
from osint.target_profile import build_target_profile
from osint.coverage import FINISHED_CAPTURE_STATUSES, observation_has_gap
from osint.url_tools import is_content_page_url, classify_source_url, normalize_result_url
from osint.storage import OSINTRepository
from osint.evidence_capture import SERPEvidenceCapturePipeline
from osint.domain_intelligence import DomainIntelligenceService
from osint.cancellation import InvestigationCancelled
from osint.image_review import ScreenshotSummarizer, screenshot_tasks
from config import EVIDENCE_DIR


def public_social_capture_tasks(repository: OSINTRepository, investigation_id: str, limit: int) -> list[dict]:
    """Select accepted search sources for social findings that still lack a page capture."""
    if limit <= 0:
        return []
    uncaptured_urls: set[str] = set()
    for finding in repository.get_social_findings(investigation_id):
        if not finding.get("post_url") or finding.get("capture_status") == "captured":
            continue
        try:
            uncaptured_urls.add(normalize_result_url(finding["post_url"]))
        except ValueError:
            continue
    return [
        task for task in repository.get_evidence_tasks(investigation_id, 10_000)
        if task.get("normalized_url") in uncaptured_urls
    ][:limit]


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
        try:
            readiness = run_readiness(target, collectors, timeout=context.request_timeout, cancel_check=cancel_check)
            raise_if_cancelled()
            self.repository.save_collector_result(investigation_id, readiness)
            checks = readiness.observations[0].metadata["checks"]
            unavailable = {item["component"]: item["reason"] for item in checks if item["status"] == "unavailable"}
            for collector in collectors:
                if collector.name in unavailable:
                    self.repository.save_collector_result(investigation_id, CollectorResult(
                        collector.name, "FAILED", error=unavailable[collector.name],
                    ))
            collectors = [collector for collector in collectors if collector.name not in unavailable]
            with ThreadPoolExecutor(max_workers=min(max(len(collectors), 1), 4)) as executor:
                future_map = {executor.submit(self._execute, collector, target, context): collector for collector in collectors}
                for future in as_completed(future_map):
                    raise_if_cancelled()
                    result = future.result()
                    self.repository.save_collector_result(investigation_id, result)
                    all_observations.extend(result.observations)
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
            domains = [item["domain"] for item in candidates]
            checks = DomainIntelligenceService().check_many(domains, traffic_cache=self.repository.get_traffic_cache(domains))
            self.repository.save_domain_checks(investigation_id, checks)
            self.repository.save_collector_result(
                investigation_id, CollectorResult("domain_availability", "COMPLETED", duration_seconds=time.monotonic() - check_started)
            )
        except Exception as exc:
            self.repository.save_collector_result(
                investigation_id, CollectorResult("domain_availability", "PARTIAL", error=str(exc), duration_seconds=time.monotonic() - check_started)
            )

        profile = build_target_profile(target, self.repository.get_observations(investigation_id))
        self.repository.save_collector_result(investigation_id, CollectorResult("target_profile", "COMPLETED", [
            Observation("target_profile", "Target identity", "TARGET_PROFILE", target.domain,
                        target.url, confidence=0.0, metadata=profile),
        ]))
        discovery_candidates = self.repository.get_sources(investigation_id)
        excluded = [item for item in discovery_candidates if not is_content_page_url(item["source_url"])]
        self.repository.save_collector_result(investigation_id, CollectorResult("source_selection", "COMPLETED", [
            Observation("source_selection", "Collection diagnostics", "SOURCE_SELECTION", str(len(excluded)),
                        target.url, confidence=0.0, metadata={
                            "excluded_from_page_and_text_review": [{"source_url": item["source_url"], "title": item.get("title", ""),
                                "kind": classify_source_url(item["source_url"]).kind,
                                "reason": classify_source_url(item["source_url"]).reason} for item in excluded],
                            "reason": "Non-page resources retained in discovered sources; excluded before text review and page budgets.",
                        }),
        ]))
        reviewer = None
        if os.getenv("OSINT_LLM_REVIEW_ENABLED", "false").lower() in {"1", "true", "yes"}:
            try:
                if "AI relevance review" in unavailable:
                    # Collection may take minutes; a startup outage must not suppress a recovered model.
                    recheck = llm_readiness()
                    raise_if_cancelled()
                    if recheck["status"] != "ready":
                        unavailable["AI relevance review"] = recheck["reason"]
                        raise RuntimeError(recheck["reason"])
                    unavailable.pop("AI relevance review")
                reviewer = RelevanceReviewer()
                discovery_sources = [review_source(
                    item["source_url"], item.get("title"), item.get("snippet") or item.get("title"),
                    kind="discovery_snippet", source_ref=f"source:{item['id']}", target=target, profile=profile,
                ) for item in discovery_candidates if is_content_page_url(item["source_url"])]
                self.repository.save_collector_result(investigation_id, reviewer.run(
                    target, discovery_sources, stage="discovery", cancel_check=cancel_check, profile=profile,
                ))
            except InvestigationCancelled:
                self.repository.cancel(investigation_id)
                raise
            except Exception as exc:
                self.repository.save_collector_result(investigation_id, CollectorResult(
                    "llm_relevance_discovery", "PARTIAL", error=unavailable.get("AI relevance review", f"Advisory review unavailable: {type(exc).__name__}"),
                ))
                if reviewer is None:
                    self.repository.save_collector_result(investigation_id, CollectorResult(
                        "llm_relevance_content", "PARTIAL", error="AI reviewer unavailable at startup; source evidence retained.",
                    ))

        document_budget = max(0, min(int(os.getenv("OSINT_DOCUMENT_DOWNLOAD_BUDGET", "100")), 10_000))
        document_sources = self.repository.get_document_sources(investigation_id, document_budget)
        source_budget = max(0, min(int(os.getenv("OSINT_SOURCE_CRAWL_BUDGET", "8")), 25))
        ordinary_sources = [source for source in self.repository.get_sources(investigation_id)
                            if is_content_page_url(source["source_url"])
                            and source.get("source_type") not in PublicSearchResultCollector.SKIPPED_SOURCE_TYPES][:source_budget]
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

        # A lightweight HTTP request may be blocked while a public browser can
        # render the supplied page, so always capture the input URL independently.
        self.repository.ensure_first_party_source(investigation_id, target, queries)
        evidence_budget = max(0, min(int(os.getenv("OSINT_EVIDENCE_SOURCE_BUDGET", "8")), 25))
        evidence_tasks = self.repository.get_evidence_tasks(investigation_id, evidence_budget)
        social_capture_budget = max(0, min(int(os.getenv("OSINT_PUBLIC_SOCIAL_CAPTURE_BUDGET", "25")), 25))
        social_evidence_tasks = public_social_capture_tasks(
            self.repository, investigation_id, social_capture_budget,
        )
        document_tasks = self.repository.get_document_capture_tasks(investigation_id)
        merged_tasks = {item["source_id"]: item for item in evidence_tasks}
        for document_task in document_tasks + social_evidence_tasks:
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
                capture_status = "COMPLETED" if len(captures) == len(evidence_tasks) and all(
                    item.accessibility_status in FINISHED_CAPTURE_STATUSES for item in captures
                ) else "PARTIAL"
                capture_error = None if capture_status == "COMPLETED" else (
                    f"{sum(item.accessibility_status not in FINISHED_CAPTURE_STATUSES for item in captures)} "
                    f"capture(s) unavailable; {len(evidence_tasks) - len(captures)} missing. See page capture diagnostics."
                )
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

        if reviewer is not None:
            try:
                self.repository.save_collector_result(investigation_id, reviewer.run(
                    target, collected_sources(self.repository, investigation_id, target=target, profile=profile),
                    stage="content", cancel_check=cancel_check, profile=profile,
                ))
            except InvestigationCancelled:
                self.repository.cancel(investigation_id)
                raise
            except Exception as exc:
                self.repository.save_collector_result(investigation_id, CollectorResult(
                    "llm_relevance_content", "PARTIAL", error=f"Advisory review unavailable: {type(exc).__name__}",
                ))
            if os.getenv("OSINT_LLM_IMAGE_REVIEW_ENABLED", "true").lower() in {"1", "true", "yes"}:
                try:
                    self.repository.save_collector_result(investigation_id, ScreenshotSummarizer().run(
                        target, screenshot_tasks(self.repository, investigation_id), cancel_check=cancel_check,
                    ))
                except InvestigationCancelled:
                    self.repository.cancel(investigation_id)
                    raise
                except Exception as exc:
                    self.repository.save_collector_result(investigation_id, CollectorResult(
                        "llm_screenshot_summary", "PARTIAL", error=f"Visual summaries unavailable: {type(exc).__name__}",
                    ))
        assessment = RiskScorer.assess(all_observations)
        raise_if_cancelled()
        # Completion describes whether processing and reportable persistence finished.
        # Individual collector gaps remain visible through collection coverage.
        self.repository.complete(investigation_id, assessment, "COMPLETED")
        return investigation_id

    @staticmethod
    def _execute(collector: Collector, target, context) -> CollectorResult:
        started = time.monotonic()
        try:
            observations = collector.collect(target, context)
            status = "PARTIAL" if any(
                observation_has_gap(item)
                for item in observations
            ) else "COMPLETED"
            return CollectorResult(collector.name, status, observations, duration_seconds=time.monotonic() - started)
        except InvestigationCancelled:
            raise
        except Exception as exc:
            return CollectorResult(collector.name, "FAILED", error=str(exc), duration_seconds=time.monotonic() - started)
