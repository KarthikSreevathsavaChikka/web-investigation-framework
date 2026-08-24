from __future__ import annotations

import requests

from osint.collectors.base import Collector, CollectorContext
from osint.models import NormalizedTarget, Observation, SearchResult
from osint.relevance import assess_serp_result
from osint.source_classifier import SourceClassifier
from osint.url_tools import normalize_result_url, registrable_domain


class CertificateTransparencyCollector(Collector):
    """Free crt.sh discovery. Returned domains are leads, never accepted evidence."""

    name = "certificate_transparency"
    endpoint = "https://crt.sh/"

    def collect(self, target: NormalizedTarget, context: CollectorContext) -> list[Observation]:
        query = target.brand or target.domain.split(".", 1)[0]
        response = requests.get(
            self.endpoint,
            params={"q": f"%{query}%", "output": "json"},
            headers={"User-Agent": "Web-Investigator-OSINT/1.0"},
            timeout=context.request_timeout,
        )
        response.raise_for_status()
        candidates: dict[str, int] = {}
        for item in response.json():
            for name in str(item.get("name_value", "")).splitlines():
                host = name.casefold().lstrip("*.").strip(".")
                domain = registrable_domain(host)
                if domain and query.casefold().replace(" ", "") in domain.replace("-", ""):
                    candidates[domain] = candidates.get(domain, 0) + 1
        return [
            Observation(
                self.name,
                "Discovery candidates",
                "CANDIDATE_DOMAIN",
                domain,
                f"https://crt.sh/?q=%25{query}%25",
                confidence=0.35,
                metadata={
                    "lead_only": True,
                    "source": "crt.sh",
                    "appearances": appearances,
                    "reason": "Certificate Transparency name match; requires independent validation",
                },
            )
            for domain, appearances in sorted(candidates.items(), key=lambda item: (-item[1], item[0]))[:25]
        ]


class WaybackCDXCollector(Collector):
    """Free historical URL discovery. URLs must pass the normal SERP relevance gate."""

    name = "wayback_cdx"
    endpoint = "https://web.archive.org/cdx/search/cdx"

    def collect(self, target: NormalizedTarget, context: CollectorContext) -> list[Observation]:
        response = requests.get(
            self.endpoint,
            params={
                "url": f"{target.domain}/*",
                "output": "json",
                "fl": "timestamp,original,statuscode,mimetype",
                "filter": "statuscode:200",
                "collapse": "urlkey",
                "limit": min(context.results_per_query * 3, 50),
            },
            headers={"User-Agent": "Web-Investigator-OSINT/1.0"},
            timeout=context.request_timeout,
        )
        response.raise_for_status()
        rows = response.json()
        if rows and isinstance(rows[0], list) and rows[0][:2] == ["timestamp", "original"]:
            rows = rows[1:]
        observations = []
        for rank, row in enumerate(rows, 1):
            if len(row) < 2 or not str(row[1]).startswith(("http://", "https://")):
                continue
            result = SearchResult(
                query_id="WAYBACK_001",
                query_text=f"Wayback historical URLs for {target.domain}",
                search_engine="wayback_cdx",
                rank=rank,
                title=f"Historical URL: {row[1]}",
                url=row[1],
                snippet=f"Wayback capture timestamp: {row[0]}",
            )
            relevance = assess_serp_result(result, target)
            try:
                normalized_url = normalize_result_url(result.url)
            except ValueError:
                continue
            metadata = {
                "query_id": result.query_id,
                "query_text": result.query_text,
                "search_engine": result.search_engine,
                "rank": result.rank,
                "title": result.title,
                "snippet": result.snippet,
                "normalized_url": normalized_url,
                "source_type": SourceClassifier.classify(normalized_url, target.domain),
                "relevance_status": "accepted" if relevance.accepted else "rejected_irrelevant",
                "matched_target_variant": relevance.matched_variant,
                "relevance_field": relevance.matched_field,
                "relevance_reason": relevance.reason,
                "provider_semantic_quality": "full",
                "archived_timestamp": row[0],
            }
            observations.append(Observation(
                self.name,
                "Search.Wayback historical URLs" if relevance.accepted else "Search diagnostics.Wayback",
                "SEARCH_RESULT" if relevance.accepted else "SEARCH_RESULT_REJECTED",
                result.title,
                result.url,
                confidence=0.55 if relevance.accepted else 0.0,
                metadata=metadata,
            ))
        return observations
