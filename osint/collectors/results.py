from __future__ import annotations

import os
import time
import hashlib
from pathlib import Path
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from config import DATA_DIR
from osint.evidence import PublicPageEvidenceExtractor
from osint.documents import assess_pdf, render_pdf_pages
from osint.http import get_public_url
from osint.models import CollectorResult, NormalizedTarget, Observation
from osint.relevance import assess_page_relevance


class PublicSearchResultCollector:
    name = "public_search_results"
    SKIPPED_SOURCE_TYPES = {
        "social_x", "social_facebook", "social_instagram", "social_youtube",
        "social_reddit", "social_quora", "telegram", "app_download",
    }

    def collect(
        self,
        target: NormalizedTarget,
        sources: list[dict],
        timeout: int,
        investigation_id: str,
    ) -> CollectorResult:
        started = time.monotonic()
        observations = []
        max_bytes = max(100_000, min(int(os.getenv("OSINT_MAX_ARTIFACT_BYTES", "5000000")), 25_000_000))
        request_delay = max(0.0, min(float(os.getenv("OSINT_SOURCE_REQUEST_DELAY", "0.5")), 5.0))
        for source in sources:
            if source.get("source_type") in self.SKIPPED_SOURCE_TYPES:
                continue
            if request_delay:
                time.sleep(request_delay)
            source_url = source["source_url"]
            try:
                response = get_public_url(
                    source_url,
                    timeout=timeout,
                    headers={"User-Agent": "Web-Investigator-OSINT/1.0"},
                    max_bytes=max_bytes,
                )
            except Exception as exc:
                observations.append(
                    Observation(
                        self.name, "Collection status", "ACCESS_STATUS", "manual_required",
                        source_url, 1.0, metadata={"error": str(exc), "source_type": source.get("source_type")},
                    )
                )
                continue

            if response.status_code in {401, 403, 429}:
                observations.append(
                    Observation(
                        self.name, "Collection status", "ACCESS_STATUS", "manual_required",
                        source_url, 1.0,
                        metadata={"http_status": response.status_code, "source_type": source.get("source_type")},
                    )
                )
                continue
            if not response.ok:
                observations.append(
                    Observation(
                        self.name, "Collection status", "ACCESS_STATUS", "inaccessible",
                        source_url, 1.0,
                        metadata={"http_status": response.status_code, "source_type": source.get("source_type")},
                    )
                )
                continue

            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower()
            if content_type == "application/pdf" or source.get("source_type") == "pdf_document":
                evidence_keywords = tuple(
                    keyword
                    for terms in PublicPageEvidenceExtractor.TERMS.values()
                    for keyword in terms
                )
                document_assessment = assess_pdf(response.content, target, evidence_keywords)
                if not document_assessment.accepted:
                    observations.append(
                        Observation(
                            self.name,
                            "Collection diagnostics",
                            "DOCUMENT_REJECTED",
                            "manual_required" if "could not be extracted" in document_assessment.reason else "rejected_irrelevant",
                            source_url,
                            0.0,
                            metadata={
                                "final_url": response.url,
                                "source_type": "pdf_document",
                                "relevance_status": "manual_required" if "could not be extracted" in document_assessment.reason else "rejected_irrelevant",
                                "relevance_reason": document_assessment.reason,
                            },
                        )
                    )
                    continue
                artifact_path, artifact_hash = self._store_artifact(
                    investigation_id, response.content, ".pdf"
                )
                page_screenshots = render_pdf_pages(
                    artifact_path,
                    document_assessment.relevant_pages,
                    Path(artifact_path).parent / f"{artifact_hash}_pages",
                )
                observations.append(
                    Observation(
                        self.name, "Documents", "PUBLIC_DOCUMENT", response.url,
                        source_url, 0.95,
                        metadata={
                            "document_type": document_assessment.document_type,
                            "content_length": len(response.content),
                            "final_url": response.url,
                            "source_type": "pdf_document",
                            "artifact_path": artifact_path,
                            "sha256": artifact_hash,
                            "matched_target_variant": document_assessment.matched_target_variant,
                            "matched_keywords": list(document_assessment.matched_keywords),
                            "relevant_pages": list(document_assessment.relevant_pages),
                            "evidence_context": document_assessment.evidence_context,
                            "relevance_status": "confirmed_evidence" if document_assessment.matched_keywords else "target_reference_only",
                            "relevance_reason": document_assessment.reason,
                            "page_screenshots": page_screenshots,
                        },
                    )
                )
                continue
            if "html" not in content_type:
                suffix = Path(urljoin(response.url, "")).suffix[:10] or ".bin"
                artifact_path, artifact_hash = self._store_artifact(
                    investigation_id, response.content, suffix
                )
                observations.append(
                    Observation(
                        self.name, "Documents", "PUBLIC_DOCUMENT", response.url,
                        source_url, 0.85,
                        metadata={
                            "document_type": content_type or "unknown",
                            "content_length": len(response.content),
                            "final_url": response.url,
                            "source_type": source.get("source_type"),
                            "artifact_path": artifact_path,
                            "sha256": artifact_hash,
                        },
                    )
                )
                continue

            soup = BeautifulSoup(response.text, "html.parser")
            for element in soup(["script", "style", "noscript"]):
                element.decompose()
            title = soup.title.get_text(" ", strip=True) if soup.title else source.get("title") or response.url
            description_tag = soup.select_one('meta[name="description"]')
            canonical_tag = soup.select_one('link[rel="canonical"]')
            description = description_tag.get("content", "").strip() if description_tag else ""
            canonical = urljoin(response.url, canonical_tag.get("href")) if canonical_tag and canonical_tag.get("href") else ""
            visible_text = soup.get_text(" ", strip=True)[:200_000]
            page_relevance = assess_page_relevance(
                target=target,
                visible_text=visible_text,
                final_url=response.url,
                canonical_url=canonical,
                page_title=title,
            )
            if not page_relevance.accepted:
                observations.append(
                    Observation(
                        self.name, "Collection diagnostics", "PAGE_REJECTED_IRRELEVANT",
                        title, source_url, 0.0,
                        metadata={
                            "final_url": response.url,
                            "canonical_url": canonical,
                            "source_type": source.get("source_type"),
                            "relevance_status": "rejected_irrelevant",
                            "relevance_reason": page_relevance.reason,
                        },
                    )
                )
                continue
            observations.append(
                Observation(
                    self.name, "Page metadata", "PUBLIC_PAGE_METADATA", title,
                    source_url, 0.95,
                    metadata={
                        "final_url": response.url,
                        "meta_description": description,
                        "canonical_url": canonical,
                        "document_type": content_type,
                        "source_type": source.get("source_type"),
                        "relevance_status": "accepted",
                        "matched_target_variant": page_relevance.matched_variant,
                        "relevance_field": page_relevance.matched_field,
                    },
                )
            )
            observations.extend(
                PublicPageEvidenceExtractor.extract(
                    visible_text,
                    collector=self.name,
                    source_url=response.url,
                    source_title=title,
                    source_type=source.get("source_type") or "unknown",
                    target=target,
                )
            )
        return CollectorResult(
            self.name,
            "COMPLETED",
            observations,
            duration_seconds=time.monotonic() - started,
        )

    @staticmethod
    def _store_artifact(investigation_id: str, content: bytes, suffix: str) -> tuple[str, str]:
        digest = hashlib.sha256(content).hexdigest()
        artifact_dir = DATA_DIR / "osint_artifacts" / investigation_id
        artifact_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = artifact_dir / f"{digest}{suffix}"
        if not artifact_path.exists():
            artifact_path.write_bytes(content)
        return str(artifact_path), digest
