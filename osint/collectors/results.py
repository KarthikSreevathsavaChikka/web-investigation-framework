from __future__ import annotations

import os
import time
import hashlib
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit

from bs4 import BeautifulSoup

from config import EVIDENCE_DIR
from osint.evidence import PublicPageEvidenceExtractor
from osint.cancellation import InvestigationCancelled
from osint.documents import assess_docx, assess_pdf, render_docx_pages, render_pdf_pages
from osint.http import get_public_url
from osint.coverage import observation_has_gap
from osint.url_tools import ResourceClassification, classify_response_content, classify_source_url
from osint.models import CollectorResult, NormalizedTarget, Observation
from osint.relevance import assess_page_relevance


class PublicSearchResultCollector:
    name = "public_search_results"
    SKIPPED_SOURCE_TYPES = {
        "social_x", "social_facebook", "social_instagram", "social_youtube",
        "social_reddit", "social_quora", "telegram",
    }
    PDF_MEDIA_TYPES = {"application/pdf", "application/x-pdf"}
    DOCX_MEDIA_TYPES = {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }

    def collect(
        self,
        target: NormalizedTarget,
        sources: list[dict],
        timeout: int,
        investigation_id: str,
        cancel_check=None,
    ) -> CollectorResult:
        started = time.monotonic()
        observations = []
        max_bytes = max(100_000, min(int(os.getenv("OSINT_MAX_ARTIFACT_BYTES", "5000000")), 25_000_000))
        request_delay = max(0.0, min(float(os.getenv("OSINT_SOURCE_REQUEST_DELAY", "0.5")), 5.0))
        for source in sources:
            if cancel_check and cancel_check():
                raise InvestigationCancelled("Investigation cancelled during source collection")
            if source.get("source_type") in self.SKIPPED_SOURCE_TYPES:
                continue
            source_class = classify_source_url(source["source_url"])
            if not source_class.is_content:
                observations.append(self.resource_observation(source, source_class))
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

            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            response_class = classify_response_content(response.url, content_type, response.content[:1024])
            if not response_class.is_content:
                observations.append(self.resource_observation(
                    source, response_class, final_url=response.url, content_type=content_type,
                ))
                continue
            suffix = Path(unquote(urlsplit(response.url).path)).suffix.lower()
            is_pdf = response_class.kind == "document" and (
                content_type in self.PDF_MEDIA_TYPES or suffix == ".pdf" or response.content[:1024].lstrip().startswith(b"%PDF-")
            )
            is_docx = response_class.kind == "document" and (
                content_type in self.DOCX_MEDIA_TYPES or suffix == ".docx"
            )
            is_document_lead = source.get("source_type") in {
                "pdf_document",
                "other_document",
            }
            if is_pdf or is_docx:
                evidence_keywords = tuple(dict.fromkeys(
                    keyword
                    for query in source.get("discovery_queries", [])
                    for keyword in query.get("evidence_keywords", [])
                )) or tuple(
                    keyword
                    for terms in PublicPageEvidenceExtractor.TERMS.values()
                    for keyword in terms
                )
                document_assessment = (
                    assess_pdf(response.content, target, evidence_keywords)
                    if is_pdf
                    else assess_docx(response.content, target, evidence_keywords)
                )
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
                                "source_type": "pdf_document" if is_pdf else "other_document",
                                "relevance_status": "manual_required" if "could not be extracted" in document_assessment.reason else "rejected_irrelevant",
                                "relevance_reason": document_assessment.reason,
                            },
                        )
                    )
                    continue
                artifact_path, artifact_hash = self._store_artifact(
                    investigation_id, response.content, ".pdf" if is_pdf else ".docx"
                )
                highlight_terms = tuple(dict.fromkeys((
                    document_assessment.matched_target_variant,
                    *document_assessment.matched_keywords,
                )))
                page_screenshots = (
                    render_pdf_pages(
                        artifact_path,
                        tuple(document_assessment.relevant_pages),
                        Path(artifact_path).parent / f"{artifact_hash}_pages",
                        highlight_terms=highlight_terms,
                    )
                    if is_pdf
                    else render_docx_pages(
                        artifact_path,
                        Path(artifact_path).parent / f"{artifact_hash}_pages",
                        target,
                        evidence_keywords,
                    )
                )
                file_name = Path(unquote(urlsplit(response.url).path)).name
                if not file_name.lower().endswith((".pdf", ".docx")):
                    file_name = f"{artifact_hash}{'.pdf' if is_pdf else '.docx'}"
                observations.append(
                    Observation(
                        self.name, "Documents", "PUBLIC_DOCUMENT", response.url,
                        source_url, 0.95,
                        metadata={
                            "document_type": document_assessment.document_type,
                            "content_length": len(response.content),
                            "final_url": response.url,
                            "source_type": "pdf_document" if is_pdf else "other_document",
                            "artifact_path": artifact_path,
                            "sha256": artifact_hash,
                            "file_name": file_name,
                            "media_type": content_type or (
                                "application/pdf" if is_pdf else next(iter(self.DOCX_MEDIA_TYPES))
                            ),
                            "discovery_queries": source.get("discovery_queries", []),
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
            if (is_document_lead and "html" not in content_type) or response_class.kind == "document":
                observations.append(
                    Observation(
                        self.name, "Collection diagnostics", "DOCUMENT_REJECTED",
                        "manual_required", source_url, 0.0,
                        metadata={
                            "final_url": response.url,
                            "source_type": source.get("source_type"),
                            "relevance_status": "manual_required",
                            "relevance_reason": (
                                f"Unsupported document format ({content_type or suffix or 'unknown'}); "
                                "only verified PDF and DOCX files are stored automatically"
                            ),
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
                        "page_text": visible_text[:20_000] if not target.domain or source.get("source_type") == "app_download" else "",
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
            "PARTIAL" if any(observation_has_gap(item) for item in observations) else "COMPLETED",
            observations,
            duration_seconds=time.monotonic() - started,
        )

    @staticmethod
    def resource_observation(
        source: dict, classification: ResourceClassification, *, final_url: str = "", content_type: str = "",
    ) -> Observation:
        """Keep excluded URLs auditable without interpreting their bytes as prose."""
        return Observation(
            "public_search_results", "Collection diagnostics",
            "MEDIA_REFERENCE" if classification.kind == "media" else "NON_CONTENT_RESOURCE",
            "skipped_non_content", source["source_url"], 0.0,
            metadata={
                "final_url": final_url or source["source_url"],
                "source_type": source.get("source_type"),
                "resource_kind": classification.kind,
                "media_type": content_type,
                "reason": classification.reason,
                "classification_basis": "response" if final_url else "url_hint",
                "title": source.get("title") or "",
                "discovery_queries": source.get("discovery_queries", []),
            },
        )

    @staticmethod
    def _store_artifact(investigation_id: str, content: bytes, suffix: str) -> tuple[str, str]:
        digest = hashlib.sha256(content).hexdigest()
        # Workers and the Streamlit application run in separate containers.
        # Store document artifacts on the shared evidence volume so the UI can
        # read and display every generated page capture.
        artifact_dir = EVIDENCE_DIR / "documents" / investigation_id
        artifact_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = artifact_dir / f"{digest}{suffix}"
        if not artifact_path.exists():
            artifact_path.write_bytes(content)
        return str(artifact_path), digest
