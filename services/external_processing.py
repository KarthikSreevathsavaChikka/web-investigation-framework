from __future__ import annotations

import os
import time
from datetime import datetime
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

import requests
from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Inches, Pt, RGBColor

from osint.docx_report import OSINTDocxReportBuilder
from osint.orchestrator import IntelligenceOrchestrator
from osint.normalizer import target_for_domain
from osint.resolver import TargetResolver
from osint.search import build_keyless_search_provider
from osint.storage import OSINTRepository
from virustotal.client import VirusTotalClient, VirusTotalError
from virustotal.report import append_batch
from virustotal.storage import VirusTotalRepository
from core.time_utils import format_ist, now_ist


DEFAULT_COLLECTORS = list(IntelligenceOrchestrator.COLLECTORS)
BRAND_SCOPED_COLLECTORS = frozenset({
    "X/Twitter authenticated search",
    "Instagram authenticated search",
    "Facebook authenticated search",
    "Telegram authenticated search",
    "YouTube authenticated search",
    "Quora authenticated search",
    "Trustpilot public reviews",
})


def execute_external_investigation(payload: dict, cancel_check: Callable[[], bool] | None = None) -> dict:
    """Resolve one external target and produce one combined OSINT + VirusTotal DOCX."""
    resolution = TargetResolver().resolve(payload["target"], build_keyless_search_provider())
    domains = [item.domain for item in resolution.candidates]
    domain_limit = max(1, min(int(os.getenv("EXTERNAL_DOMAIN_LIMIT", "25")), 25))
    domains = list(dict.fromkeys(domains))[:domain_limit]
    if not domains:
        raise RuntimeError("No eligible target domains were resolved")

    requested_collectors = payload.get("collectors") or DEFAULT_COLLECTORS
    collectors = [item for item in requested_collectors if item in IntelligenceOrchestrator.COLLECTORS]
    if not collectors:
        raise RuntimeError("No supported evidence collectors were selected")

    repository = OSINTRepository()
    investigation_ids: list[str] = []
    for index, domain in enumerate(domains):
        enabled = collectors if index == 0 else [
            item for item in collectors if item not in BRAND_SCOPED_COLLECTORS
        ]
        investigation_ids.append(IntelligenceOrchestrator(repository).run(
            target_for_domain(payload["target"], domain),
            enabled,
            brand=resolution.resolved_brand,
            resolution=resolution,
            query_budget=int(payload.get("query_budget", 12)),
            cancel_check=cancel_check,
        ))

    vt_batch = _run_virustotal(domains, resolution.resolved_brand, cancel_check)
    report_path = _build_combined_report(payload, resolution, investigation_ids, vt_batch, repository)
    return {
        "component": "external",
        "external_job_id": payload["external_job_id"],
        "complaint_id": payload["complaint_id"],
        "target_id": payload["target_id"],
        "target_url": target_for_domain(payload["target"], domains[0]) if "://" in target_for_domain(payload["target"], domains[0]) else f"https://{domains[0]}",
        "resolved_brand": resolution.resolved_brand,
        "domains": domains,
        "investigation_ids": investigation_ids,
        "virustotal_batch_id": vt_batch.get("id") if vt_batch else None,
        "virustotal_status": "COMPLETED" if vt_batch else "NOT_CONFIGURED",
        "report_path": str(report_path),
    }


def _run_virustotal(domains: list[str], brand: str, cancel_check) -> dict | None:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return None
    client = VirusTotalClient(api_key)
    results = []
    for domain in domains:
        if cancel_check and cancel_check():
            from osint.cancellation import InvestigationCancelled
            raise InvestigationCancelled("External investigation cancelled")
        try:
            results.append({"domain": domain, "status": "COMPLETED", "report": client.lookup(domain), "error": None})
        except (ValueError, VirusTotalError) as exc:
            results.append({"domain": domain, "status": "FAILED", "report": None, "error": str(exc)})
    vt_repository = VirusTotalRepository()
    batch_id = vt_repository.save_batch(brand, domains, results)
    return vt_repository.get_batch(batch_id)


def _build_combined_report(payload, resolution, investigation_ids, vt_batch, repository) -> Path:
    document = Document()
    generated_at = now_ist()
    _configure_report_document(document, generated_at)
    _add_executive_summary(document, payload, resolution, investigation_ids, vt_batch, repository, generated_at)
    builder = OSINTDocxReportBuilder(repository)
    for index, investigation_id in enumerate(investigation_ids):
        document.add_page_break()
        builder.append(document, investigation_id, heading_level=1)
    if vt_batch:
        document.add_page_break()
        append_batch(document, vt_batch, heading_level=1)
    else:
        document.add_page_break()
        document.add_heading("VirusTotal intelligence", level=1)
        document.add_paragraph("VirusTotal was not run because VIRUSTOTAL_API_KEY is not configured.")

    report_dir = Path(os.getenv("EXTERNAL_REPORT_DIR", "/app/reports"))
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / external_report_filename(
        f"https://{resolution.candidates[0].domain}",
        generated_at=generated_at,
    )
    document.save(report_path)
    return report_path


def _configure_report_document(document: Document, generated_at: datetime) -> None:
    """Apply a compact, readable house style to the combined analyst report."""
    section = document.sections[0]
    section.top_margin = Inches(0.6)
    section.bottom_margin = Inches(0.6)
    section.left_margin = Inches(0.65)
    section.right_margin = Inches(0.65)
    styles = document.styles
    normal = styles["Normal"]
    normal.font.name = "Aptos"
    normal.font.size = Pt(9.5)
    normal.font.color.rgb = RGBColor(31, 41, 55)
    for name, size, color in (
        ("Title", 24, RGBColor(15, 50, 86)),
        ("Heading 1", 16, RGBColor(15, 50, 86)),
        ("Heading 2", 12, RGBColor(25, 94, 145)),
        ("Heading 3", 10.5, RGBColor(25, 94, 145)),
    ):
        style = styles[name]
        style.font.name = "Aptos Display"
        style.font.size = Pt(size)
        style.font.bold = True
        style.font.color.rgb = color
    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    footer.text = f"Web Investigation Framework · Generated {format_ist(generated_at)}"
    footer.runs[0].font.size = Pt(8)
    footer.runs[0].font.color.rgb = RGBColor(100, 116, 139)


def _add_key_value_table(document: Document, rows: list[tuple[str, object]]) -> None:
    table = document.add_table(rows=0, cols=2)
    table.style = "Light Shading Accent 1"
    for label, value in rows:
        cells = table.add_row().cells
        cells[0].text = label
        cells[1].text = str(value if value not in {None, ""} else "Unavailable")
        for run in cells[0].paragraphs[0].runs:
            run.font.bold = True


def _add_executive_summary(
    document: Document,
    payload: dict,
    resolution,
    investigation_ids: list[str],
    vt_batch: dict | None,
    repository: OSINTRepository,
    generated_at: datetime,
) -> None:
    title = document.add_heading("Web Scraping and VirusTotal report", 0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    subtitle = document.add_paragraph("External investigation summary")
    subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
    subtitle.runs[0].font.color.rgb = RGBColor(71, 85, 105)
    document.add_heading("Executive summary", level=1)
    _add_key_value_table(document, [
        ("Report generated", format_ist(generated_at)),
        ("External job ID", payload.get("external_job_id")),
        ("Complaint ID", payload.get("complaint_id")),
        ("Requested by", payload.get("requested_by") or "Not supplied"),
        ("Target ID", payload.get("target_id")),
        ("Received target", payload["target"]),
        ("Resolved brand", resolution.resolved_brand or "Unknown"),
        ("Primary domain", resolution.candidates[0].domain if resolution.candidates else "Unavailable"),
        ("Domains analyzed", len(investigation_ids)),
        ("Web Scraping investigations", len(investigation_ids)),
        ("VirusTotal", "Completed" if vt_batch else "Not configured"),
    ])
    total_evidence = sum(len(repository.get_evidence(investigation_id)) for investigation_id in investigation_ids)
    total_documents = sum(len(repository.get_documents(investigation_id)) for investigation_id in investigation_ids)
    document.add_heading("Key results", level=2)
    _add_key_value_table(document, [
        ("Evidence screenshots captured", total_evidence),
        ("Verified public documents", total_documents),
        ("VirusTotal domain reports", len((vt_batch or {}).get("results") or [])),
    ])
    document.add_heading("Scope and interpretation", level=2)
    document.add_paragraph(
        "This report combines publicly accessible web evidence with VirusTotal intelligence for the domains listed below. "
        "Search-derived candidate domains and security-engine verdicts support analyst review; they do not by themselves prove common ownership, illegality, or a final safety determination."
    )
    document.add_paragraph("Domains covered:", style="List Bullet")
    for candidate in resolution.candidates[:len(investigation_ids)]:
        document.add_paragraph(candidate.domain, style="List Bullet 2")
    document.add_heading("Report guide", level=2)
    document.add_paragraph(
        "The following sections provide one Web Scraping record per analyzed domain, followed by the VirusTotal intelligence results. "
        "Each evidence item includes its source URL, discovery context, and screenshot hash where a capture is available."
    )


def external_report_filename(target_url: str, *, generated_at: datetime) -> str:
    """Return the human-readable DOCX filename delivered to the complaint system."""
    hostname = (urlsplit(target_url).hostname or "report").lower()
    safe_hostname = "".join(char if char.isalnum() or char in ".-" else "-" for char in hostname)
    return f"WebScraping-{safe_hostname}-{generated_at.strftime('%d-%b-%Y')}.docx"


def send_external_callback(payload: dict, status: str, *, result: dict | None = None, error: str | None = None) -> None:
    """Deliver the callback with bounded retries and without exposing internal tracebacks."""
    callback_url = os.getenv("EXTERNAL_CALLBACK_URL", "").strip()
    if not callback_url:
        raise RuntimeError("EXTERNAL_CALLBACK_URL is not configured")
    result = result or {}
    form = {
        "job_id": payload["external_job_id"],
        "complaint_id": payload["complaint_id"],
        "target_id": payload["target_id"],
        "status": status,
        "url": result.get("target_url") or payload.get("target") or "",
        "error": (error or "")[:1000],
    }
    report_path = Path(result.get("report_path", "")) if result.get("report_path") else None
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            if report_path and report_path.is_file():
                with report_path.open("rb") as handle:
                    response = requests.post(
                        callback_url,
                        data=form,
                        files={"file": (report_path.name, handle, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")},
                        timeout=30,
                    )
            else:
                response = requests.post(callback_url, data=form, timeout=30)
            response.raise_for_status()
            return
        except requests.RequestException as exc:
            last_error = exc
            if attempt < 2:
                time.sleep(2 ** attempt)
    raise RuntimeError(f"External callback delivery failed: {last_error}")
