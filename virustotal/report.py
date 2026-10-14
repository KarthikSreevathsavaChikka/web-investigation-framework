from __future__ import annotations

from io import BytesIO
import json

from docx import Document

from virustotal.client import expand_stored_report
from core.time_utils import format_ist


def _certificate_summary(certificate: dict) -> list[tuple[str, str]]:
    if not certificate:
        return []
    subject = certificate.get("subject") or {}
    issuer = certificate.get("issuer") or {}
    validity = certificate.get("validity") or {}
    return [
        ("Subject", subject.get("CN") or subject.get("common_name") or "Unavailable"),
        ("Issuer", issuer.get("CN") or issuer.get("common_name") or "Unavailable"),
        ("Serial number", str(certificate.get("serial_number") or "Unavailable")),
        ("Valid from", str(validity.get("not_before") or "Unavailable")),
        ("Valid until", str(validity.get("not_after") or "Unavailable")),
        ("Thumbprint", str(certificate.get("thumbprint") or certificate.get("thumbprint_sha256") or "Unavailable")),
    ]


def _add_domain_context(document: Document, report: dict) -> None:
    document.add_heading("Registration and lifecycle", level=2)
    for label, value in (
        ("Registrar", report.get("registrar")),
        ("Creation date", report.get("creation_date")),
        ("Registry update date", report.get("last_update_date")),
        ("WHOIS observed", report.get("whois_date")),
        ("VirusTotal record modified", report.get("last_modification_date")),
    ):
        document.add_paragraph(f"{label}: {value or 'Unavailable'}")

    votes = report.get("total_votes") or {}
    document.add_paragraph(
        f"Community votes: harmless {votes.get('harmless', 0)}; malicious {votes.get('malicious', 0)}"
    )

    dns_records = report.get("dns_records") or []
    document.add_heading("Last observed DNS records", level=2)
    document.add_paragraph(f"Observed: {report.get('last_dns_records_date') or 'Unavailable'}")
    if dns_records:
        table = document.add_table(rows=1, cols=3)
        for cell, title in zip(table.rows[0].cells, ("Type", "Value", "TTL")):
            cell.text = title
        for record in dns_records:
            for cell, value in zip(
                table.add_row().cells,
                (record.get("type"), record.get("value"), record.get("ttl")),
            ):
                cell.text = str(value or "")
    else:
        document.add_paragraph("No DNS records were returned.")

    document.add_heading("Last HTTPS certificate", level=2)
    document.add_paragraph(f"Observed: {report.get('last_https_certificate_date') or 'Unavailable'}")
    certificate_rows = _certificate_summary(report.get("https_certificate") or {})
    if certificate_rows:
        for label, value in certificate_rows:
            document.add_paragraph(f"{label}: {value}")
    else:
        document.add_paragraph("No certificate details were returned.")
    if report.get("jarm"):
        document.add_paragraph(f"JARM fingerprint: {report['jarm']}")

    ranks = report.get("popularity_ranks") or {}
    if ranks:
        document.add_heading("Popularity rankings", level=2)
        for source, details in sorted(ranks.items()):
            document.add_paragraph(f"{source}: {details.get('rank', 'Unavailable')}")

    relationships = report.get("relationships") or {}
    document.add_heading("Related infrastructure", level=2)
    for relationship_name, label in (("resolutions", "Passive DNS resolutions"), ("subdomains", "Subdomains")):
        relationship = relationships.get(relationship_name) or {}
        items = relationship.get("items") or []
        count = relationship.get("count")
        document.add_paragraph(
            f"{label}: {count if count is not None else len(items)} returned by VirusTotal"
        )
        for item in items[:10]:
            attributes = item.get("attributes") or {}
            value = attributes.get("ip_address") or item.get("id")
            document.add_paragraph(str(value), style="List Bullet")

    whois = (report.get("whois") or "").strip()
    if whois:
        document.add_heading("WHOIS record", level=2)
        document.add_paragraph(whois)


def build_docx(report: dict) -> bytes:
    report = expand_stored_report(report)
    document = Document()
    document.add_heading("VirusTotal intelligence report", 0)
    for label, value in (("Report ID", report.get("id")), ("Target", report.get("target")), ("Target type", report.get("target_type")), ("Retrieved at", format_ist(report.get("retrieved_at"))), ("VirusTotal reference", report.get("permalink"))):
        document.add_paragraph(f"{label}: {value or 'Unavailable'}")
    document.add_heading("Detection summary", level=1)
    stats = report.get("analysis_stats") or {}
    document.add_paragraph(", ".join(f"{name}: {count}" for name, count in sorted(stats.items())) or "No analysis statistics returned.")
    document.add_paragraph(f"Reputation: {report.get('reputation', 'Unavailable')}")
    document.add_paragraph(f"Last analysis: {format_ist(report.get('last_analysis_date'))}")
    document.add_heading("Target metadata", level=1)
    for label, value in (("Registrar", report.get("registrar")), ("Country", report.get("country")), ("Network", report.get("network")), ("AS owner", report.get("as_owner")), ("Tags", ", ".join(report.get("tags") or [])), ("Categories", json.dumps(report.get("categories") or {}, ensure_ascii=False))):
        document.add_paragraph(f"{label}: {value or 'Unavailable'}")
    document.add_heading("Malicious and suspicious detections", level=1)
    detections = report.get("detections") or []
    if not detections:
        document.add_paragraph("No malicious or suspicious engine verdicts were returned in this report.")
    else:
        table = document.add_table(rows=1, cols=3)
        for cell, title in zip(table.rows[0].cells, ("Engine", "Category", "Result")):
            cell.text = title
        for item in detections:
            cells = table.add_row().cells
            for cell, value in zip(cells, (item.get("engine"), item.get("category"), item.get("result"))):
                cell.text = str(value or "")
    _add_domain_context(document, report)
    document.add_paragraph("VirusTotal aggregates third-party engine verdicts. Results are evidence for analyst review, not a final safety determination.")
    output = BytesIO()
    document.save(output)
    return output.getvalue()


def build_batch_docx(batch: dict) -> bytes:
    document = Document()
    document.add_heading("Combined VirusTotal intelligence report", 0)
    append_batch(document, batch, heading_level=1, include_heading=False)
    output = BytesIO()
    document.save(output)
    return output.getvalue()


def append_batch(
    document: Document,
    batch: dict,
    *,
    heading_level: int = 1,
    include_heading: bool = True,
) -> None:
    """Append a VirusTotal batch to an existing combined DOCX."""
    if include_heading:
        document.add_heading("VirusTotal intelligence", level=heading_level)
    document.add_paragraph(f"Batch ID: {batch['id']}")
    document.add_paragraph(f"Brand: {batch.get('brand') or 'Not specified'}")
    document.add_paragraph(f"Domains analyzed: {len(batch.get('domains') or [])}")
    document.add_paragraph(f"Retrieved at: {format_ist(batch['retrieved_at'])}")
    completed = sum(item.get("status") == "COMPLETED" for item in batch.get("results") or [])
    document.add_paragraph(f"Completed: {completed}; Failed: {len(batch.get('results') or []) - completed}")
    for item in batch.get("results") or []:
        document.add_heading(item["domain"], level=heading_level + 1)
        if item.get("status") != "COMPLETED" or not item.get("report"):
            document.add_paragraph(f"Status: Failed — {item.get('error') or 'No report returned'}")
            continue
        report = expand_stored_report(item["report"])
        stats = report.get("analysis_stats") or {}
        document.add_paragraph(
            "Detection summary: " + (
                ", ".join(f"{name}: {count}" for name, count in sorted(stats.items()))
                or "No statistics returned"
            )
        )
        document.add_paragraph(f"Reputation: {report.get('reputation', 'Unavailable')}")
        document.add_paragraph(f"Last analysis: {format_ist(report.get('last_analysis_date'))}")
        document.add_paragraph(f"VirusTotal reference: {report['permalink']}")
        document.add_paragraph(f"Categories: {json.dumps(report.get('categories') or {}, ensure_ascii=False)}")
        document.add_paragraph(f"Tags: {', '.join(report.get('tags') or []) or 'Unavailable'}")
        _add_domain_context(document, report)
        detections = report.get("detections") or []
        if detections:
            table = document.add_table(rows=1, cols=3)
            for cell, title in zip(table.rows[0].cells, ("Engine", "Category", "Result")):
                cell.text = title
            for detection in detections:
                for cell, value in zip(table.add_row().cells, (detection.get("engine"), detection.get("category"), detection.get("result"))):
                    cell.text = str(value or "")
        else:
            document.add_paragraph("No malicious or suspicious engine verdicts were returned.")
    document.add_paragraph("VirusTotal results support analyst review and are not a final safety determination.")
