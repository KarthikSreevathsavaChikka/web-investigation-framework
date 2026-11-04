from __future__ import annotations

from io import BytesIO
from pathlib import Path
from urllib.parse import urlsplit

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.opc.constants import RELATIONSHIP_TYPE as RT
from docx.shared import Inches, Cm, Pt

from osint.storage import OSINTRepository
from osint.text_cleanup import clean_evidence_text, evidence_scope, social_screenshot_context
from osint.report_presentation import observed_identity, report_overview
from osint.report_branding import LEFT_LOGO, RIGHT_LOGO
from core.time_utils import format_ist


class OSINTDocxReportBuilder:
    """Build a portable report with stored evidence and its discovery sources."""

    def __init__(self, repository: OSINTRepository):
        self.repository = repository

    @staticmethod
    def _add_source_link(paragraph, url: str) -> None:
        """Write a visible URL with an explicit Word hyperlink relationship."""
        try:
            parsed = urlsplit(url)
            valid = parsed.scheme in {"http", "https"} and bool(parsed.hostname)
        except ValueError:
            valid = False
        if not valid:
            paragraph.add_run(url or "Unavailable")
            return
        hyperlink = OxmlElement("w:hyperlink")
        hyperlink.set(qn("r:id"), paragraph.part.relate_to(url, RT.HYPERLINK, is_external=True))
        run = OxmlElement("w:r")
        properties = OxmlElement("w:rPr")
        color = OxmlElement("w:color")
        color.set(qn("w:val"), "0563C1")
        underline = OxmlElement("w:u")
        underline.set(qn("w:val"), "single")
        properties.extend([color, underline])
        run.append(properties)
        text = OxmlElement("w:t")
        text.text = url
        run.append(text)
        hyperlink.append(run)
        paragraph._p.append(hyperlink)

    def build(self, investigation_id: str) -> bytes:
        report = Document()
        investigation = self.repository.get_investigation(investigation_id)
        section = report.sections[0]
        section.page_width, section.page_height = Cm(21), Cm(29.7)
        section.top_margin = section.bottom_margin = Cm(1.8)
        section.left_margin = section.right_margin = Cm(1.6)
        section.header_distance = section.footer_distance = Cm(0.7)
        normal = report.styles["Normal"]
        normal.font.name = "Arial"
        normal.font.size = Pt(10)
        normal.paragraph_format.space_after = Pt(7)
        normal.paragraph_format.line_spacing = 1.15
        for name in ("Heading 1", "Heading 2", "Heading 3"):
            style = report.styles[name]
            style.font.name = "Arial"
            style.paragraph_format.space_before = Pt(16)
            style.paragraph_format.space_after = Pt(8)
            style.paragraph_format.keep_with_next = True

        header = section.header
        header_table = header.add_table(rows=1, cols=2, width=Cm(17.8))
        header_table.columns[0].width = Cm(11)
        header_table.columns[1].width = Cm(6.8)
        for cell, image_path, fallback, width in (
            (header_table.cell(0, 0), LEFT_LOGO, "MINISTRY OF ELECTRONICS\nAND INFORMATION TECHNOLOGY", Cm(8.0)),
            (header_table.cell(0, 1), RIGHT_LOGO, "सी-डैक\nC-DAC", Cm(2.5)),
        ):
            if image_path.is_file():
                cell.paragraphs[0].add_run().add_picture(str(image_path), width=width)
            else:
                cell.text = fallback
        header_table.cell(0, 1).paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.RIGHT
        for cell in header_table.rows[0].cells:
            for paragraph in cell.paragraphs:
                for run in paragraph.runs:
                    run.bold = True
                    run.font.size = Pt(9)
        footer = section.footer.paragraphs[0]
        footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
        footer.add_run(f"Confidential  ·  {investigation_id}  ·  Page ")
        page_field = OxmlElement("w:fldSimple")
        page_field.set(qn("w:instr"), "PAGE")
        footer._p.append(page_field)
        cover_label = report.add_paragraph("Confidential")
        cover_label.alignment = WD_ALIGN_PARAGRAPH.CENTER
        cover_label.runs[0].italic = True
        cover_label.paragraph_format.space_before = Pt(40)
        title = report.add_paragraph()
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        title.paragraph_format.space_before = Cm(6)
        title.add_run("TECHNICAL ASSESSMENT REPORT").bold = True
        subtitle = report.add_paragraph("for the")
        subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
        subject = report.add_paragraph(f"{investigation.get('resolved_brand') or investigation.get('target_domain') or 'Target'} — Web investigation")
        subject.alignment = WD_ALIGN_PARAGRAPH.CENTER
        subject.runs[0].bold = True
        reference = report.add_paragraph(f"Report ID: {investigation_id}")
        reference.alignment = WD_ALIGN_PARAGRAPH.CENTER
        report.add_page_break()
        report.add_heading("Web intelligence and OSINT report", 0)
        report.add_heading("Executive summary", level=1)
        for label, value in report_overview(investigation, self.repository.get_summary_counts(investigation_id)):
            paragraph = report.add_paragraph()
            paragraph.add_run(f"{label}: ").bold = True
            paragraph.add_run(value)
        report.add_paragraph(f"Collection status: {investigation['coverage']['status']}. {investigation['coverage']['message']}")
        report.add_paragraph("Risk scores describe collected indicators only. A low score does not establish that a target is safe.")
        report.add_paragraph("Reading guide: The following sections give the evidence and source details. 'No records' means no item was stored for that section.")
        self.append(report, investigation_id)
        output = BytesIO()
        report.save(output)
        return output.getvalue()

    def append(self, report: Document, investigation_id: str, heading_level: int = 1) -> None:
        """Append a complete investigation to an existing combined DOCX."""
        investigation = self.repository.get_investigation(investigation_id)
        evidence = self.repository.get_evidence(investigation_id)
        documents = self.repository.get_documents(investigation_id)
        social_findings = self.repository.get_social_findings(investigation_id)
        domains = self.repository.get_candidates(investigation_id)
        sources = self.repository.get_sources(investigation_id)
        screenshot_summaries = {item.get("screenshot_path"): item for item in self.repository.get_screenshot_summaries(investigation_id)}
        report.add_heading(f"Web Scraping — {investigation.get('target_domain') or investigation_id}", level=heading_level)
        report.add_paragraph(f"Investigation reference: {investigation_id}")
        report.add_heading("Target", level=heading_level + 1)
        target_table = report.add_table(rows=0, cols=2)
        target_table.style = "Light Shading Accent 1"
        for label, value in (
            ("Original input", investigation.get("original_input")),
            ("Resolved domain", investigation.get("target_domain")),
            ("Resolved brand", investigation.get("resolved_brand")),
            ("Status", investigation.get("status")),
        ):
            cells = target_table.add_row().cells
            cells[0].text = label
            cells[1].text = str(value or "Unknown")
            for run in cells[0].paragraphs[0].runs:
                run.font.bold = True

        coverage = investigation["coverage"]
        report.add_heading("Collection coverage", level=heading_level + 1)
        report.add_paragraph(f"{coverage['status']}: {coverage['message']}")
        report.add_paragraph(coverage["risk_notice"])
        diagnostics = self.repository.get_collection_diagnostics(investigation_id)
        if diagnostics["readiness"].get("checks"):
            report.add_heading("Worker readiness", level=heading_level + 1)
            for check in diagnostics["readiness"]["checks"]:
                report.add_paragraph(f"{check['component']}: {check['status']} — {check['reason']}")
        profile = diagnostics["target_profile"]
        if profile:
            report.add_heading("Observed target identity", level=heading_level + 1)
            report.add_paragraph("Names and accounts below were observed in collected sources. They do not establish ownership.")
            for label, value in observed_identity(profile):
                paragraph = report.add_paragraph()
                paragraph.add_run(f"{label}: ").bold = True
                paragraph.add_run(value)
        for diagnostic in diagnostics["social_collection"]:
            report.add_paragraph(
                f"Social extraction ({diagnostic.get('platform', 'platform')}): "
                f"{diagnostic.get('detailed_captures', 0)} detailed captures; "
                f"{diagnostic.get('unavailable', 0)} unavailable; "
                f"{diagnostic.get('budget_skipped', 0)} outside detail budget."
            )
        report.add_heading("Resolved / related domains", level=heading_level + 1)
        report.add_paragraph("Traffic figures are third-party estimated visits, not exact site analytics.")
        table = report.add_table(rows=1, cols=5)
        table.style = "Light Shading Accent 1"
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        for cell, label in zip(table.rows[0].cells, ("Domain", "Status / HTTP", "Monthly Visits", "Yearly Visits", "Traffic source")):
            cell.text = label
        for item in domains:
            cells = table.add_row().cells
            values = (
                item.get("domain"), f"{item.get('domain_status', 'Unknown')} / {item.get('http_status') or 'Unavailable'}",
                item.get("monthly_visits") if item.get("monthly_visits") is not None else "Unavailable",
                (str(item.get("yearly_visits")) + (" (Projected)" if item.get("yearly_visits_kind") == "Projected" else "")) if item.get("yearly_visits") is not None else "Unavailable",
                item.get("traffic_source", "Unavailable"),
            )
            for cell, value in zip(cells, values):
                cell.text = str(value)
            yearly_basis = "12-month estimate" if item.get("yearly_visits_kind") == "Actual" else item.get("yearly_visits_kind", "Unavailable")
            report.add_paragraph(
                f"Traffic for {item.get('domain')}: {item.get('traffic_status') or 'not_checked'} | "
                f"Data month: {item.get('traffic_data_date') or 'Unavailable'} | Yearly basis: {yearly_basis} | "
                f"Checked: {format_ist(item.get('traffic_refreshed_at'))}. {item.get('traffic_error') or ''}"
            )

        report.add_heading("Source URLs", level=heading_level + 1)
        report.add_paragraph(
            "All discovered sources recorded for this investigation are listed below, including historical URLs "
            "and non-page resources. Discovery alone does not establish that a source was captured or verified."
        )
        if not sources:
            report.add_paragraph("No source URLs were recorded.")
        for index, source in enumerate(sources, 1):
            paragraph = report.add_paragraph()
            paragraph.add_run(f"{index}. {source.get('title') or source['source_url']}").bold = True
            self._add_source_link(report.add_paragraph("Source URL: "), source["source_url"])
            report.add_paragraph(
                f"Source type: {source.get('source_type') or 'unknown'} | "
                f"Discovery query count: {source.get('discovered_by_queries', 0)}"
            )
            if source.get("snippet"):
                report.add_paragraph(source["snippet"])

        reviews = self.repository.get_llm_reviews(investigation_id)
        if reviews:
            report.add_heading("AI relevance review — advisory", level=heading_level + 1)
            report.add_paragraph("Text-only model interpretations, not verified evidence. Original evidence is retained; ownership and allegations are not established by these reviews.")
            for review in reviews:
                report.add_paragraph(f"{review['source_url']} | {review['stage']} | {review['relevance']} | {review['relationship']}: {review['reason']}")
                report.add_paragraph(f"Model: {review['model']} | Prompt: {review['prompt_version']} | Review status: {review['review_status']}")
        report.add_heading("Verified web evidence", level=heading_level + 1)
        if not evidence and not documents:
            report.add_paragraph("No confirmed target-specific public evidence found.")
        included_evidence_screenshots: set[str] = set()
        for item in evidence:
            screenshot_key = item.get("sha256") or item.get("screenshot_path")
            if screenshot_key and screenshot_key in included_evidence_screenshots:
                continue
            if screenshot_key:
                included_evidence_screenshots.add(screenshot_key)
            scope = evidence_scope(
                item["source_url"], item.get("final_url") or item["source_url"],
                investigation.get("target_domain") or "",
            )
            report.add_heading(f"Web evidence — {scope}", level=heading_level + 2)
            detail_table = report.add_table(rows=0, cols=2)
            detail_table.style = "Light Shading Accent 1"
            for label, value in (
                ("Discovery query", item.get('query_name') or item['query_id']),
                ("Source URL", item['source_url']),
                ("Final URL", item.get('final_url') or item['source_url']),
                ("Matched target", item.get('matched_target_variant') or 'stored page match'),
                ("Matched keywords", ', '.join(item.get('matched_keywords') or []) or 'None recorded'),
            ):
                cells = detail_table.add_row().cells
                cells[0].text = label
                if label in {"Source URL", "Final URL"}:
                    self._add_source_link(cells[1].paragraphs[0], str(value))
                else:
                    cells[1].text = str(value)
                for run in cells[0].paragraphs[0].runs:
                    run.font.bold = True
            report.add_paragraph(clean_evidence_text(item.get("context_text") or item.get("evidence_text")))
            image_path = Path(item["screenshot_path"])
            if image_path.is_file():
                report.add_paragraph("AI visual summary (advisory): " + (
                    screenshot_summaries.get(item["screenshot_path"], {}).get("summary") or "Not generated"
                ))
                report.add_picture(str(image_path), width=Inches(6.2))
                report.add_paragraph(f"Screenshot SHA-256: {item.get('sha256') or ''}")

        text_only_findings = [item for item in social_findings if not item.get("screenshot_paths")]
        if text_only_findings:
            report.add_heading("Collected social text", level=heading_level + 1)
            report.add_paragraph(
                "Social findings without a stored screenshot. Captured findings are shown once beside their screenshot below."
            )
            for item in text_only_findings:
                report.add_paragraph(f"{item.get('platform', 'Social')} | {item.get('post_url', '')}")
                report.add_paragraph(f"Text scope: {item.get('content_scope', 'legacy capture')} | Capture: {item.get('capture_status', 'legacy')}")
                report.add_paragraph(clean_evidence_text(item.get("post_text") or item.get("title"), limit=6_000))

        social_by_screenshot: dict[str, list[dict]] = {}
        for finding in social_findings:
            for screenshot_path in finding.get("screenshot_paths") or []:
                social_by_screenshot.setdefault(screenshot_path, []).append(finding)
        if social_by_screenshot:
            report.add_heading("Social and review captures", level=heading_level + 1)
            report.add_paragraph(
                "Each browser screenshot is included once, followed by the target-matching posts visible during that capture."
            )
        described_social_urls: set[str] = set()
        for screenshot_path, findings in social_by_screenshot.items():
            platform = findings[0].get("platform") or "Social platform"
            report.add_heading(f"{platform} capture", level=heading_level + 2)
            described_in_capture = 0
            for finding in findings:
                finding_key = finding.get("post_url") or f"finding:{finding.get('id')}"
                if finding_key in described_social_urls:
                    continue
                described_social_urls.add(finding_key)
                described_in_capture += 1
                screenshot_context = social_screenshot_context(finding, screenshot_path)
                report.add_paragraph(f"Post URL: {finding.get('post_url') or 'Unavailable'}")
                if finding.get("content_scope"):
                    report.add_paragraph(
                        f"Text scope: {finding['content_scope']} | Detail capture: {finding.get('capture_status', 'unknown')} | "
                        f"Screenshot scope: {screenshot_context['scope']}"
                    )
                    if finding.get("capture_reason"):
                        report.add_paragraph(f"Capture note: {finding['capture_reason']}")
                    if finding.get("author") or finding.get("published_at"):
                        report.add_paragraph(f"Author: {finding.get('author') or 'unavailable'} | Published: {format_ist(finding.get('published_at'))}")
                report.add_paragraph(
                    clean_evidence_text(screenshot_context["text"], limit=2_000)
                )
            if not described_in_capture:
                report.add_paragraph("Additional screenshot for social findings described above.")
            image_path = Path(screenshot_path)
            if image_path.is_file():
                report.add_paragraph("AI visual summary (advisory): " + (
                    screenshot_summaries.get(screenshot_path, {}).get("summary") or "Not generated"
                ))
                report.add_picture(str(image_path), width=Inches(6.2))

        if documents:
            report.add_heading("Verified public documents", level=heading_level + 1)
        for item in documents:
            report.add_heading(item.get("document_type") or "Public document", level=heading_level + 2)
            self._add_source_link(report.add_paragraph("Source URL: "), item["source_url"])
            report.add_paragraph(f"Matched target: {item.get('matched_target_variant') or ''}")
            report.add_paragraph(f"Relevant pages: {', '.join(map(str, item.get('relevant_pages') or []))}")
            report.add_paragraph(clean_evidence_text(item.get("evidence_context"), limit=12_000))
            for capture in item.get("page_screenshots", []):
                image_path = Path(capture.get("path", ""))
                if image_path.is_file():
                    report.add_paragraph("AI visual summary (advisory): " + (
                        screenshot_summaries.get(capture.get("path"), {}).get("summary") or "Not generated"
                    ))
                    report.add_picture(str(image_path), width=Inches(6.2))
                    report.add_paragraph(f"Document page {capture.get('page')} SHA-256: {capture.get('sha256')}")
