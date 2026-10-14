from __future__ import annotations

from collections import Counter
import base64
from html import escape
from pathlib import Path
import csv
import io
import json

from osint.storage import OSINTRepository
from osint.text_cleanup import clean_evidence_text, evidence_scope, social_screenshot_context
from osint.coverage import DIAGNOSTIC_ENTITY_TYPES
from osint.report_presentation import observed_identity, report_overview
from osint.report_branding import LEFT_LOGO, RIGHT_LOGO
from core.time_utils import format_ist


class OSINTReportBuilder:
    """Build a self-contained, source-traceable HTML report from stored OSINT data."""

    def __init__(self, repository: OSINTRepository):
        self.repository = repository

    def build_html(self, investigation_id: str) -> str:
        investigation = self.repository.get_investigation(investigation_id)
        coverage = investigation["coverage"]
        diagnostics = self.repository.get_collection_diagnostics(investigation_id)
        observations = self.repository.get_observations(investigation_id)
        candidates = self.repository.get_candidates(investigation_id)
        candidate_leads = self.repository.get_candidate_leads(investigation_id)
        identities = self.repository.get_search_identities(investigation_id)
        social_findings = self.repository.get_social_findings(investigation_id)
        sources = self.repository.get_sources(investigation_id)
        documents = self.repository.get_documents(investigation_id)
        queries = self.repository.get_queries(investigation_id)
        query_metrics = self.repository.get_query_metrics(investigation_id)
        collector_runs = self.repository.get_collector_runs(investigation_id)
        risks = self.repository.get_risk_indicators(investigation_id)
        notes = self.repository.get_analyst_notes(investigation_id)
        evidence = self.repository.get_evidence(investigation_id)
        page_captures = self.repository.get_page_captures(investigation_id)
        screenshot_summaries = {item.get("screenshot_path"): item for item in self.repository.get_screenshot_summaries(investigation_id)}
        summary = self.repository.get_summary_counts(investigation_id)
        automated_platforms = {item["platform"] for item in social_findings}
        manual_links = [
            item for item in observations
            if item.get("entity_type") == "MANUAL_REVIEW_LINK"
            and item.get("value") not in automated_platforms
        ]
        report_observations = [
            item for item in observations
            if item.get("entity_type") not in {"LLM_RELEVANCE_REVIEW", "SEARCH_RESULT", "SEARCH_RESULT_REJECTED", "SEARCH_PROVIDER_MANUAL_REQUIRED", "SEARCH_PROVIDER_ERROR", "ACCESS_STATUS", "CANDIDATE_DOMAIN", "AUTOMATED_SOCIAL_FINDING"}
            and item.get("entity_type") not in DIAGNOSTIC_ENTITY_TYPES
            and not (
                item.get("entity_type") in {"SEARCH_SNIPPET_EVIDENCE", "PUBLIC_PAGE_EVIDENCE"}
                and item.get("target_keyword_distance") is None
            )
            and not (
                item.get("entity_type") == "PUBLIC_PAGE_METADATA"
                and item.get("relevance_status") != "accepted"
            )
        ]
        category_counts = Counter(item["category"] for item in report_observations)
        no_evidence_message = (
            "<p><strong>No confirmed target-specific public evidence found.</strong></p>"
            if not summary["confirmed_evidence"] and not summary["public_documents"]
            else ""
        )
        overview = report_overview(investigation, summary)
        overview_html = "".join(
            f'<div class="overview-item"><h3>{escape(label)}</h3><p>{escape(value)}</p></div>'
            for label, value in overview
        )
        identity_html = "".join(
            f"<tr><th>{escape(label)}</th><td>{escape(value)}</td></tr>"
            for label, value in observed_identity(diagnostics["target_profile"])
        )
        def brand_mark(path: Path, fallback: str) -> str:
            if path.is_file():
                encoded = base64.b64encode(path.read_bytes()).decode("ascii")
                return f'<img class="brand-logo" src="data:image/png;base64,{encoded}" alt="{escape(fallback, quote=True)}">'
            return escape(fallback).replace("\n", "<br>")

        left_mark = brand_mark(LEFT_LOGO, "MINISTRY OF ELECTRONICS\nAND INFORMATION TECHNOLOGY")
        right_mark = brand_mark(RIGHT_LOGO, "सी-डैक\nC-DAC")

        def rows(items: list[dict], columns: list[str]) -> str:
            if not items:
                return f'<tr><td colspan="{len(columns)}">No records</td></tr>'
            return "".join(
                "<tr>" + "".join(
                    f"<td>{escape(str(format_ist(item.get(column), fallback='') if column.endswith(('_at', '_date')) else item.get(column) or ''))}</td>"
                    for column in columns
                ) + "</tr>"
                for item in items
            )

        def table(items: list[dict], columns: list[str]) -> str:
            headers = "".join(f"<th>{escape(column.replace('_', ' ').title())}</th>" for column in columns)
            return f"<table><thead><tr>{headers}</tr></thead><tbody>{rows(items, columns)}</tbody></table>"

        def visit(value: object) -> str:
            return "Unavailable" if value is None else self.format_visits(int(value))

        domain_rows = [{
            "domain": item["domain"], "confidence": f"{float(item['confidence']):.0%}", "appearances": item["appearances"],
            "status": item.get("domain_status", "Unknown"), "http": item.get("http_status", "Unavailable"),
            "final_url": item.get("final_url") or "", "monthly_visits": visit(item.get("monthly_visits")),
            "yearly_visits": (visit(item.get("yearly_visits")) + (" (Projected)" if item.get("yearly_visits_kind") == "Projected" else "")),
            "traffic_source": item.get("traffic_source") or "Unavailable", "checked_at": format_ist(item.get("checked_at"), fallback=""),
            "yearly_basis": "12-month estimate" if item.get("yearly_visits_kind") == "Actual" else item.get("yearly_visits_kind", "Unavailable"),
            "traffic_month": item.get("traffic_data_date") or "", "traffic_status": item.get("traffic_status") or "not_checked",
            "traffic_detail": item.get("traffic_error") or "", "traffic_checked": format_ist(item.get("traffic_refreshed_at"), fallback=""),
            "resolution_reason": item.get("reason") or "",
        } for item in candidates]
        traffic_notes_html = "".join(
            f"<li><strong>{escape(str(item['domain']))}:</strong> data month {escape(str(item['traffic_month'] or 'Unavailable'))}; "
            f"yearly basis {escape(str(item['yearly_basis']))}; source {escape(str(item['traffic_source']))}. "
            f"{escape(str(item['traffic_detail']))}</li>"
            for item in domain_rows
        )

        def evidence_cards(items: list[dict]) -> str:
            if not items:
                return "<p>No highlighted evidence screenshots were captured.</p>"
            cards = []
            for item in items:
                screenshot = Path(item["screenshot_path"])
                image_html = "<em>Screenshot file unavailable</em>"
                if screenshot.is_file():
                    encoded = base64.b64encode(screenshot.read_bytes()).decode("ascii")
                    image_html = f'<img src="data:image/png;base64,{encoded}" alt="Highlighted evidence screenshot">'
                keywords = ", ".join(item.get("matched_keywords") or [])
                scope = evidence_scope(
                    item["source_url"], item.get("final_url") or item["source_url"],
                    investigation.get("target_domain") or "",
                )
                cards.append(
                    '<section class="evidence">'
                    f"<h3>{escape(scope)}</h3>"
                    f"<p><b>Discovery query:</b> {escape(str(item.get('query_name') or item['query_id']))}<br>"
                    f"<b>Search provider/rank:</b> {escape(str(item.get('search_engine') or ''))} / {escape(str(item.get('serp_rank') or ''))}<br>"
                    f"<b>Source:</b> <a href=\"{escape(str(item['source_url']), quote=True)}\">{escape(str(item['source_url']))}</a><br>"
                    f"<b>Matched keywords:</b> {escape(keywords)}<br>"
                    f"<b>Evidence:</b> {escape(clean_evidence_text(item.get('context_text') or item.get('evidence_text')))}</p>"
                    f"<p><b>AI visual summary (advisory):</b> {escape(str(screenshot_summaries.get(item['screenshot_path'], {}).get('summary') or 'Not generated'))}</p>"
                    f"{image_html}<p><small>SHA-256: {escape(str(item.get('sha256') or ''))}</small></p></section>"
                )
            return "".join(cards)

        def document_capture_cards(items: list[dict]) -> str:
            cards = []
            for item in items:
                for capture in item.get("page_screenshots", []):
                    screenshot = Path(capture.get("path", ""))
                    if not screenshot.is_file():
                        continue
                    encoded = base64.b64encode(screenshot.read_bytes()).decode("ascii")
                    cards.append(
                        '<section class="evidence">'
                        f"<h3>{escape(str(item.get('document_type') or 'Public document'))} — page {int(capture.get('page') or 0)}</h3>"
                        f"<p><b>AI visual summary (advisory):</b> {escape(str(screenshot_summaries.get(capture.get('path'), {}).get('summary') or 'Not generated'))}</p>"
                        f'<img src="data:image/png;base64,{encoded}" alt="Relevant public document page">'
                        f"<p><small>SHA-256: {escape(str(capture.get('sha256') or ''))}</small></p></section>"
                    )
            return "".join(cards) or "<p>No document page screenshots were captured.</p>"

        def social_capture_cards(items: list[dict]) -> str:
            grouped: dict[str, list[dict]] = {}
            for item in items:
                for screenshot_path in item.get("screenshot_paths") or []:
                    grouped.setdefault(screenshot_path, []).append(item)
            cards = []
            for screenshot_path, findings in grouped.items():
                screenshot = Path(screenshot_path)
                if not screenshot.is_file():
                    continue
                encoded = base64.b64encode(screenshot.read_bytes()).decode("ascii")
                posts = "".join(
                    f'<p><a href="{escape(str(item.get("post_url") or ""), quote=True)}">Open post</a><br>'
                    f'Screenshot scope: {escape(social_screenshot_context(item, screenshot_path)["scope"])}<br>'
                    f'{escape(clean_evidence_text(social_screenshot_context(item, screenshot_path)["text"], limit=2_000))}</p>'
                    for item in findings
                )
                cards.append(
                    '<section class="evidence">'
                    f'<h3>{escape(str(findings[0].get("platform") or "Platform"))} capture</h3>'
                    f'<p><b>AI visual summary (advisory):</b> {escape(str(screenshot_summaries.get(screenshot_path, {}).get("summary") or "Not generated"))}</p>'
                    f'{posts}<img src="data:image/png;base64,{encoded}" alt="Authenticated social-media screenshot">'
                    '</section>'
                )
            return "".join(cards) or "<p>No authenticated social-media screenshots were captured.</p>"

        return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>OSINT report {escape(investigation_id)}</title>
<style>
@page{{size:A4;margin:18mm 16mm 18mm}}
*{{box-sizing:border-box}}body{{font-family:Arial,sans-serif;margin:0;color:#17202a;font-size:10pt;line-height:1.45}}
h1,h2{{color:#152c40}}h2{{font-size:15pt;margin-top:28px;border-bottom:1px solid #cbd5e1;padding-bottom:5px}}
h3{{font-size:11pt;margin:0}}p{{margin:8px 0 12px}}.cover{{height:257mm;display:flex;flex-direction:column;text-align:center;break-after:page}}
.cover-head{{display:flex;align-items:flex-start;justify-content:space-between;text-align:left;min-height:25mm}}
.cover-brand{{font-weight:bold;font-size:11pt;line-height:1.15}}.cover-brand.right{{text-align:right;color:#3b0764;font-size:19pt}}
.brand-logo{{display:block;max-width:80mm;max-height:25mm;object-fit:contain}}.cover-brand.right .brand-logo{{max-width:25mm;margin-left:auto}}
.confidential{{font:italic 12pt Georgia,serif;margin-top:12mm}}.cover-title{{margin:auto 0}}
.cover-title h1{{font: bold 20pt Georgia,serif;text-decoration:underline;color:#111}}
.cover-title p{{font: bold 13pt Georgia,serif}}.cover-foot{{font-size:9pt;border-top:1px solid #cbd5e1;padding-top:8px}}
.overview{{display:grid;grid-template-columns:1fr 1fr;gap:10px}}.overview-item{{border:1px solid #cbd5e1;padding:11px;break-inside:avoid}}
.overview-item p{{margin-bottom:0}}table{{border-collapse:collapse;width:100%;margin:12px 0 24px;table-layout:fixed;font-size:8pt;overflow-wrap:anywhere}}
th,td{{border:1px solid #ccd6dd;padding:6px;text-align:left;vertical-align:top}}th{{background:#eef4f7}}
thead{{display:table-header-group}}tr{{break-inside:avoid}}.summary{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}}
.card{{border:1px solid #ccd6dd;padding:10px;overflow-wrap:anywhere}}small{{color:#586069}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;font-size:8pt}}
.evidence{{border:1px solid #ccd6dd;padding:12px;margin:14px 0;break-inside:avoid}}.evidence img{{max-width:100%;height:auto;border:1px solid #8996a0}}
@media screen{{body{{max-width:210mm;margin:0 auto;padding:16px;background:white}}.cover{{height:257mm}}}}
</style></head><body>
<section class="cover">
<div class="cover-head"><div class="cover-brand">{left_mark}</div><div class="cover-brand right">{right_mark}</div></div>
<div class="confidential">Confidential</div>
<div class="cover-title"><h1>TECHNICAL ASSESSMENT REPORT</h1><p>for the</p><p>{escape(str(investigation.get('resolved_brand') or investigation.get('target_domain') or 'Target'))} — Web investigation</p><p>Report ID: {escape(investigation_id)}</p></div>
<div class="cover-foot">{escape(investigation_id)} · Generated from stored investigation evidence</div>
</section>
<h1>Web intelligence and OSINT report</h1>
<small>Investigation {escape(investigation_id)}</small>
<h2>Executive summary</h2><div class="overview">{overview_html}</div>
<p><strong>Overall collection status:</strong> {escape(str(coverage.get('status') or 'Unknown'))}. {escape(str(coverage.get('message') or ''))}</p>
<p><strong>Risk score:</strong> {int(investigation.get('risk_score') or 0)}/100. A low score means few indicators were collected; it is not a safety rating.</p>
<p><strong>Reading guide:</strong> The sections below show the target identity, evidence, sources, collection gaps, and technical search details. "No records" means no item was stored for that section.</p>
<h2>1. Input and target resolution</h2>
<div class="summary">
<div class="card"><b>Original input</b><br>{escape(str(investigation.get('original_input') or ''))}</div>
<div class="card"><b>Resolved domain</b><br>{escape(str(investigation.get('target_domain') or ''))}</div>
<div class="card"><b>Resolved brand</b><br>{escape(str(investigation.get('resolved_brand') or ''))}</div>
<div class="card"><b>Resolution confidence</b><br>{float(investigation.get('resolution_confidence') or 0):.0%}</div>
<div class="card"><b>Risk score</b><br>{int(investigation.get('risk_score') or 0)}/100</div>
<div class="card"><b>Status</b><br>{escape(str(investigation.get('status') or ''))}</div>
</div>
<p><strong>Collection coverage: {escape(coverage['status'])}</strong> — {escape(coverage['message'])}</p>
<p>{escape(coverage['risk_notice'])}</p>
<h2>Worker readiness</h2>{table(diagnostics['readiness'].get('checks', []), ['component', 'status', 'reason'])}
<h2>Observed target identity</h2><p>Names and accounts below were observed in collected sources. They do not establish ownership.</p><table><tbody>{identity_html}</tbody></table>
<h2>Social extraction coverage</h2>{table(diagnostics['social_collection'], ['platform', 'search_status', 'result_cards_seen', 'matched_findings', 'extraction_errors', 'detailed_captures', 'unavailable', 'budget_skipped'])}
<h2>Resolved / related domains</h2><p><small>Worldwide estimated visits, not site analytics. Yearly is a 12-month estimate or a projection of the latest month × 12. Missing values are unavailable, not zero.</small></p>{table(domain_rows, ['domain', 'status', 'http', 'monthly_visits', 'yearly_visits', 'traffic_status'])}<h3>Traffic estimate details</h3><ul>{traffic_notes_html or '<li>No domain estimates stored.</li>'}</ul>
<h2>Certificate Transparency leads — not evidence</h2>{table(candidate_leads, ['domain', 'source_url', 'confidence', 'metadata_json', 'discovered_at'])}
<h2>Search identities</h2>{table(identities, ['value', 'identity_type', 'confidence', 'reason'])}
<h2>2. Search summary</h2>
<p>{summary['configured_queries']} configured queries · {summary['raw_search_results']} raw results ·
{summary['accepted_sources']} accepted sources · {summary['rejected_irrelevant']} rejected irrelevant ·
{summary['pages_visited']} pages visited · {summary['confirmed_evidence']} confirmed evidence findings ·
{summary['public_documents']} public documents · {summary['screenshots_captured']} screenshots ·
{summary['manual_required']} manual required · {summary['failures']} failures</p>
{no_evidence_message}
{table([{'category': key, 'findings': value} for key, value in sorted(category_counts.items())], ['category', 'findings'])}
<h2>3. Findings and evidence snippets</h2>
{table(report_observations, ['category', 'entity_type', 'value', 'evidence_snippet', 'source_url'])}
<h2>4. Source URLs</h2>{table(sources, ['source_type', 'title', 'source_url', 'first_seen_at'])}
<h2>5. Evidence screenshots</h2>{evidence_cards(evidence)}
<h2>Page capture status</h2>{table(page_captures, ['source_type', 'source_url', 'http_status', 'accessibility_status', 'failure_reason', 'captured_at'])}
<h2>AI relevance review — advisory, not verified evidence</h2>
<p>Text-only review. Original evidence is retained; these decisions do not establish ownership or prove allegations.</p>
{table(self.repository.get_llm_reviews(investigation_id), ['source_url', 'stage', 'relevance', 'relationship', 'reason', 'review_status', 'model', 'prompt_version', 'reviewed_at'])}
<h2>Collector status</h2>{table(collector_runs, ['collector', 'status', 'observation_count', 'error'])}
<h2>Automated social and review findings</h2>{table(social_findings, ['platform', 'title', 'post_text', 'capture_status', 'post_url'])}
<h2>Social and review screenshots</h2>{social_capture_cards(social_findings)}
<h2>Manual social/review links</h2>{table(manual_links, ['query_id', 'value', 'source_url', 'metadata_json', 'discovered_at'])}
<h2>Public documents</h2>{table(documents, ['document_type', 'source_url', 'relevant_pages', 'evidence_context'])}
<h2>Public document page captures</h2>{document_capture_cards(documents)}
<h2>6. Search execution</h2>{table(
    [item for item in query_metrics if item.get('provider')],
    ['query_id', 'name', 'provider', 'raw_results', 'accepted_results', 'failed']
)}
<h2>7. Explainable risk indicators</h2>{table(risks, ['category', 'indicator', 'value', 'points', 'confidence', 'source_url'])}
<h2>8. Analyst notes</h2>{table(notes, ['created_at', 'note'])}
</body></html>"""

    @staticmethod
    def format_visits(value: int) -> str:
        for threshold, suffix in ((1_000_000_000, "B"), (1_000_000, "M"), (1_000, "K")):
            if value >= threshold:
                return f"{value / threshold:.1f}".rstrip("0").rstrip(".") + suffix
        return str(value)

    def build_json(self, investigation_id: str) -> str:
        return json.dumps(self.build_payload(investigation_id), indent=2, default=str)

    def build_payload(self, investigation_id: str) -> dict:
        """Canonical stored report data shared by downloadable representations."""
        return {
            "schema_version": "1.0",
            "investigation": self.repository.get_investigation(investigation_id),
            "summary": self.repository.get_summary_counts(investigation_id),
            "domains": self.repository.get_candidates(investigation_id),
            "observations": self.repository.get_observations(investigation_id),
            "findings": self.repository.get_social_findings(investigation_id),
            "evidence": self.repository.get_evidence(investigation_id),
            "page_captures": self.repository.get_page_captures(investigation_id),
            "screenshot_summaries": self.repository.get_screenshot_summaries(investigation_id),
            "queries": self.repository.get_queries(investigation_id),
            "query_metrics": self.repository.get_query_metrics(investigation_id),
            "sources": self.repository.get_sources(investigation_id),
            "documents": self.repository.get_documents(investigation_id),
            "collector_runs": self.repository.get_collector_runs(investigation_id),
            "risk_indicators": self.repository.get_risk_indicators(investigation_id),
            "analyst_notes": self.repository.get_analyst_notes(investigation_id),
            "ai_reviews": self.repository.get_llm_reviews(investigation_id),
            "collection_diagnostics": self.repository.get_collection_diagnostics(investigation_id),
        }

    def build_domain_csv(self, investigation_id: str) -> str:
        rows = self.build_payload(investigation_id)["domains"]
        output = io.StringIO()
        fields = ["domain", "confidence", "appearances", "domain_status", "detailed_status", "http_status", "final_url", "monthly_visits", "yearly_visits", "yearly_visits_kind", "traffic_source", "traffic_data_date", "traffic_status", "traffic_error", "traffic_refreshed_at", "checked_at", "reason"]
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader(); writer.writerows(rows)
        return output.getvalue()
