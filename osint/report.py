from __future__ import annotations

from collections import Counter
import base64
from html import escape
from pathlib import Path
import csv
import io
import json

from osint.storage import OSINTRepository
from osint.text_cleanup import clean_evidence_text, evidence_scope


class OSINTReportBuilder:
    """Build a self-contained, source-traceable HTML report from stored OSINT data."""

    def __init__(self, repository: OSINTRepository):
        self.repository = repository

    def build_html(self, investigation_id: str) -> str:
        investigation = self.repository.get_investigation(investigation_id)
        observations = self.repository.get_observations(investigation_id)
        candidates = self.repository.get_candidates(investigation_id)
        candidate_leads = self.repository.get_candidate_leads(investigation_id)
        identities = self.repository.get_search_identities(investigation_id)
        sources = self.repository.get_sources(investigation_id)
        documents = self.repository.get_documents(investigation_id)
        queries = self.repository.get_queries(investigation_id)
        query_metrics = self.repository.get_query_metrics(investigation_id)
        collector_runs = self.repository.get_collector_runs(investigation_id)
        risks = self.repository.get_risk_indicators(investigation_id)
        notes = self.repository.get_analyst_notes(investigation_id)
        evidence = self.repository.get_evidence(investigation_id)
        page_captures = self.repository.get_page_captures(investigation_id)
        rejected_search = self.repository.get_rejected_search_results(investigation_id)
        summary = self.repository.get_summary_counts(investigation_id)
        manual_links = [item for item in observations if item.get("entity_type") == "MANUAL_REVIEW_LINK"]
        report_observations = [
            item for item in observations
            if item.get("entity_type") not in {"SEARCH_RESULT", "SEARCH_RESULT_REJECTED", "SEARCH_PROVIDER_MANUAL_REQUIRED", "ACCESS_STATUS", "CANDIDATE_DOMAIN"}
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

        def rows(items: list[dict], columns: list[str]) -> str:
            if not items:
                return '<tr><td colspan="99">No records</td></tr>'
            return "".join(
                "<tr>" + "".join(f"<td>{escape(str(item.get(column) or ''))}</td>" for column in columns) + "</tr>"
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
            "traffic_source": item.get("traffic_source") or "Unavailable", "checked_at": item.get("checked_at") or "",
            "resolution_reason": item.get("reason") or "",
        } for item in candidates]

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
                        f"<p>{escape(clean_evidence_text(item.get('evidence_context'), limit=12_000))}</p>"
                        f'<img src="data:image/png;base64,{encoded}" alt="Relevant public document page">'
                        f"<p><small>SHA-256: {escape(str(capture.get('sha256') or ''))}</small></p></section>"
                    )
            return "".join(cards) or "<p>No document page screenshots were captured.</p>"

        return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>OSINT report {escape(investigation_id)}</title>
<style>
body{{font-family:Arial,sans-serif;margin:32px;color:#17202a}} h1,h2{{color:#123b5d}}
table{{border-collapse:collapse;width:100%;margin:12px 0 28px}} th,td{{border:1px solid #ccd6dd;padding:7px;text-align:left;vertical-align:top}}
th{{background:#eef4f7}} .summary{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}}
.card{{border:1px solid #ccd6dd;border-radius:8px;padding:12px}} small{{color:#586069}}
.evidence{{border:1px solid #ccd6dd;border-radius:8px;padding:14px;margin:14px 0;break-inside:avoid}}
.evidence img{{max-width:100%;height:auto;border:1px solid #8996a0}}
</style></head><body>
<h1>Web intelligence and OSINT report</h1>
<small>Investigation {escape(investigation_id)}</small>
<h2>1. Input and target resolution</h2>
<div class="summary">
<div class="card"><b>Original input</b><br>{escape(str(investigation.get('original_input') or ''))}</div>
<div class="card"><b>Resolved domain</b><br>{escape(str(investigation.get('target_domain') or ''))}</div>
<div class="card"><b>Resolved brand</b><br>{escape(str(investigation.get('resolved_brand') or ''))}</div>
<div class="card"><b>Resolution confidence</b><br>{float(investigation.get('resolution_confidence') or 0):.0%}</div>
<div class="card"><b>Risk score</b><br>{int(investigation.get('risk_score') or 0)}/100</div>
<div class="card"><b>Status</b><br>{escape(str(investigation.get('status') or ''))}</div>
</div>
<h2>Resolved / related domains</h2><p><small>Monthly and yearly visits are third-party estimates, not site analytics.</small></p>{table(domain_rows, ['domain', 'confidence', 'appearances', 'status', 'http', 'final_url', 'monthly_visits', 'yearly_visits', 'traffic_source', 'checked_at', 'resolution_reason'])}
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
{table(report_observations, ['category', 'entity_type', 'value', 'confidence', 'query_id', 'search_rank', 'evidence_snippet', 'source_url', 'discovered_at'])}
<h2>4. Source URLs</h2>{table(sources, ['source_type', 'title', 'source_url', 'discovered_by_queries', 'best_rank', 'first_seen_at'])}
<h2>5. Evidence screenshots</h2>{evidence_cards(evidence)}
<h2>Page capture status</h2>{table(page_captures, ['source_type', 'source_url', 'http_status', 'accessibility_status', 'failure_reason', 'captured_at'])}
<h2>Collector status</h2>{table(collector_runs, ['collector', 'status', 'duration_seconds', 'observation_count', 'error'])}
<h2>Rejected search noise (diagnostics)</h2>{table(rejected_search, ['query_id', 'provider', 'search_rank', 'title', 'source_url', 'relevance_reason', 'discovered_at'])}
<h2>Manual social/review links</h2>{table(manual_links, ['query_id', 'value', 'source_url', 'metadata_json', 'discovered_at'])}
<h2>Public documents</h2>{table(documents, ['document_type', 'source_url', 'final_url', 'matched_target_variant', 'matched_keywords', 'relevant_pages', 'evidence_context', 'sha256', 'size_bytes', 'discovered_at'])}
<h2>Public document page captures</h2>{document_capture_cards(documents)}
<h2>6. Search execution</h2>{table(
    [item for item in query_metrics if item.get('provider')],
    ['query_id', 'category', 'name', 'query', 'provider', 'raw_results', 'accepted_results', 'rejected_results', 'pages_visited', 'evidence_matches', 'screenshots', 'manual_required', 'failed']
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
        return json.dumps({
            "investigation": self.repository.get_investigation(investigation_id),
            "domains": self.repository.get_candidates(investigation_id),
        }, indent=2, default=str)

    def build_domain_csv(self, investigation_id: str) -> str:
        rows = self.repository.get_candidates(investigation_id)
        output = io.StringIO()
        fields = ["domain", "confidence", "appearances", "domain_status", "detailed_status", "http_status", "final_url", "monthly_visits", "yearly_visits", "yearly_visits_kind", "traffic_source", "traffic_data_date", "checked_at", "reason"]
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader(); writer.writerows(rows)
        return output.getvalue()
