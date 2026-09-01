from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import re
from urllib.parse import urlsplit

import pandas as pd
import streamlit as st

from osint.collectors import BraveSearchCollector
from osint.collectors.x_authenticated import configured_x_session_path
from osint.collectors.authenticated_social import (
    AUTHENTICATED_SOCIAL_COLLECTORS,
    configured_social_session_path,
)
from osint.models import TargetResolution
from osint.orchestrator import IntelligenceOrchestrator
from osint.resolver import ResolutionProviderUnavailable, TargetResolver
from osint.report import OSINTReportBuilder
from osint.docx_report import OSINTDocxReportBuilder
from osint.search import BraveSearchProvider, GoogleSearchProvider, build_keyless_search_provider
from osint.storage import OSINTRepository
from osint.domain_intelligence import DomainIntelligenceService, http_status_meaning
from ui.api_client import APIClientError
from ui.job_status import get_api_client, render_osint_job_status


BRAND_SCOPED_COLLECTORS = frozenset({
    "X/Twitter authenticated search",
    "Instagram authenticated search",
    "Facebook authenticated search",
    "Telegram authenticated search",
    "YouTube authenticated search",
    "Quora authenticated search",
    "Trustpilot public reviews",
})


def collectors_for_domain(
    selected_collectors: list[str],
    domain_index: int,
) -> list[str]:
    """Run brand-wide browser collectors once, on the primary resolved domain."""
    if domain_index == 0:
        return list(selected_collectors)
    return [
        collector
        for collector in selected_collectors
        if collector not in BRAND_SCOPED_COLLECTORS
    ]


def report_file_prefix(investigation: dict) -> str:
    """Return a filesystem-safe, human-readable prefix for exported reports."""
    values = [
        investigation.get("resolved_brand") or investigation.get("original_input"),
        investigation.get("target_domain"),
    ]
    parts: list[str] = []
    for value in values:
        part = re.sub(r"[^a-zA-Z0-9.-]+", "-", str(value or "").strip()).strip("-.")
        if part and part.casefold() not in {item.casefold() for item in parts}:
            parts.append(part)
    suffix = "_".join(parts) or "target"
    return f"{investigation['id']}_{suffix}"


def render_osint_workspace() -> None:
    repository = OSINTRepository()
    resolver = TargetResolver()
    google_provider = GoogleSearchProvider()
    brave_provider = BraveSearchProvider()
    google_api_available = bool(google_provider.api_key and google_provider.cse_id)
    search_provider = build_keyless_search_provider()

    st.title(":material/travel_explore: Web intelligence and OSINT")
    st.caption(
        "Collect passive public intelligence with evidence provenance. "
        "Only investigate domains you are authorized to assess."
    )
    if notice := st.session_state.pop("osint_notice", None):
        st.success(notice)
    if error := st.session_state.pop("osint_error", None):
        st.error(error)
    st.session_state.setdefault("osint_job_ids", [])
    render_osint_job_status()

    history = repository.list_investigations()
    history_options = {f"{item['target_domain']} · {item['started_at']}": item["id"] for item in history}
    selected_id = st.session_state.get("osint_current_investigation")

    with st.form("osint_resolution_form", border=True):
        target_input = st.text_input(
            "Analyze URL, domain, partial name, or application/brand name",
            placeholder="Parimatch, parimatch123, example.com, or https://example.com",
            key="osint_target",
        )
        acknowledged = st.checkbox(
            "I am authorized to collect public intelligence about this target.",
            key="osint_authorized",
        )
        resolve_clicked = st.form_submit_button(
            ":material/search: Resolve target",
            type="primary",
            width="stretch",
        )

    if resolve_clicked:
        if not acknowledged:
            st.error("Confirm authorization before resolving and collecting intelligence.")
        else:
            try:
                with st.spinner("Classifying input and resolving candidate domains…"):
                    st.session_state.pop("osint_selected_domains", None)
                    st.session_state.osint_resolution = resolver.resolve(target_input, search_provider)
            except (ValueError, ResolutionProviderUnavailable) as exc:
                st.error(str(exc))

    resolution: TargetResolution | None = st.session_state.get("osint_resolution")
    if resolution:
        st.subheader("Target resolution")
        summary_columns = st.columns(3)
        summary_columns[0].metric("Input type", resolution.input_type.replace("_", " ").title(), border=True)
        summary_columns[1].metric("Resolved brand", resolution.resolved_brand, border=True)
        summary_columns[2].metric("Domains discovered", len(resolution.candidates), border=True)

        if not resolution.candidates:
            st.warning("No candidate domains were found. Refine the input or configure another search provider.")
        else:
            st.caption(
                "All distinct brand-related domains found by the configured public search providers are shown. "
                "They are candidates, not proof of official ownership, and unindexed/private domains cannot be discovered by public search."
            )
            candidate_rows = [
                {
                    "domain": candidate.domain,
                    "confidence": candidate.confidence,
                    "appearances": candidate.appearances,
                    "resolution_reason": candidate.reason,
                }
                for candidate in resolution.candidates
            ]
            st.dataframe(
                pd.DataFrame(candidate_rows),
                hide_index=True,
                column_config={
                    "confidence": st.column_config.ProgressColumn("Resolution confidence", min_value=0.0, max_value=1.0, format="percent"),
                },
            )
            discovered_domains = [candidate.domain for candidate in resolution.candidates]
            recommended_domains = [
                candidate.domain
                for candidate in resolution.candidates
                if candidate.confidence >= 0.70
            ] or discovered_domains[:1]
            selected_domains = st.multiselect(
                "Domains to analyze",
                discovered_domains,
                default=recommended_domains,
                help=(
                    "Only candidates with at least 70% resolution confidence are selected automatically. "
                    "Lower-confidence related domains remain available for deliberate manual selection."
                ),
                key="osint_selected_domains",
            )
            default_search_collector = (
                "Google public search" if google_api_available else "Keyless Web Search (no API key)"
            )
            discovery_depth = st.selectbox(
                "Discovery depth",
                ["Fast", "Balanced", "Deep"],
                index=0,
                help=(
                    "Fast runs the 12 highest-priority queries per domain. Balanced runs 25. "
                    "Deep runs every configured query and can take substantially longer."
                ),
                key="osint_discovery_depth",
            )
            query_budget = {"Fast": 12, "Balanced": 25, "Deep": 100}[discovery_depth]
            x_session_ready = configured_x_session_path().is_file()
            default_collectors = [
                "DNS", "RDAP", "Public website", "Certificate Transparency (crt.sh)",
                "Wayback historical URLs", default_search_collector,
            ]
            if x_session_ready:
                default_collectors.append("X/Twitter authenticated search")
            social_session_ready = {
                label: configured_social_session_path(collector.platform_key).is_file()
                for label, collector in AUTHENTICATED_SOCIAL_COLLECTORS.items()
            }
            default_collectors.extend(
                label for label, ready in social_session_ready.items() if ready
            )
            default_collectors.append("Trustpilot public reviews")
            collectors = st.multiselect(
                "Evidence collectors",
                list(IntelligenceOrchestrator.COLLECTORS),
                default=default_collectors,
                help="Free discovery uses crt.sh, Wayback, and keyless search. Google is optional and not selected by default.",
                key="osint_collectors",
            )
            if len(selected_domains) > 1 and BRAND_SCOPED_COLLECTORS.intersection(collectors):
                st.caption(
                    "Authenticated social and Trustpilot searches run once for the primary domain. "
                    "Related-domain jobs reuse the brand scope and run only domain-specific collectors."
                )
            if "X/Twitter authenticated search" in collectors and not x_session_ready:
                st.warning(
                    "X authenticated search needs a local browser session. Run "
                    "`python -m scripts.setup_x_session` on the host, complete login/OTP, then restart the workers."
                )
            elif x_session_ready:
                st.success("X authenticated browser session is configured.")
            for label, collector in AUTHENTICATED_SOCIAL_COLLECTORS.items():
                platform = collector.platform_key.capitalize()
                if label in collectors and not social_session_ready[label]:
                    st.warning(
                        f"{platform} authenticated search needs a local browser session. Run "
                        f"`python -m scripts.setup_{collector.platform_key}_session` on the host, "
                        "complete login/OTP, then restart the workers."
                    )
                elif social_session_ready[label]:
                    st.success(f"{platform} authenticated browser session is configured.")
            if "Brave Search" in collectors and not BraveSearchCollector().available:
                st.info("Brave Search is unavailable until `BRAVE_SEARCH_API_KEY` is configured.")
            if "Google public search" in collectors and not (google_provider.api_key and google_provider.cse_id):
                st.warning(
                    "Google API credentials are not configured. Public HTML search will be attempted, "
                    "but Google may return a consent/challenge page. For reliable results, set "
                    "`GOOGLE_SEARCH_API_KEY` and `GOOGLE_SEARCH_CSE_ID`."
                )
            if st.button(
                ":material/play_arrow: Start evidence discovery",
                type="primary",
                width="stretch",
                disabled=not selected_domains or not collectors or bool(st.session_state.osint_job_ids),
            ):
                try:
                    jobs = []
                    progress = st.progress(0, text="Starting evidence discovery…")
                    for index, domain in enumerate(selected_domains):
                        progress.progress(
                            index / len(selected_domains),
                            text=f"Collecting public evidence for {domain}…",
                        )
                        jobs.append(
                            get_api_client().submit_osint(
                                domain,
                                collectors_for_domain(list(collectors), index),
                                brand=resolution.resolved_brand,
                                resolution=asdict(resolution),
                                query_budget=query_budget,
                                authorized=acknowledged,
                            )
                        )
                    progress.progress(1.0, text="Evidence jobs queued")
                    st.session_state.osint_job_ids = [job["id"] for job in jobs]
                    st.session_state.osint_notice = f"Queued {len(jobs)} evidence investigation(s)."
                    st.session_state.pop("osint_resolution", None)
                    st.rerun()
                except (APIClientError, ValueError) as exc:
                    st.error(str(exc))

    if history_options:
        labels = list(history_options)
        current_index = 0
        if selected_id in history_options.values():
            current_index = list(history_options.values()).index(selected_id)
        selected_label = st.selectbox("Previous OSINT investigations", labels, index=current_index)
        selected_id = history_options[selected_label]
        st.session_state.osint_current_investigation = selected_id

    if selected_id:
        render_osint_dashboard(repository, selected_id)


def render_osint_dashboard(repository: OSINTRepository, investigation_id: str) -> None:
    investigation = repository.get_investigation(investigation_id)
    if not investigation:
        return

    st.divider()
    st.subheader(f"Intelligence report · {investigation['target_domain']}")
    metric_columns = st.columns(4)
    metric_columns[0].metric("Risk score", f"{investigation['risk_score']}/100", border=True)
    metric_columns[1].metric("Risk level", investigation["risk_level"], border=True)

    observations = repository.get_observations(investigation_id)
    findings = [
        item for item in observations
        if item.get("entity_type") not in {"SEARCH_RESULT", "SEARCH_RESULT_REJECTED", "SEARCH_PROVIDER_MANUAL_REQUIRED", "SEARCH_PROVIDER_ERROR", "ACCESS_STATUS", "CANDIDATE_DOMAIN", "AUTOMATED_SOCIAL_FINDING"}
        and not (
            item.get("entity_type") in {"SEARCH_SNIPPET_EVIDENCE", "PUBLIC_PAGE_EVIDENCE"}
            and item.get("target_keyword_distance") is None
        )
        and not (
            item.get("entity_type") == "PUBLIC_PAGE_METADATA"
            and item.get("relevance_status") != "accepted"
        )
    ]
    collector_runs = repository.get_collector_runs(investigation_id)
    x_session_ready = configured_x_session_path().is_file()
    x_collector_run = next(
        (item for item in collector_runs if item["collector"] == "x_authenticated_playwright"),
        None,
    )
    queries = repository.get_queries(investigation_id)
    candidates = repository.get_candidates(investigation_id)
    candidate_leads = repository.get_candidate_leads(investigation_id)
    identities = repository.get_search_identities(investigation_id)
    social_findings = repository.get_social_findings(investigation_id)
    sources = repository.get_sources(investigation_id)
    documents = repository.get_documents(investigation_id)
    document_viewer_captures = repository.get_document_viewer_captures(investigation_id)
    analyst_notes = repository.get_analyst_notes(investigation_id)
    risk_indicators = repository.get_risk_indicators(investigation_id)
    automated_platforms = {item["platform"] for item in social_findings}
    manual_links = [
        item for item in observations
        if item.get("entity_type") == "MANUAL_REVIEW_LINK"
        and item.get("value") not in automated_platforms
    ]
    evidence = repository.get_evidence(investigation_id)
    page_captures = repository.get_page_captures(investigation_id)
    query_metrics = repository.get_query_metrics(investigation_id)
    summary_counts = repository.get_summary_counts(investigation_id)
    file_prefix = report_file_prefix(investigation)
    metric_columns[2].metric("Confirmed findings", len(findings), border=True)
    metric_columns[3].metric("Dork queries", len(queries), border=True)

    report_html = OSINTReportBuilder(repository).build_html(investigation_id)
    st.download_button(
        ":material/download: Download HTML intelligence report",
        data=report_html.encode("utf-8"),
        file_name=f"{file_prefix}_osint_report.html",
        mime="text/html",
    )
    report_builder = OSINTReportBuilder(repository)
    downloads = st.container(horizontal=True)
    with downloads:
        st.download_button(":material/data_object: Download domain JSON", report_builder.build_json(investigation_id), f"{file_prefix}_domains.json", "application/json")
        st.download_button(":material/table: Download domain CSV", report_builder.build_domain_csv(investigation_id), f"{file_prefix}_domains.csv", "text/csv")
    st.download_button(
        ":material/download: Download DOCX evidence report",
        data=OSINTDocxReportBuilder(repository).build(investigation_id),
        file_name=f"{file_prefix}_evidence_report.docx",
        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )

    st.caption(
        f"Original input: `{investigation.get('original_input') or investigation['target_domain']}` · "
        f"Brand: **{investigation.get('resolved_brand') or 'Unknown'}** · "
        f"Resolution confidence: **{float(investigation.get('resolution_confidence') or 0):.0%}**"
    )

    queries_run = sum(1 for item in query_metrics if item.get("provider"))
    raw_results = int(summary_counts.get("raw_search_results", 0))
    target_sources = int(summary_counts.get("accepted_sources", 0))
    pages_checked = int(summary_counts.get("pages_visited", 0))
    evidence_captures = len(evidence)
    with st.container(horizontal=True):
        st.metric("Queries run", queries_run, border=True, help="Search queries actually executed in this investigation. The full query library may contain more queries.")
        st.metric("Results reviewed", raw_results, border=True, help="All URLs returned by the enabled public search providers before relevance filtering.")
        st.metric("Target-related sources", target_sources, border=True, help="Deduplicated URLs that passed the strict target-identity relevance check.")
        st.metric("Pages checked", pages_checked, border=True, help="Target-related source URLs opened for page-level evidence checking.")
        st.metric("Screenshots", evidence_captures, border=True, help="Confirmed evidence screenshots and target-presence baseline captures from accessible public pages.")

    overview_tab, resolution_tab, findings_tab, evidence_tab, search_tab, sources_tab, documents_tab, collectors_tab, risk_tab, notes_tab = st.tabs(
        ["Overview", "Resolution", "Findings", "Evidence captures", "Search queries", "Sources", "Documents", "Collector status", "Risk analysis", "Analyst notes"]
    )

    with overview_tab:
        st.subheader("Investigation funnel")
        st.caption("This shows how search results moved through validation. It does not count DNS, RDAP, or collector observations as evidence.")
        if target_sources:
            funnel = pd.DataFrame({
                "Stage": ["Results reviewed", "Target-related sources", "Pages checked", "Evidence captures"],
                "Count": [raw_results, target_sources, pages_checked, evidence_captures],
            })
            st.bar_chart(funnel, x="Stage", y="Count", horizontal=True)
        else:
            st.info(
                "No search result passed target relevance validation, so no pages were opened. "
                "This protects the report from unrelated sources."
            )
        with st.expander("What these statistics mean"):
            st.markdown(
                """- **Queries run**: searches actually sent during this run.
- **Results reviewed**: URLs returned by search before filtering.
- **Target-related sources**: URLs mentioning the resolved target identity that passed relevance rules.
- **Pages checked**: accepted source URLs opened for evidence extraction.
- **Evidence captures**: confirmed target-plus-evidence matches and clearly labelled target-presence baseline screenshots."""
            )

    with findings_tab:
        if findings:
            findings_frame = pd.DataFrame(findings)[
                [
                    "category", "entity_type", "value", "confidence", "query_id", "search_rank",
                    "source_type", "evidence_snippet", "source_url", "discovered_at",
                ]
            ]
            st.dataframe(
                findings_frame,
                hide_index=True,
                column_config={
                    "source_url": st.column_config.LinkColumn("Source"),
                    "confidence": st.column_config.NumberColumn("Confidence", format="%.2f"),
                },
            )
        else:
            st.info("No confirmed target-specific public evidence found.")

    with search_tab:
        st.caption(
            "Provider-neutral queries include public discovery across X, Reddit, Telegram, "
            "Facebook, Instagram, LinkedIn, YouTube, TikTok, Discord and GitHub."
        )
        if query_metrics:
            st.dataframe(pd.DataFrame(query_metrics), hide_index=True)
            selected_query = st.selectbox(
                "View results for query",
                [item["query_id"] for item in query_metrics],
                key=f"query_results_{investigation_id}",
            )
            query_results = repository.get_query_results(investigation_id, selected_query)
            if query_results:
                st.dataframe(
                    pd.DataFrame(query_results),
                    hide_index=True,
                    column_config={"source_url": st.column_config.LinkColumn("Source URL")},
                )
            else:
                st.info("This query returned no stored search results.")

    with evidence_tab:
        status_counts = pd.DataFrame(page_captures)["accessibility_status"].value_counts() if page_captures else {}
        evidence_columns = st.columns(4)
        evidence_columns[0].metric("Pages attempted", len(page_captures), border=True)
        evidence_columns[1].metric("Screenshots", len(evidence), border=True)
        evidence_columns[2].metric("Manual review", int(status_counts.get("manual_required", 0)), border=True)
        evidence_columns[3].metric("Failed", int(status_counts.get("failed", 0)), border=True)
        if evidence:
            filter_columns = st.columns(3)
            query_filter = filter_columns[0].multiselect(
                "Query", sorted({item["query_id"] for item in evidence}), key=f"evidence_query_{investigation_id}"
            )
            category_filter = filter_columns[1].multiselect(
                "Category", sorted({item["query_category"] for item in evidence}), key=f"evidence_category_{investigation_id}"
            )
            type_filter = filter_columns[2].multiselect(
                "Source type", sorted({item["source_type"] for item in evidence}), key=f"evidence_type_{investigation_id}"
            )
            detail_filters = st.columns(3)
            keyword_filter = detail_filters[0].text_input(
                "Keyword contains", key=f"evidence_keyword_{investigation_id}"
            ).strip().casefold()
            domain_filter = detail_filters[1].multiselect(
                "Source domain",
                sorted({urlsplit(item["source_url"]).hostname or "unknown" for item in evidence}),
                key=f"evidence_domain_{investigation_id}",
            )
            highest_rank = max(int(item["serp_rank"] or 0) for item in evidence)
            max_rank = detail_filters[2].number_input(
                "Maximum SERP rank", min_value=1, max_value=max(highest_rank, 1),
                value=max(highest_rank, 1), key=f"evidence_rank_{investigation_id}",
            )
            filtered = [
                item for item in evidence
                if (not query_filter or item["query_id"] in query_filter)
                and (not category_filter or item["query_category"] in category_filter)
                and (not type_filter or item["source_type"] in type_filter)
                and (not keyword_filter or keyword_filter in " ".join(item["matched_keywords"]).casefold())
                and (not domain_filter or (urlsplit(item["source_url"]).hostname or "unknown") in domain_filter)
                and int(item["serp_rank"] or 0) <= max_rank
            ]
            for item in filtered:
                with st.container(border=True):
                    st.markdown(
                        f"**{item['query_id']} · {item['query_name']}** — SERP rank {item['serp_rank']} · "
                        f"confidence {float(item['confidence']):.0%}"
                    )
                    image_path = Path(item["screenshot_path"])
                    if image_path.is_file():
                        st.image(str(image_path), width="stretch")
                    else:
                        st.warning("The stored screenshot file is unavailable.")
                    st.caption(
                        f"Keywords: {', '.join(item['matched_keywords'])} · SHA-256: {item['sha256']}"
                    )
                    st.write(item["context_text"] or item["evidence_text"])
                    st.link_button(":material/open_in_new: Open source", item["source_url"])
        elif page_captures:
            st.info("Pages were visited, but no confirmed evidence or baseline screenshots were captured.")
            st.dataframe(pd.DataFrame(page_captures), hide_index=True)
        else:
                st.info("No SERP-backed pages were available for browser evidence capture.")
        non_evidence_captures = [
            item for item in page_captures if item["accessibility_status"] not in {"evidence_found", "baseline_captured"}
        ]
        if non_evidence_captures:
            with st.expander("No evidence, manual review, and failed pages"):
                st.dataframe(
                    pd.DataFrame(non_evidence_captures),
                    hide_index=True,
                    column_config={"source_url": st.column_config.LinkColumn("Source URL")},
                )

    with findings_tab:
        if social_findings:
            st.subheader("Automated social and review findings")
            st.caption(
                "Target-validated public results discovered automatically through keyless search. "
                "These remain search-result evidence until the platform page is independently captured."
            )
            social_frame = pd.DataFrame(social_findings).rename(
                columns={
                    "post_url": "Source URL", "post_text": "Public snippet",
                    "search_rank": "Rank", "search_engine": "Provider",
                }
            )
            st.dataframe(
                social_frame[
                    ["platform", "title", "Public snippet", "confidence", "query_id",
                     "Provider", "Rank", "status", "Source URL", "collected_at"]
                ],
                hide_index=True,
                column_config={
                    "Source URL": st.column_config.LinkColumn("Source URL"),
                    "confidence": st.column_config.ProgressColumn(
                        "Confidence", min_value=0.0, max_value=1.0, format="percent"
                    ),
                },
            )
            captured_platform_findings = [
                item for item in social_findings
                if item["screenshot_paths"]
            ]
            if captured_platform_findings:
                screenshot_count = sum(len(item["screenshot_paths"]) for item in captured_platform_findings)
                with st.expander(f"Platform capture screenshots ({screenshot_count})"):
                    shown_paths: set[str] = set()
                    for item in captured_platform_findings:
                        for screenshot_path in item["screenshot_paths"]:
                            if screenshot_path in shown_paths or not Path(screenshot_path).is_file():
                                continue
                            shown_paths.add(screenshot_path)
                            st.image(
                                screenshot_path,
                                caption=f"{item['title']} · {item['post_url']}",
                                width="stretch",
                            )

        platforms = ["X/Twitter", "Reddit", "Instagram", "Facebook", "Telegram", "YouTube", "Quora", "Trustpilot", "Review site"]
        if not x_session_ready:
            st.warning(
                "Authenticated X/Twitter collection is not configured yet. Run "
                "`python -m scripts.setup_x_session`, complete login in the visible browser, "
                "restart the workers, and start a new investigation."
            )
        elif not x_collector_run:
            st.info(
                "The X session is ready, but this investigation did not run the authenticated X collector. "
                "Start a new investigation and select `X/Twitter authenticated search`."
            )
        coverage = []
        for platform in platforms:
            count = sum(1 for item in social_findings if item["platform"] == platform)
            if platform == "X/Twitter":
                direct_count = sum(
                    1 for item in social_findings
                    if item["platform"] == platform
                    and item["collector_method"] == "x_authenticated_playwright"
                )
                if x_collector_run:
                    method = "Authenticated Playwright"
                    if x_collector_run["status"] == "FAILED":
                        status = f"Failed: {x_collector_run['error'] or 'unknown error'}"
                    elif direct_count:
                        status = "Authenticated results captured"
                    else:
                        status = "Completed; no matching posts captured"
                elif not x_session_ready:
                    method = "Authenticated Playwright"
                    status = "Login session not configured"
                else:
                    method = "Authenticated Playwright"
                    status = "Ready; collector not selected for this investigation"
            elif platform in {"Instagram", "Facebook", "Telegram", "YouTube", "Quora"}:
                platform_key = platform.casefold()
                collector_name = f"{platform_key}_authenticated_playwright"
                platform_run = next(
                    (item for item in collector_runs if item["collector"] == collector_name),
                    None,
                )
                session_ready = configured_social_session_path(platform_key).is_file()
                direct_count = sum(
                    1 for item in social_findings
                    if item["platform"] == platform
                    and item["collector_method"] == collector_name
                )
                method = "Authenticated Playwright"
                if platform_run and platform_run["status"] == "FAILED":
                    status = f"Failed: {platform_run['error'] or 'unknown error'}"
                elif platform_run and direct_count:
                    status = "Authenticated results and screenshots captured"
                elif platform_run:
                    status = "Completed; no matching public results captured"
                elif not session_ready:
                    status = "Login session not configured"
                else:
                    status = "Ready; collector not selected for this investigation"
            elif platform == "Trustpilot":
                trustpilot_run = next(
                    (item for item in collector_runs if item["collector"] == "trustpilot_public_playwright"),
                    None,
                )
                method = "Public Playwright"
                if trustpilot_run and trustpilot_run["status"] == "FAILED":
                    status = f"Failed: {trustpilot_run['error'] or 'unknown error'}"
                elif trustpilot_run and count:
                    status = "Public reviews and screenshots captured"
                elif trustpilot_run:
                    status = "Completed; no matching company reviews found"
                else:
                    status = "Collector not selected for this investigation"
            else:
                method = "Keyless public search"
                status = "Automated results found" if count else "Manual fallback retained"
            coverage.append({
                "Platform": platform,
                "Automated findings": count,
                "Method": method,
                "Status": status,
            })
        st.subheader("Social collection coverage")
        st.dataframe(pd.DataFrame(coverage), hide_index=True)

        if manual_links:
            st.subheader("Manual social and review searches")
            st.caption("Only platforms with no automated result remain here for manual review.")
            st.dataframe(
                pd.DataFrame(manual_links)[["value", "source_url", "query_id", "discovered_at"]],
                hide_index=True,
                column_config={"source_url": st.column_config.LinkColumn("Open platform search")},
            )

    with resolution_tab:
        if identities:
            st.markdown("**Search identities**")
            st.dataframe(
                pd.DataFrame(identities),
                hide_index=True,
                column_config={
                    "confidence": st.column_config.ProgressColumn(
                        "Confidence", min_value=0.0, max_value=1.0, format="percent"
                    )
                },
            )
        if candidates:
            st.markdown("**Resolved / related domains**")
            controls = st.container(horizontal=True)
            with controls:
                active_only = st.checkbox("Active only", key=f"active_only_{investigation_id}")
                statuses = st.multiselect("Status", ["Active", "Inactive", "Unknown"], default=["Active", "Inactive", "Unknown"], key=f"domain_status_{investigation_id}")
                sort_by = st.selectbox("Sort by", ["Confidence", "Monthly visits", "Yearly visits"], key=f"domain_sort_{investigation_id}")
                refresh_traffic = st.checkbox("Refresh traffic data", help="Requests the configured third-party traffic provider again.", key=f"traffic_refresh_{investigation_id}")
                recheck = st.button(":material/refresh: Recheck domains", key=f"recheck_{investigation_id}")
            if recheck:
                progress = st.progress(0, text="Checking discovered domains safely…")
                domains = [item["domain"] for item in candidates]
                checks = DomainIntelligenceService().check_many(
                    domains, progress=lambda done, total: progress.progress(done / total, text=f"Checked {done} of {total} domains…"),
                    traffic_cache=repository.get_traffic_cache(domains), refresh_traffic=refresh_traffic,
                )
                repository.save_domain_checks(investigation_id, checks)
                progress.progress(1.0, text="Domain checks completed")
                st.rerun()
            frame = pd.DataFrame(candidates).rename(columns={"reason": "Resolution reason", "confidence": "Confidence", "appearances": "Appearances", "domain": "Domain", "domain_status": "Status", "http_status": "HTTP", "final_url": "Final URL", "monthly_visits": "Monthly Visits", "yearly_visits": "Yearly Visits", "traffic_source": "Traffic Source", "checked_at": "Checked At"})
            frame["HTTP meaning"] = frame.apply(
                lambda row: http_status_meaning(row.get("HTTP"), row.get("detailed_status", "")),
                axis=1,
            )
            if active_only:
                frame = frame[frame["Status"] == "Active"]
            frame = frame[frame["Status"].isin(statuses)]
            sort_column = {"Confidence": "Confidence", "Monthly visits": "Monthly Visits", "Yearly visits": "Yearly Visits"}[sort_by]
            frame = frame.sort_values(sort_column, ascending=False, na_position="last")
            columns = ["Domain", "Confidence", "Appearances", "Status", "HTTP", "HTTP meaning", "Final URL", "Monthly Visits", "Yearly Visits", "Traffic Source", "Checked At", "Resolution reason"]
            st.caption("Traffic figures are third-party estimated visits, not exact site analytics. Unavailable means no configured provider or no returned data.")
            st.dataframe(frame.reindex(columns=columns), hide_index=True, column_config={"Final URL": st.column_config.LinkColumn("Final URL"), "HTTP meaning": st.column_config.TextColumn("HTTP meaning", width="large"), "Confidence": st.column_config.ProgressColumn("Confidence", min_value=0.0, max_value=1.0, format="percent")})
        if candidate_leads:
            st.markdown("**Certificate Transparency leads — not evidence**")
            st.dataframe(pd.DataFrame(candidate_leads), hide_index=True)
        elif not candidates:
            st.info("This older investigation has no stored candidate-domain records.")

    with sources_tab:
        if sources:
            st.dataframe(
                pd.DataFrame(sources),
                hide_index=True,
                column_config={
                    "source_url": st.column_config.LinkColumn("Source URL"),
                    "normalized_url": st.column_config.LinkColumn("Normalized URL"),
                },
            )
        else:
            st.info("No search-backed sources were collected. Enable a configured search provider.")

    with documents_tab:
        if documents or document_viewer_captures:
            st.caption(
                "Verified downloaded files and captures from publicly accessible HTML document viewers. "
                "Each item keeps its source URL, SHA-256 hash, and query provenance."
            )
            metric_columns = st.columns(2)
            metric_columns[0].metric("Verified downloads", len(documents), border=True)
            metric_columns[1].metric("Viewer page captures", len(document_viewer_captures), border=True)
            document_rows = []
            for document in documents:
                row = dict(document)
                row["found_by_queries"] = ", ".join(
                    dict.fromkeys(
                        query.get("query_id", "")
                        for query in document.get("discovery_queries", [])
                        if query.get("query_id")
                    )
                )
                document_rows.append(row)
            st.dataframe(
                pd.DataFrame(document_rows).drop(
                    columns=["id", "local_path", "page_screenshots", "discovery_queries"],
                    errors="ignore",
                ),
                hide_index=True,
                column_config={
                    "source_url": st.column_config.LinkColumn("Source URL"),
                    "final_url": st.column_config.LinkColumn("Final URL"),
                    "size_bytes": st.column_config.NumberColumn("Size", format="%d bytes"),
                    "found_by_queries": st.column_config.TextColumn("Found by queries"),
                },
            )
            for document in documents:
                file_name = document.get("file_name") or Path(document["local_path"]).name
                query_ids = ", ".join(
                    dict.fromkeys(
                        query.get("query_id", "")
                        for query in document.get("discovery_queries", [])
                        if query.get("query_id")
                    )
                ) or "Legacy investigation"
                with st.container(border=True):
                    st.markdown(f"**{file_name}**")
                    st.caption(
                        f"{document.get('document_type') or 'Public document'} · "
                        f"Found by: {query_ids} · SHA-256: {document['sha256']}"
                    )
                    st.link_button(":material/open_in_new: Open source", document["source_url"])
                    content = repository.get_document_content(investigation_id, document["id"])
                    if content:
                        st.download_button(
                            ":material/download: Download stored document",
                            data=content,
                            file_name=file_name,
                            mime=document.get("media_type") or "application/octet-stream",
                            key=f"document_download_{investigation_id}_{document['id']}",
                        )
                    else:
                        st.caption("This legacy record contains metadata only; download it from the source link.")
                for capture in document.get("page_screenshots", []):
                    image_path = Path(capture["path"])
                    if image_path.is_file():
                        st.markdown(f"**Evidence page {capture['page']}**")
                        st.image(str(image_path), width="stretch")
                        st.caption(f"Screenshot SHA-256: {capture['sha256']}")
                        st.write(document.get("evidence_context") or "Target-specific document evidence")

            if document_viewer_captures:
                st.subheader("Public document viewer captures")
                st.caption(
                    "These sources were HTML viewers rather than directly downloadable files. "
                    "Only pages visible without login, paywall, CAPTCHA, or access-control bypass are captured."
                )
                for capture in document_viewer_captures:
                    with st.container(border=True):
                        st.markdown(f"**{capture.get('page_title') or 'Public document viewer'}**")
                        st.caption(
                            f"Found by {capture['query_id']} via {capture.get('search_engine') or 'public search'} · "
                            f"Page {capture['page_number']} · SHA-256: {capture['sha256']}"
                        )
                        st.link_button(
                            ":material/open_in_new: Open viewer",
                            capture.get("final_url") or capture["source_url"],
                            key=f"viewer_link_{investigation_id}_{capture['capture_id']}",
                        )
                        image_path = Path(capture["screenshot_path"])
                        if image_path.is_file():
                            st.image(str(image_path), width="stretch")
                        else:
                            st.warning("The stored viewer screenshot file is unavailable.")
        else:
            st.info(
                "No target-related public documents or accessible viewer pages were captured. "
                "Document-query results are prioritised before ordinary webpages."
            )

    with collectors_tab:
        if collector_runs:
            runs = pd.DataFrame(collector_runs)
            st.dataframe(
                runs,
                hide_index=True,
                column_config={
                    "duration_seconds": st.column_config.NumberColumn("Duration", format="%.2f s"),
                },
            )

    with risk_tab:
        st.caption("Only deterministic, evidence-backed indicators contribute to the risk score.")
        if risk_indicators:
            st.dataframe(
                pd.DataFrame(risk_indicators),
                hide_index=True,
                column_config={"source_url": st.column_config.LinkColumn("Source")},
            )
        else:
            st.success("No scored risk indicators were produced by the enabled collectors.")

    with notes_tab:
        if analyst_notes:
            st.dataframe(pd.DataFrame(analyst_notes), hide_index=True)
        with st.form(f"analyst_note_{investigation_id}"):
            note = st.text_area("Add analyst note", key=f"note_text_{investigation_id}")
            if st.form_submit_button(":material/note_add: Save note", disabled=not note.strip()):
                repository.add_analyst_note(investigation_id, note)
                st.rerun()
