"""Live operational view for jobs received from the external complaint system."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st
from docx import Document

from core.time_utils import format_ist, parse_timestamp
from ui.api_client import APIClientError
from ui.job_status import get_api_client, job_timing


ACTIVE_STATUSES = {"QUEUED", "RUNNING", "CANCELLING"}


def _compact_id(value: str | None, prefix: int = 12) -> str:
    """Keep operational tables readable while full identifiers remain in job details."""
    text = str(value or "")
    return text if len(text) <= prefix else f"{text[:prefix]}…"


@st.cache_data(ttl="15m", max_entries=50, show_spinner="Preparing document preview…")
def _docx_preview(path_text: str, modified_time_ns: int) -> tuple[list[str], list[list[str]]]:
    """Extract a readable, bounded preview without altering the original DOCX."""
    del modified_time_ns  # Cache invalidates if a report is regenerated in place.
    document = Document(path_text)
    paragraphs = [paragraph.text.strip() for paragraph in document.paragraphs if paragraph.text.strip()]
    tables = [
        [" | ".join(cell.text.strip().replace("\n", " ") for cell in row.cells) for row in table.rows]
        for table in document.tables
    ]
    return paragraphs, tables


def _render_report_preview(report_path: Path) -> None:
    try:
        paragraphs, tables = _docx_preview(str(report_path), report_path.stat().st_mtime_ns)
    except Exception as exc:
        st.error(f"Could not preview this DOCX: {exc}")
        return
    st.caption("Preview of the generated DOCX. Images remain available in the downloaded original report.")
    with st.container(border=True):
        for paragraph in paragraphs[:300]:
            st.write(paragraph)
        for index, table in enumerate(tables[:30], start=1):
            with st.expander(f"Report table {index}"):
                for row in table[:100]:
                    st.write(row)
        if len(paragraphs) > 300 or len(tables) > 30:
            st.info("This preview is shortened for browser performance. Download the DOCX for the complete report.")


def _parse_time(value: str | None) -> datetime | None:
    return parse_timestamp(value)


def _elapsed_seconds(job: dict) -> int | None:
    started = _parse_time(job.get("started_at"))
    if not started:
        return None
    finished = _parse_time(job.get("completed_at")) or datetime.now(timezone.utc)
    return max(0, int((finished - started).total_seconds()))


def _table_rows(jobs: list[dict]) -> list[dict]:
    rows = []
    for job in jobs:
        payload = job.get("payload") or {}
        result = job.get("result") or {}
        rows.append({
            "Local job": _compact_id(job["id"], 16),
            "External job": _compact_id(payload.get("external_job_id"), 18),
            "Complaint": payload.get("complaint_id", ""),
            "Target ID": _compact_id(payload.get("target_id"), 18),
            "Target": job.get("target", ""),
            "Status": job.get("status", ""),
            "Timing": job_timing(job),
            "Run seconds": _elapsed_seconds(job),
            "Attempts": job.get("attempts", 0),
            "Callback": "Delivered" if result.get("callback_delivered") else ("Pending" if job.get("status") in ACTIVE_STATUSES else "Not delivered"),
            "VirusTotal": result.get("virustotal_status", "Waiting" if job.get("status") in ACTIVE_STATUSES else "Not configured"),
            "Received": format_ist(job.get("created_at")),
            "Started": format_ist(job.get("started_at"), fallback="Waiting"),
            "Finished": format_ist(job.get("completed_at"), fallback="Not finished"),
        })
    return rows


def _render_job_details(job: dict) -> None:
    payload = job.get("payload") or {}
    result = job.get("result") or {}
    with st.expander(f"{job['id']} · {job.get('target', '')} · {job.get('status', '')}"):
        st.caption(job_timing(job))
        if job.get("error"):
            st.error(job["error"])
        with st.container(horizontal=True):
            st.metric("Attempts", job.get("attempts", 0), border=True)
            st.metric("Callback", "Delivered" if result.get("callback_delivered") else "Pending", border=True)
            st.metric("VirusTotal", result.get("virustotal_status", "Waiting"), border=True)
        show_report_preview = False
        report_path: Path | None = None
        with st.container(horizontal=True):
            target = str(result.get("target_url") or job.get("target") or "")
            if target.startswith(("http://", "https://")):
                st.link_button(":material/open_in_new: Open input target", target)
            report_path = Path(str(result.get("report_path") or ""))
            if report_path.is_file():
                st.download_button(
                    ":material/download: Download generated report",
                    data=report_path.read_bytes(),
                    file_name=report_path.name,
                    mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    key=f"external_report_{job['id']}",
                )
                show_report_preview = st.checkbox(
                    ":material/visibility: View report",
                    key=f"external_report_preview_{job['id']}",
                    help="Display a readable in-browser preview below these actions.",
                )
            elif job.get("status") == "COMPLETED":
                st.warning("The job completed, but its report file is no longer available in shared storage.")
        if show_report_preview and report_path and report_path.is_file():
            st.subheader("Generated report preview")
            _render_report_preview(report_path)
        st.subheader("External request")
        st.json(payload, expanded=False)
        if result:
            st.subheader("Processing result")
            st.json(result, expanded=False)
            domains = result.get("domains") or []
            if domains:
                st.write("Resolved/analyzed domains: " + ", ".join(domains))
        st.caption(
            f"Received: {format_ist(job.get('created_at'))} · "
            f"Started: {format_ist(job.get('started_at'), fallback='Waiting')} · "
            f"Finished: {format_ist(job.get('completed_at'), fallback='Not finished')}"
        )


def render_external_jobs_workspace() -> None:
    st.title("External job monitor")
    st.caption("Tracks targets received from the complaint system. Refreshes every five seconds while this page is open.")
    _render_live_external_jobs()


@st.fragment(run_every="5s")
def _render_live_external_jobs() -> None:
    try:
        jobs = [job for job in get_api_client().list_jobs() if job.get("component") == "external"]
    except APIClientError as exc:
        st.error(f"Cannot read external jobs from the API: {exc}")
        return
    with st.container(horizontal=True):
        st.metric("Received", len(jobs), border=True)
        st.metric("Running", sum(job.get("status") == "RUNNING" for job in jobs), border=True)
        st.metric("Waiting", sum(job.get("status") == "QUEUED" for job in jobs), border=True)
        st.metric("Completed", sum(job.get("status") == "COMPLETED" for job in jobs), border=True)
        st.metric("Failed", sum(job.get("status") == "FAILED" for job in jobs), border=True)
    if not jobs:
        st.info("No external jobs have been received yet.")
        return
    statuses = sorted({job.get("status", "Unknown") for job in jobs})
    selected_statuses = st.multiselect("Show statuses", statuses, default=statuses, key="external_job_status_filter")
    target_filter = st.text_input("Filter by target, complaint, external job, or local job ID", key="external_job_text_filter").strip().casefold()
    filtered = [
        job for job in jobs
        if job.get("status") in selected_statuses
        and (not target_filter or target_filter in " ".join(str(value) for value in (
            job.get("id"), job.get("target"), (job.get("payload") or {}).get("external_job_id"),
            (job.get("payload") or {}).get("complaint_id"), (job.get("payload") or {}).get("target_id"),
        )).casefold())
    ]
    st.caption(f"Showing {len(filtered)} of {len(jobs)} external job(s).")
    st.dataframe(
        pd.DataFrame(_table_rows(filtered)), hide_index=True, height=420,
        column_config={
            "Local job": st.column_config.TextColumn("Local job", width="small", pinned=True),
            "External job": st.column_config.TextColumn("External job", width="medium"),
            "Target ID": st.column_config.TextColumn("Target ID", width="medium"),
            "Target": st.column_config.TextColumn("Target", width="medium", pinned=True),
            "Status": st.column_config.TextColumn("Status", width="small"),
            "Run seconds": st.column_config.NumberColumn("Run seconds", format="%d s", width="small"),
        },
    )
    st.subheader("Job details")
    for job in filtered:
        _render_job_details(job)
