from __future__ import annotations

from datetime import datetime, timezone

import streamlit as st

from core.time_utils import parse_timestamp
from ui.api_client import APIClientError, FrameworkAPIClient


@st.cache_resource
def get_api_client() -> FrameworkAPIClient:
    return FrameworkAPIClient()


def status_label(status: str) -> str:
    return {
        "QUEUED": "Waiting for an available worker",
        "RUNNING": "Investigation worker is collecting evidence",
        "COMPLETED": "Processing finished; review collection coverage",
        "FAILED": "Investigation failed",
        "CANCELLING": "Cancellation requested; stopping safely",
        "CANCELLED": "Investigation cancelled",
    }.get(status, status.replace("_", " ").title())


def _parse_time(value: str | None) -> datetime | None:
    return parse_timestamp(value)


def _format_seconds(seconds: float) -> str:
    total = max(0, int(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:d}:{minutes:02d}:{seconds:02d}" if hours else f"{minutes:d}:{seconds:02d}"


def job_timing(job: dict) -> str:
    now = datetime.now(timezone.utc)
    created = _parse_time(job.get("created_at"))
    started = _parse_time(job.get("started_at"))
    completed = _parse_time(job.get("completed_at"))
    if started:
        elapsed = (completed or now) - started
        queue_wait = started - created if created else None
        timing = f"Run time {_format_seconds(elapsed.total_seconds())}"
        if queue_wait:
            timing += f" · waited {_format_seconds(queue_wait.total_seconds())}"
        return timing
    if created:
        return f"Waiting {_format_seconds(((completed or now) - created).total_seconds())}"
    return "Timing unavailable"


def cancel_button(job: dict, *, key_prefix: str) -> None:
    if job["status"] not in {"QUEUED", "RUNNING"}:
        return
    if st.button(
        ":material/cancel: Cancel",
        key=f"{key_prefix}_{job['id']}",
        type="tertiary",
    ):
        try:
            get_api_client().cancel_job(job["id"])
            st.toast(f"Cancellation requested for {job['target']}")
            st.rerun()
        except APIClientError as exc:
            st.error(f"Could not cancel `{job['id']}`: {exc}")


@st.fragment(run_every="2s")
def render_osint_job_status() -> None:
    job_ids = st.session_state.get("osint_job_ids", [])
    if not job_ids:
        return
    try:
        jobs = [get_api_client().get_job(job_id) for job_id in job_ids]
    except APIClientError as exc:
        st.error(f"Could not refresh queued OSINT jobs: {exc}")
        return

    completed = [job for job in jobs if job["status"] == "COMPLETED"]
    failed = [job for job in jobs if job["status"] == "FAILED"]
    cancelled = [job for job in jobs if job["status"] == "CANCELLED"]
    active = [job for job in jobs if job["status"] in {"QUEUED", "RUNNING", "CANCELLING"}]
    with st.container(border=True):
        st.caption(f"Queued evidence jobs · {len(completed)}/{len(jobs)} completed")
        if active:
            running = sum(job["status"] in {"RUNNING", "CANCELLING"} for job in active)
            st.status(
                f"{running} running · {len(active) - running} waiting",
                state="running",
            )
        partial = [job for job in completed if job.get("result", {}).get("coverage", {}).get("status") == "PARTIAL"]
        if partial:
            st.warning(f"{len(partial)} finished job(s) have incomplete collection. Review report diagnostics.")
        if failed:
            st.error(f"{len(failed)} job(s) failed. Expand job details for the recorded errors.")
        with st.expander("Job details"):
            for job in jobs:
                message = (
                    f"`{job['id']}` · {job['target']} · **{job['status']}** · "
                    f"{job_timing(job)}"
                )
                if job.get("error"):
                    message += f" · {job['error']}"
                st.markdown(message)
                cancel_button(job, key_prefix="cancel_osint")

    if not active:
        investigation_ids = [
            job.get("result", {}).get("investigation_id") for job in completed
            if job.get("result", {}).get("investigation_id")
        ]
        st.session_state.osint_job_ids = []
        if failed:
            st.session_state.osint_error = (
                f"{len(failed)} queued investigation(s) failed. "
                f"Latest error: {failed[-1].get('error') or 'Unknown worker error'}"
            )
        elif cancelled and not investigation_ids:
            st.session_state.osint_error = f"{len(cancelled)} investigation(s) cancelled."
        if investigation_ids:
            st.session_state.osint_current_investigation = investigation_ids[-1]
            st.session_state.osint_notice = (
                f"Finished processing {len(investigation_ids)} investigation(s); review report coverage. "
                f"Latest: `{investigation_ids[-1]}`"
            )
        st.rerun()
