from __future__ import annotations

from datetime import datetime, timezone

import streamlit as st

from ui.api_client import APIClientError, FrameworkAPIClient


@st.cache_resource
def get_api_client() -> FrameworkAPIClient:
    return FrameworkAPIClient()


def status_label(status: str) -> str:
    return {
        "QUEUED": "Waiting for an available worker",
        "RUNNING": "Investigation worker is collecting evidence",
        "COMPLETED": "Investigation completed",
        "FAILED": "Investigation failed",
        "CANCELLING": "Cancellation requested; stopping safely",
        "CANCELLED": "Investigation cancelled",
    }.get(status, status.replace("_", " ").title())


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


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
def render_dynamic_job_status() -> None:
    job_id = st.session_state.get("dynamic_job_id")
    if not job_id:
        return
    try:
        job = get_api_client().get_job(job_id)
    except APIClientError as exc:
        st.error(f"Could not refresh job `{job_id}`: {exc}")
        return

    status = job["status"]
    with st.container(border=True):
        st.caption(f"Queued job `{job_id}`")
        if status in {"QUEUED", "RUNNING", "CANCELLING"}:
            st.status(status_label(status), state="running")
            st.caption(job_timing(job))
            cancel_button(job, key_prefix="cancel_dynamic")
        elif status == "FAILED":
            st.error(job.get("error") or "The worker could not complete this investigation.")
        elif status == "CANCELLED":
            st.warning(status_label(status))
        else:
            st.success(status_label(status))
            st.caption(job_timing(job))

    if status == "COMPLETED":
        investigation_id = job.get("result", {}).get("investigation_id")
        st.session_state.dynamic_job_id = None
        st.session_state.current_inv_id = investigation_id
        st.session_state.status = "completed"
        st.session_state.dynamic_notice = f"Queued investigation completed: `{investigation_id}`"
        st.rerun()
    if status == "FAILED":
        st.session_state.dynamic_job_id = None
        st.session_state.status = "failed"
        st.session_state.dynamic_notice = (
            f"Queued investigation failed: {job.get('error') or 'Unknown worker error'}"
        )
        st.rerun()
    if status == "CANCELLED":
        st.session_state.dynamic_job_id = None
        st.session_state.status = "cancelled"
        st.session_state.dynamic_notice = "Queued investigation was cancelled."
        st.rerun()


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
                f"Completed {len(investigation_ids)} queued evidence investigation(s). "
                f"Latest: `{investigation_ids[-1]}`"
            )
        st.rerun()
