from __future__ import annotations

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
    }.get(status, status.replace("_", " ").title())


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
        if status in {"QUEUED", "RUNNING"}:
            st.status(status_label(status), state="running")
        elif status == "FAILED":
            st.error(job.get("error") or "The worker could not complete this investigation.")
        else:
            st.success(status_label(status))

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
    active = [job for job in jobs if job["status"] in {"QUEUED", "RUNNING"}]
    with st.container(border=True):
        st.caption(f"Queued evidence jobs · {len(completed)}/{len(jobs)} completed")
        if active:
            running = sum(job["status"] == "RUNNING" for job in active)
            st.status(
                f"{running} running · {len(active) - running} waiting",
                state="running",
            )
        if failed:
            st.error(f"{len(failed)} job(s) failed. Expand job details for the recorded errors.")
        with st.expander("Job details"):
            for job in jobs:
                message = f"`{job['id']}` · {job['target']} · **{job['status']}**"
                if job.get("error"):
                    message += f" · {job['error']}"
                st.markdown(message)

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
        if investigation_ids:
            st.session_state.osint_current_investigation = investigation_ids[-1]
            st.session_state.osint_notice = (
                f"Completed {len(investigation_ids)} queued evidence investigation(s). "
                f"Latest: `{investigation_ids[-1]}`"
            )
        st.rerun()
