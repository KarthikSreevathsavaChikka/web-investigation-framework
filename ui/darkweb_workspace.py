"""Supplied-source dark-web collection using the shared API and worker."""
import json

import streamlit as st

from ui.api_client import APIClientError, FrameworkAPIClient


def render_darkweb_workspace():
    st.title("Dark-web references")
    st.caption("Free resources · Check supplied onion pages for exact gaming-domain references.")
    with st.form("darkweb_collection"):
        target = st.text_input("Gaming URL or domain", placeholder="partimatch123.com")
        st.markdown("Find candidate pages with [Ahmia (manual search)](https://ahmia.fi/) or your existing sources. Search for the exact gaming domain and paste the original onion URLs.")
        urls = st.text_area("Onion URLs, one per line", height=150,
                            placeholder="Complete http://…onion/ or https://…onion/ URLs")
        st.caption("Up to 10 sources; five-minute run budget. Tor must be configured in the worker. Automatic discovery is not enabled.")
        submitted = st.form_submit_button("Collect related references", type="primary")
    if submitted:
        entries = list(dict.fromkeys(url.strip() for url in urls.splitlines() if url.strip()))
        if not target.strip() or not 1 <= len(entries) <= 10:
            st.error("Enter a gaming domain and between 1 and 10 onion URLs.")
        else:
            try:
                job = FrameworkAPIClient().submit_darkweb(target.strip(), entries)
                st.session_state["darkweb_job_id"] = job["id"]
                st.success("Collection queued")
            except APIClientError as exc:
                st.error(str(exc))
    _runs()


@st.fragment(run_every="5s")
def _runs():
    client = FrameworkAPIClient()
    try:
        jobs = [job for job in client.list_jobs() if job["component"] == "darkweb"]
        if not jobs:
            st.info("No dark-web collection runs yet.")
            return
        lookup = {job["id"]: job for job in jobs}
        selected = st.session_state.get("darkweb_job_id")
        ids = list(lookup)
        job_id = st.selectbox("Saved collection runs", ids,
                              index=ids.index(selected) if selected in ids else 0,
                              format_func=lambda key: f'{lookup[key]["target"]} · {lookup[key]["created_at"]} · {lookup[key]["status"]}')
        job = client.get_job(job_id)
        st.write(f'Job status: {job["status"]}')
        if job.get("error"):
            st.error(job["error"])
        if job["status"] not in {"COMPLETED", "FAILED", "CANCELLED"}:
            st.caption("Results appear when processing finishes.")
            if st.button("Cancel collection", key=f"cancel_{job_id}", disabled=job["status"] == "CANCELLING"):
                client.cancel_job(job_id)
                st.rerun(scope="fragment")
        result = job.get("result") or {}
        if not result:
            return
        columns = st.columns(3)
        columns[0].metric("Supplied sources", result["supplied_sources"])
        columns[1].metric("Assessed pages", result["retrieved_sources"])
        columns[2].metric("Matching sources", result["matched_sources"])
        st.write(f'Coverage: {result["coverage"]}')
        st.caption(result["scope"])
        st.caption(result["evidence_scope"])
        if not result["matched_sources"]:
            st.info("No exact-domain matches were verified in the supplied sources. Review source statuses for collection gaps.")
        st.download_button("Download evidence JSON", json.dumps(job, ensure_ascii=False, indent=2),
                           file_name=f"{job_id}.json", mime="application/json", key=f"export_{job_id}")
        for source in result["sources"]:
            with st.expander(f'{source.get("title") or source["source_url"]} — {source["status"]}'):
                st.code(source["source_url"], language=None)
                st.caption(f'Retrieved: {source["retrieved_at"]}')
                if source.get("error"):
                    st.text(source["error"])
                if source.get("content_sha256"):
                    st.text(f'Content SHA-256: {source["content_sha256"]}')
                for match in source["matches"]:
                    st.caption(f'Matched in {match["field"]}')
                    st.text(match["excerpt"])
    except APIClientError as exc:
        st.error(str(exc))
