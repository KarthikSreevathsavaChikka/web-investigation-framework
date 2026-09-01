import streamlit as st
from database.db_manager import DatabaseManager
from ui.components import inject_custom_css
from ui.dashboard import render_dashboard
from ui.osint_workspace import render_osint_workspace
from ui.api_client import APIClientError
from ui.job_status import get_api_client, render_dynamic_job_status
from config import DEFAULT_MAX_PAGES

# Page Configuration
st.set_page_config(
    page_title="Web Investigation Framework",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject modern dark theme styles
inject_custom_css()

# Initialize Database Manager
db_manager = DatabaseManager()

# Keep passive OSINT separate from the dynamic Playwright investigation workflow.
workspace = st.sidebar.selectbox(
    "Workspace",
    ["Dynamic web investigation", "Web intelligence and OSINT"],
    key="workspace",
)
if workspace == "Web intelligence and OSINT":
    render_osint_workspace()
    st.stop()

# Session State Initialization
st.session_state.setdefault("current_inv_id", None)
st.session_state.setdefault("status", "idle")
st.session_state.setdefault("dynamic_job_id", None)


# Main Header
st.markdown(
    '<div class="main-header">Web Investigation Framework</div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="sub-header">Queued Dynamic Investigation Service</div>',
    unsafe_allow_html=True,
)

# Sidebar for Past Investigations
with st.sidebar:
    st.markdown("### 📜 Past Investigations")
    all_invs = db_manager.get_all_investigations()
    if all_invs:
        inv_options = {
            f"{inv['website_url']} ({inv['start_time']})": inv["id"] for inv in all_invs
        }
        selected_past = st.selectbox(
            "Select Previous Case:",
            ["-- Select Current / New Run --"] + list(inv_options.keys()),
        )
        if selected_past != "-- Select Current / New Run --":
            st.session_state.current_inv_id = inv_options[selected_past]
            st.session_state.status = "completed"
    else:
        st.info("No past investigations recorded.")

# Step 1: Homepage Controls
st.markdown("### 🎯 Investigation Controls")
url_input = st.text_input(
    "Website URL", placeholder="https://parimatch.com", key="url_input"
)

with st.expander(":material/lock: Interactive login", expanded=False):
    st.info(
        "Queued workers currently support unattended investigations only. "
        "Interactive login and manual resume will be added as a separate secure workflow."
    )
    col_u, col_p, col_m = st.columns([3, 3, 2])
    with col_u:
        auth_user = st.text_input(
            "Username / Mobile Number / Email",
            placeholder="+91 9000158052",
            key="auth_user",
            disabled=True,
        )
    with col_p:
        auth_pass = st.text_input("Password", type="password", key="auth_pass", disabled=True)
    with col_m:
        auth_mode = st.selectbox(
            "Auth Mode",
            ["Auto-Detect", "Phone / Mobile Number", "User ID / Username", "Email"],
            key="auth_mode",
            disabled=True,
        )

authorized = st.checkbox(
    "I am authorized to investigate this target.",
    key="dynamic_authorized",
)

col_start, col_limit = st.columns([2, 3])

with col_limit:
    max_pages = st.slider(
        "Max Crawl Pages (Priority First)",
        min_value=1,
        max_value=50,
        value=DEFAULT_MAX_PAGES,
    )

with col_start:
    start_clicked = st.button(
        "🔍 Start Investigation",
        width="stretch",
        type="primary",
        disabled=bool(st.session_state.dynamic_job_id),
    )

if notice := st.session_state.pop("dynamic_notice", None):
    if st.session_state.status == "failed":
        st.error(notice)
    else:
        st.success(notice)

# Submit the investigation to FastAPI; validation and browser work run in the worker.
if start_clicked:
    if not url_input.strip():
        st.error("Enter a website URL before starting an investigation.")
    elif not authorized:
        st.error("Confirm authorization before starting an investigation.")
    else:
        try:
            job = get_api_client().submit_dynamic(
                url_input.strip(), max_pages, authorized=authorized
            )
            st.session_state.dynamic_job_id = job["id"]
            st.session_state.status = "queued"
            st.session_state.current_inv_id = None
            st.rerun()
        except APIClientError as exc:
            st.error(f"Could not queue the investigation: {exc}")

render_dynamic_job_status()

# Step 12: Render Evidence Dashboard if Investigation is Selected / Completed
if st.session_state.current_inv_id and st.session_state.status in [
    "completed",
    "stopped",
]:
    st.markdown("---")
    render_dashboard(db_manager, st.session_state.current_inv_id)
