import asyncio
import uuid
import streamlit as st
from database.db_manager import DatabaseManager
from core.validator import TargetValidator
from core.browser_engine import PlaywrightInvestigationEngine
from ui.components import inject_custom_css
from ui.dashboard import render_dashboard
from ui.osint_workspace import render_osint_workspace
from config import DEFAULT_MAX_PAGES

# Page Configuration
st.set_page_config(
    page_title="Gaming Website Investigation Prototype",
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
if "engine" not in st.session_state:
    st.session_state.engine = None
if "current_inv_id" not in st.session_state:
    st.session_state.current_inv_id = None
if "status" not in st.session_state:
    st.session_state.status = "idle"  # idle, running, paused_auth, completed, stopped
if "logs" not in st.session_state:
    st.session_state.logs = []


def add_log(action: str, status: str):
    st.session_state.logs.append(f"[{status}] {action}")


def trigger_auth_pause():
    st.session_state.status = "paused_auth"


# Main Header
st.markdown(
    '<div class="main-header">Gaming Website Investigation Prototype</div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="sub-header">Automated Evidence Collection Engine (Version 1)</div>',
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

with st.expander("🔑 Automated Login Credentials (Optional)", expanded=True):
    col_u, col_p, col_m = st.columns([3, 3, 2])
    with col_u:
        auth_user = st.text_input(
            "Username / Mobile Number / Email",
            placeholder="+91 9000158052",
            key="auth_user",
        )
    with col_p:
        auth_pass = st.text_input("Password", type="password", key="auth_pass")
    with col_m:
        auth_mode = st.selectbox(
            "Auth Mode",
            ["Auto-Detect", "Phone / Mobile Number", "User ID / Username", "Email"],
            key="auth_mode",
        )

col_start, col_stop, col_limit = st.columns([2, 2, 3])

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
        disabled=(st.session_state.status == "running"),
    )

with col_stop:
    stop_clicked = st.button(
        "🛑 Stop Investigation",
        width="stretch",
        disabled=(st.session_state.status != "running"),
    )

# Handle Stop Button Click
if stop_clicked and st.session_state.engine:
    st.session_state.engine.request_stop()
    st.warning("Stop request sent to crawler. Finalizing evidence collected so far...")

# Step 6: Authentication Banner (if login required)
if st.session_state.status == "paused_auth":
    st.markdown(
        """
        <div class="auth-banner">
            ⚠️ Login Required — Please log in manually in the open browser window on your screen.<br>
            After logging in, click the button below to resume evidence collection.
        </div>
    """,
        unsafe_allow_html=True,
    )
    if st.button("▶️ Resume Investigation", type="primary"):
        if st.session_state.engine:
            st.session_state.engine.resume_investigation()
            st.session_state.status = "running"
            st.rerun()

# Execute Start Investigation Workflow
if start_clicked and url_input.strip():
    target_url = url_input.strip()
    st.session_state.logs = []

    # Step 2: Validate Target URL
    st.info(f"Validating target URL: `{target_url}`...")
    val_result = TargetValidator.validate_url(target_url)

    if not val_result["valid"]:
        st.error(
            f"❌ Target Validation Failed: {val_result.get('error', 'Unreachable website')}"
        )
        st.session_state.status = "idle"
    else:
        st.success(
            f"✅ Target Validated: Reachable ({val_result['status_code']}), HTTPS: {val_result['is_https']}"
        )

        investigation_id = f"INV_{uuid.uuid4().hex[:8].upper()}"
        st.session_state.current_inv_id = investigation_id
        st.session_state.status = "running"

        # Instantiate Browser Engine
        engine = PlaywrightInvestigationEngine(db_manager, max_pages=max_pages)
        st.session_state.engine = engine

        # Run Async Playwright Workflow
        with st.spinner(
            "Investigating target website... Playwright headed browser active."
        ):
            res = asyncio.run(
                engine.run_investigation(
                    target_url=val_result["final_url"],
                    investigation_id=investigation_id,
                    log_callback=add_log,
                    auth_callback=trigger_auth_pause,
                    auth_user=auth_user.strip() if auth_user else "",
                    auth_pass=auth_pass.strip() if auth_pass else "",
                    auth_mode=auth_mode,
                )
            )

        if res.get("status") == "FAILED":
            st.session_state.status = "idle"
            st.session_state.engine = None
            st.error(f"Investigation failed: {res.get('error', 'Unknown error')}")
        else:
            st.session_state.status = "completed"
            st.session_state.engine = None
            st.rerun()

# Render Real-time Logs if Running
if st.session_state.status == "running" and st.session_state.logs:
    st.markdown("### 📋 Live Investigation Logs")
    with st.container():
        for log in st.session_state.logs[-10:]:
            st.code(log)

# Step 12: Render Evidence Dashboard if Investigation is Selected / Completed
if st.session_state.current_inv_id and st.session_state.status in [
    "completed",
    "stopped",
]:
    st.markdown("---")
    render_dashboard(db_manager, st.session_state.current_inv_id)
