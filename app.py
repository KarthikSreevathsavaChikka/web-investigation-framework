import streamlit as st

from ui.external_jobs_workspace import render_external_jobs_workspace
from ui.osint_workspace import render_osint_workspace
from ui.virustotal_workspace import render_virustotal_workspace
from ui.darkweb_workspace import render_darkweb_workspace
from ui.cases_workspace import render_cases_workspace

# Page Configuration
st.set_page_config(
    page_title="Web Investigation Framework",
    page_icon=":material/shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)

pages = [
    st.Page(render_cases_workspace, title="Cases and evidence", icon=":material/folder:"),
    st.Page(render_darkweb_workspace, title="Dark-web references", icon=":material/travel_explore:"),
    st.Page(
        render_osint_workspace,
        title="Web Scraping",
        icon=":material/manage_search:",
        default=True,
    ),
    st.Page(
        render_virustotal_workspace,
        title="VirusTotal intelligence",
        icon=":material/security:",
    ),
    st.Page(
        render_external_jobs_workspace,
        title="External job monitor",
        icon=":material/monitoring:",
    ),
]

navigation = st.navigation(pages, position="top")
navigation.run()
