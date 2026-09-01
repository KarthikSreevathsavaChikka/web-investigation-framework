import os
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from PIL import Image

from database.db_manager import DatabaseManager
from ui.components import render_metric_card, render_priority_badge, render_bounding_legend
from config import CATEGORY_COLORS_HEX
from database.connection import is_postgresql_enabled

def render_dashboard(db: DatabaseManager, investigation_id: str):
    """Step 12: Renders full Evidence Investigation Dashboard for a completed or stopped investigation."""
    
    summary = db.get_investigation_summary(investigation_id)
    inv_info = summary.get("investigation", {})
    
    if not inv_info:
        st.error("No investigation data found.")
        return

    # Header & Case Info
    st.markdown(f"## 🛡️ Investigation Report: `{inv_info.get('website_url')}`")
    st.caption(f"Investigation ID: `{investigation_id}` | Status: **{inv_info.get('investigation_status')}** | Started: {inv_info.get('start_time')} | Ended: {inv_info.get('end_time', 'N/A')}")
    st.markdown("---")

    # Step 12 - Metric Summary Cards (6 Columns)
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    
    with col1:
        render_metric_card("Pages Visited", str(summary.get("pages_visited", 0)), "📄")
    with col2:
        render_metric_card("Screenshots", str(summary.get("screenshots_captured", 0)), "📸")
    with col3:
        render_metric_card("Financial KWs", str(summary.get("financial_keywords", 0)), "💳")
    with col4:
        render_metric_card("Gaming KWs", str(summary.get("gaming_keywords", 0)), "🎲")
    with col5:
        render_metric_card("Payment Findings", str(summary.get("payment_findings_count", 0)), "💰")
    with col6:
        duration_sec = inv_info.get("duration", 0.0)
        render_metric_card("Duration", f"{duration_sec:.1f}s", "⏱️")

    st.markdown("<br>", unsafe_allow_html=True)

    # Plotly Visualizations Section
    cat_counts = summary.get("keyword_categories", {})
    if cat_counts:
        chart_col1, chart_col2 = st.columns(2)
        
        with chart_col1:
            fig_donut = px.pie(
                names=list(cat_counts.keys()),
                values=list(cat_counts.values()),
                hole=0.4,
                title="Categorized Keyword Distribution",
                color_discrete_sequence=px.colors.qualitative.Set2
            )
            fig_donut.update_layout(margin=dict(t=40, b=10, l=10, r=10), height=300)
            st.plotly_chart(fig_donut, width="stretch")

        with chart_col2:
            pages_data = db.get_pages_with_evidence(investigation_id)
            priorities = [p.get("priority", "Medium") for p in pages_data]
            p_df = pd.DataFrame(priorities, columns=["Priority"]).value_counts().reset_index()
            p_df.columns = ["Priority", "Count"]
            
            fig_bar = px.bar(
                p_df, 
                x="Priority", 
                y="Count", 
                color="Priority",
                title="Priority Navigation Distribution",
                color_discrete_map={"High": "#FF4D4D", "Medium": "#FFC107", "Low": "#2ECC71"}
            )
            fig_bar.update_layout(margin=dict(t=40, b=10, l=10, r=10), height=300)
            st.plotly_chart(fig_bar, width="stretch")

    # Dashboard Navigation Tabs
    tab_pages, tab_payment, tab_screenshots, tab_db = st.tabs([
        "📄 All Visited Pages", 
        "💳 Payment Intelligence", 
        "📸 Highlighted Evidence Gallery", 
        "🗄️ Database Inspector"
    ])

    # TAB 1: ALL VISITED PAGES
    with tab_pages:
        st.markdown("### 🔍 All Investigated Pages")
        pages = db.get_pages_with_evidence(investigation_id)
        
        if not pages:
            st.info("No pages recorded.")
        else:
            search_query = st.text_input("Filter Pages by URL or Title:", "")
            priority_filter = st.multiselect("Filter Priority:", ["High", "Medium", "Low"], default=["High", "Medium", "Low"])
            
            filtered_pages = [
                p for p in pages 
                if (search_query.lower() in p["page_url"].lower() or search_query.lower() in p["page_title"].lower())
                and p["priority"] in priority_filter
            ]

            st.caption(f"Showing {len(filtered_pages)} of {len(pages)} visited pages")
            
            for p in filtered_pages:
                with st.expander(f"[{p['priority'].upper()}] {p['page_title']} - {p['page_url']}"):
                    st.write(f"**URL:** `{p['page_url']}`")
                    st.write(f"**Visited Time:** {p['visited_time']}")
                    
                    p_cols = st.columns([2, 2])
                    with p_cols[0]:
                        st.markdown("**Detected Keywords:**")
                        if p.get("keywords"):
                            kw_df = pd.DataFrame(p["keywords"])[["keyword", "category", "count"]]
                            st.dataframe(kw_df, width="stretch")
                        else:
                            st.caption("No keyword matches on this page.")
                            
                    with p_cols[1]:
                        st.markdown("**Payment Findings:**")
                        if p.get("payment_findings"):
                            pf_df = pd.DataFrame(p["payment_findings"])[["finding_type", "finding_value", "confidence"]]
                            st.dataframe(pf_df, width="stretch")
                        else:
                            st.caption("No payment indicators found.")

                    if p.get("highlighted_image_path") and os.path.exists(p["highlighted_image_path"]):
                        st.markdown("**Highlighted Evidence Screenshot:**")
                        img = Image.open(p["highlighted_image_path"])
                        st.image(img, caption=f"Evidence Screenshot for {p['page_url']}", width="stretch")

    # TAB 2: PAYMENT INTELLIGENCE
    with tab_payment:
        st.markdown("### 💳 Extracted Payment Indicators & Gateways")
        st.caption("Detailed extraction of UPI Handles, Payment Gateways (Razorpay, Cashfree, Stripe), QR Codes, and Bank Accounts.")
        
        payment_list = db.get_payment_findings_all(investigation_id)
        if not payment_list:
            st.info("No payment indicators detected for this investigation.")
        else:
            pay_df = pd.DataFrame(payment_list)[["finding_type", "finding_value", "confidence", "page_url", "priority"]]
            st.dataframe(pay_df, width="stretch")

    # TAB 3: HIGHLIGHTED EVIDENCE SCREENSHOTS GALLERY
    with tab_screenshots:
        st.markdown("### 📸 Highlighted Evidence Screenshot Inspector")
        render_bounding_legend()
        st.markdown("<br>", unsafe_allow_html=True)
        
        pages = db.get_pages_with_evidence(investigation_id)
        screenshot_pages = [p for p in pages if p.get("highlighted_image_path") and os.path.exists(p["highlighted_image_path"])]
        
        if not screenshot_pages:
            st.warning("No evidence screenshots found.")
        else:
            page_options = {f"Page {idx+1}: {p['page_title']} ({p['page_url']})": p for idx, p in enumerate(screenshot_pages)}
            selected_option = st.selectbox("Select Evidence Screenshot to Inspect:", list(page_options.keys()))
            selected_page = page_options[selected_option]

            st.markdown(f"#### Screenshot: `{selected_page['page_url']}`")
            img = Image.open(selected_page["highlighted_image_path"])
            st.image(img, width="stretch")

            with st.expander("🔍 View Extracted Bounding Box Coordinates for this Screenshot", expanded=True):
                if selected_page.get("keywords"):
                    st.markdown("**Keyword Bounding Boxes:**")
                    st.json(selected_page["keywords"])
                if selected_page.get("payment_findings"):
                    st.markdown("**Payment Indicator Bounding Boxes:**")
                    st.json(selected_page["payment_findings"])

    # TAB 4: DATABASE INSPECTOR
    with tab_db:
        st.markdown("### 🗄️ SQLite Database Inspector")
        backend = "PostgreSQL" if is_postgresql_enabled() else "SQLite (local/test mode)"
        st.caption(f"Database inspector connected to: `{backend}`")
        
        tables = ["investigations", "pages", "keyword_findings", "screenshots", "payment_findings", "navigation_graph", "crawl_logs"]
        selected_table = st.selectbox("Select Table to View Raw Data:", tables)
        
        table_rows = db.get_table_data(selected_table)
        if table_rows:
            raw_df = pd.DataFrame(table_rows)
            st.dataframe(raw_df, width="stretch")
            
            # Download CSV
            csv = raw_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label=f"📥 Download {selected_table}.csv",
                data=csv,
                file_name=f"{selected_table}_{investigation_id}.csv",
                mime="text/csv"
            )
        else:
            st.info(f"Table `{selected_table}` is currently empty.")
