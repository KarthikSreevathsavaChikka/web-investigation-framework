import streamlit as st
from config import CATEGORY_COLORS_HEX

def inject_custom_css():
    """Injects custom modern dark theme CSS styling with glassmorphism effects."""
    st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');
        
        html, body, [class*="css"] {
            font-family: 'Inter', sans-serif;
        }
        
        .main-header {
            font-size: 2.2rem;
            font-weight: 700;
            background: linear-gradient(90deg, #00C8FF, #7800FF);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.2rem;
        }
        
        .sub-header {
            font-size: 1.0rem;
            color: #8E9AAF;
            margin-bottom: 2rem;
        }

        .metric-card {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 1.2rem;
            text-align: center;
            backdrop-filter: blur(10px);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
            transition: transform 0.2s ease;
        }
        .metric-card:hover {
            transform: translateY(-3px);
            border-color: #00C8FF;
        }
        .metric-value {
            font-size: 2rem;
            font-weight: 700;
            color: #FFFFFF;
        }
        .metric-label {
            font-size: 0.85rem;
            color: #A0AEC0;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 0.3rem;
        }

        .badge-high {
            background-color: rgba(230, 0, 0, 0.2);
            color: #FF4D4D;
            border: 1px solid #FF4D4D;
            padding: 2px 8px;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 600;
        }
        .badge-medium {
            background-color: rgba(255, 170, 0, 0.2);
            color: #FFC107;
            border: 1px solid #FFC107;
            padding: 2px 8px;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 600;
        }
        .badge-low {
            background-color: rgba(0, 200, 0, 0.2);
            color: #2ECC71;
            border: 1px solid #2ECC71;
            padding: 2px 8px;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 600;
        }

        .auth-banner {
            background: linear-gradient(90deg, #FF416C, #FF4B2B);
            color: white;
            padding: 1.2rem;
            border-radius: 12px;
            text-align: center;
            font-weight: 600;
            margin: 1.5rem 0;
            box-shadow: 0 4px 20px rgba(255, 65, 108, 0.4);
        }
        </style>
    """, unsafe_allow_html=True)

def render_metric_card(label: str, value: str, icon: str):
    """Renders styled metric card widget."""
    st.markdown(f"""
        <div class="metric-card">
            <div style="font-size: 1.5rem; margin-bottom: 0.2rem;">{icon}</div>
            <div class="metric-value">{value}</div>
            <div class="metric-label">{label}</div>
        </div>
    """, unsafe_allow_html=True)

def render_priority_badge(priority: str) -> str:
    """Returns HTML snippet for priority badge."""
    p_lower = priority.lower()
    if p_lower == "high":
        return '<span class="badge-high">HIGH</span>'
    elif p_lower == "medium":
        return '<span class="badge-medium">MEDIUM</span>'
    else:
        return '<span class="badge-low">LOW</span>'

def render_bounding_legend():
    """Renders Bounding Box Legend for OpenCV screenshots."""
    st.markdown("### 🎨 Evidence Bounding Box Legend")
    cols = st.columns(5)
    
    with cols[0]:
        st.markdown(f'<div style="color:{CATEGORY_COLORS_HEX["Financial"]}; font-weight:bold;">🟢 Financial Keywords</div>', unsafe_allow_html=True)
        st.caption("Deposit, Withdraw, Wallet, Cashier, Balance")
        
    with cols[1]:
        st.markdown(f'<div style="color:{CATEGORY_COLORS_HEX["Gaming"]}; font-weight:bold;">🔵 Gaming Keywords</div>', unsafe_allow_html=True)
        st.caption("Casino, Slots, Sports, Odds, Matches")

    with cols[2]:
        st.markdown(f'<div style="color:{CATEGORY_COLORS_HEX["Rewards"]}; font-weight:bold;">🟡 Rewards Keywords</div>', unsafe_allow_html=True)
        st.caption("Bonus, Referral, Cashback, Free Bet")

    with cols[3]:
        st.markdown(f'<div style="color:{CATEGORY_COLORS_HEX["Payment_Indicator"]}; font-weight:bold;">🔴 Payment Indicators</div>', unsafe_allow_html=True)
        st.caption("UPI VPA, Gateways, QR Codes, Bank Details")

    with cols[4]:
        st.markdown(f'<div style="color:{CATEGORY_COLORS_HEX["Legal"]}; font-weight:bold;">🟣 Legal & Auth</div>', unsafe_allow_html=True)
        st.caption("KYC, Login, Terms, License, AML")
