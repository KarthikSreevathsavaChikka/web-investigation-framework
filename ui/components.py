import streamlit as st

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
