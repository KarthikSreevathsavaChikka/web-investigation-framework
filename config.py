import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
SCREENSHOTS_DIR = BASE_DIR / "screenshots"
EVIDENCE_DIR = BASE_DIR / "evidence"

# Ensure directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "evidence.db"

# Crawler Parameters
DEFAULT_MAX_PAGES = 15
DEFAULT_RENDER_TIMEOUT = 30000  # ms for Playwright (30 seconds for heavy gaming portals)
HEADLESS = os.getenv("HEADLESS", "false").lower() in {"1", "true", "yes"}

# Priority Navigation Lists
HIGH_PRIORITY_KEYWORDS = [
    # Core Actions & Navigation
    "deposit", "withdraw", "withdrawal", "wallet", "cashier", 
    "payment", "pay", "transactions", "transaction", "recharge", 
    "bonus", "referral", "rewards", "reward", "kyc", "profile", 
    "account", "add money", "cash out", "cashout", "login", "log in", 
    "sign in", "signin", "register", "sign up", "signup",
    "phone number", "phone", "mobile", "mobile number", "email", "e-mail",
    
    # Financial Balance & Wallet Categories
    "my wallet", "balance", "available balance", "cash balance", 
    "bonus balance", "winning balance", "deposit balance",
    "my transactions", "transaction id", "reference number", "payment reference",
    
    # Action Buttons
    "make payment", "pay now", "checkout",
    
    # UPI & Instant Payment Rails
    "upi", "upi id", "upi address", "collect request", "scan & pay", 
    "gpay", "google pay", "phonepe", "phone pe", "paytm", "pay tm", 
    "bhim", "amazon pay", "astropay", "qr", "qr code", "scan qr", "scan code",
    
    # Banking Rails
    "bank", "bank account", "account number", "beneficiary", "beneficiary name",
    "imps", "neft", "rtgs", "ecs", "ach", "netbanking", "net banking", "bank transfer",
    
    # Cards & Gateway Rails
    "razorpay", "cashfree", "payu", "ccavenue", "billdesk",
    "debit card", "credit card", "visa", "mastercard", "rupay",
    
    # Crypto Rails
    "crypto", "cryptocurrency", "bitcoin", "btc", "ethereum", "eth", 
    "usdt", "usdc", "tron", "bnb", "coinbase", "binance pay"
]

MEDIUM_PRIORITY_KEYWORDS = [
    "casino", "games", "game", "slots", "slot", "fantasy", 
    "sports", "promotions", "promotion", "leaderboard", "live casino",
    "roulette", "blackjack", "poker", "baccarat", "betting", "match"
]

LOW_PRIORITY_KEYWORDS = [
    "about", "faq", "contact", "terms", "privacy", "help", 
    "blog", "news", "responsible gaming", "disclaimer", "license"
]

# Categorized Keyword Lists for Detection & Annotation
CATEGORIZED_KEYWORDS = {
    "Financial": [
        "deposit", "withdraw", "withdrawal", "wallet", "cashier", 
        "balance", "transfer", "payout", "topup", "add money", 
        "bank", "upi", "upi id", "gateway", "currency", "inr", "usd", 
        "crypto", "usdt", "usdc", "bitcoin", "btc", "ethereum", "eth", "tron", "bnb",
        "transaction", "my transactions", "recharge", "imps", "neft", "rtgs", "ecs", "ach",
        "gpay", "google pay", "phonepe", "phone pe", "paytm", "pay tm", "amazon pay", "bhim",
        "razorpay", "cashfree", "payu", "ccavenue", "billdesk", "rupay", "visa", "mastercard",
        "available balance", "winning balance", "deposit balance", "bonus balance",
        "beneficiary", "account number", "reference number", "transaction id",
        "qr", "qr code", "scan & pay", "scan qr"
    ],
    "Gaming": [
        "casino", "slot", "slots", "roulette", "blackjack", "poker", 
        "baccarat", "sports", "live sports", "fantasy", "betting", 
        "odds", "match", "tournament", "jackpot", "table games", 
        "crash game", "aviator", "mines", "spin"
    ],
    "Rewards": [
        "bonus", "referral", "rewards", "cashback", "spin", "wheel", 
        "promo", "promotion", "free bet", "vip", "welcome bonus", 
        "deposit bonus", "loyalty", "points", "claim"
    ],
    "Authentication": [
        "login", "sign in", "signin", "register", "sign up", "signup", 
        "kyc", "verify", "verification", "otp", "password", "account", 
        "forgot password", "join now", "register now", "phone number", "phone", "mobile", "mobile number", "email", "e-mail"
    ],
    "Legal": [
        "terms", "privacy", "policy", "license", "terms of service", 
        "responsible gaming", "18+", "anti-money laundering", "aml", 
        "disclaimer", "curacao", "malta", "isom"
    ],
    "Social": [
        "telegram", "whatsapp", "discord", "instagram", "facebook", 
        "twitter", "support", "contact us", "live chat", "channel"
    ]
}

# Category Colors for OpenCV Bounding Boxes (BGR Format for OpenCV)
CATEGORY_COLORS_BGR = {
    "Financial": (0, 200, 0),       # Green
    "Gaming": (255, 120, 0),        # Blue / Cyan
    "Rewards": (0, 215, 255),       # Gold / Yellow
    "Authentication": (0, 0, 230),  # Red
    "Legal": (180, 50, 180),        # Purple
    "Social": (255, 190, 0),        # Teal / Light Blue
    "Payment_Indicator": (0, 0, 255)# Bright Red
}

# Bounding Box Hex Colors for UI Legend
CATEGORY_COLORS_HEX = {
    "Financial": "#00C800",
    "Gaming": "#0078FF",
    "Rewards": "#FFD700",
    "Authentication": "#E60000",
    "Legal": "#B432B4",
    "Social": "#00BEFF",
    "Payment_Indicator": "#FF0000"
}

# Payment Indicator Patterns & Signatures
PAYMENT_INDICATOR_PATTERNS = {
    "UPI_ID": r"[a-zA-Z0-9.\-_]+@(upi|okicici|ybl|paytm|ibl|axl|sbi|kotak|barodampay|icici|hdfcbank|okaxis|oksbi|okhdfcbank)",
    "PAYMENT_GATEWAY": r"(razorpay|cashfree|stripe|paytm|phonepe|google pay|gpay|payu|instamojo|paypal|ccavenue|billdesk)",
    "QR_CODE": r"(qr code|scan and pay|scan & pay|upi qr|scan to pay|scan qr|scan code)",
    "BANK_TRANSFER": r"(bank transfer|imps|neft|rtgs|ecs|ach|account number|ifsc|account name|beneficiary)",
    "WALLET": r"(paytm wallet|phonepe wallet|mobikwik|freecharge|crypto wallet|usdt trc20|bep20|binance pay|coinbase)"
}
