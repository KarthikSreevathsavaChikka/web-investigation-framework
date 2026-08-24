import re
import logging
from typing import Dict, List, Any
from config import PAYMENT_INDICATOR_PATTERNS

logger = logging.getLogger(__name__)

class PaymentDetector:
    """Step 10: Detects payment gateways, UPI VPAs, QR code elements, bank details, and wallets."""

    def __init__(self, patterns: Dict[str, str] = PAYMENT_INDICATOR_PATTERNS):
        self.patterns = patterns

    async def detect_payment_indicators(self, page, page_html: str) -> List[Dict[str, Any]]:
        findings = []
        seen = set()

        # 1. Regex scanning across raw HTML text
        for ptype, pattern in self.patterns.items():
            matches = re.finditer(pattern, page_html, re.IGNORECASE)
            for m in matches:
                val = m.group(0).strip()
                if val and len(val) > 2 and val.lower() not in seen:
                    seen.add(val.lower())
                    findings.append({
                        "finding_type": ptype,
                        "finding_value": val,
                        "confidence": "High"
                    })

        # 2. DOM inspection via Playwright for payment-specific elements & bounding boxes
        js_payment_script = """
        () => {
            const results = [];
            
            // Search for payment gateway scripts or iframe integration signatures
            const scripts = Array.from(document.querySelectorAll('script, iframe')).map(el => el.src || el.id || '');
            scripts.forEach(src => {
                if (src.includes('razorpay')) results.push({ type: 'PAYMENT_GATEWAY', val: 'Razorpay SDK / Iframe', confidence: 'High' });
                if (src.includes('cashfree')) results.push({ type: 'PAYMENT_GATEWAY', val: 'Cashfree SDK / Iframe', confidence: 'High' });
                if (src.includes('stripe')) results.push({ type: 'PAYMENT_GATEWAY', val: 'Stripe SDK / Iframe', confidence: 'High' });
                if (src.includes('paytm')) results.push({ type: 'PAYMENT_GATEWAY', val: 'Paytm SDK / Gateway', confidence: 'High' });
            });

            // Search for QR Code images or canvas containers
            const images = document.querySelectorAll('img, canvas, svg, div');
            images.forEach(el => {
                const classStr = typeof el.className === 'string' ? el.className : (el.getAttribute('class') || '');
                const alt = String(el.alt || classStr || el.id || '').toLowerCase();
                if (alt.includes('qr') || alt.includes('upi') || alt.includes('scan')) {
                    const rect = el.getBoundingClientRect();
                    if (rect.width > 50 && rect.height > 50) {
                        results.push({
                            type: 'QR_CODE',
                            val: `QR Code Element (${el.tagName.toLowerCase()})`,
                            confidence: 'High',
                            bounding_box: {
                                x: Math.round(rect.left + window.scrollX),
                                y: Math.round(rect.top + window.scrollY),
                                width: Math.round(rect.width),
                                height: Math.round(rect.height)
                            }
                        });
                    }
                }
            });

            // Deep DOM scanning for active UPI VPAs (e.g. 9464604336@ptaxis)
            const upiRegex = /[a-zA-Z0-9.\\-_]+@(upi|okicici|ybl|paytm|ibl|axl|sbi|kotak|barodampay|icici|hdfcbank|okaxis|oksbi|okhdfcbank|ptaxis)/gi;
            const elements = document.querySelectorAll('div, span, p, label, code, b, strong');
            elements.forEach(el => {
                const text = el.innerText || el.textContent || '';
                if (text && text.length < 300) {
                    const matches = text.match(upiRegex);
                    if (matches) {
                        matches.forEach(vpa => {
                            const rect = el.getBoundingClientRect();
                            results.push({
                                type: 'UPI_ID',
                                val: vpa.trim(),
                                confidence: 'High (DOM Inspected)',
                                bounding_box: (rect.width > 0 && rect.height > 0) ? {
                                    x: Math.round(rect.left + window.scrollX),
                                    y: Math.round(rect.top + window.scrollY),
                                    width: Math.round(rect.width),
                                    height: Math.round(rect.height)
                                } : null
                            });
                        });
                    }
                }
            });

            return results;
        }
        """

        try:
            dom_findings = await page.evaluate(js_payment_script)
            for df in dom_findings:
                val = df["val"]
                if val.lower() not in seen:
                    seen.add(val.lower())
                    findings.append({
                        "finding_type": df["type"],
                        "finding_value": val,
                        "confidence": df.get("confidence", "High"),
                        "bounding_box": df.get("bounding_box")
                    })
        except Exception as e:
            logger.error(f"Error during payment DOM evaluation: {e}")

        return findings
