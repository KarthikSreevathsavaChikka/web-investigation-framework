import re
import asyncio
import time
import uuid
import logging
from typing import Dict, List, Any, Optional, Callable, Set
from playwright.async_api import Browser, BrowserContext, Page

from config import DEFAULT_MAX_PAGES, DEFAULT_RENDER_TIMEOUT, HEADLESS
from database.db_manager import DatabaseManager
from core.nav_engine import NavigationEngine
from core.keyword_detector import KeywordDetector
from core.payment_detector import PaymentDetector
from core.image_annotator import ImageAnnotator
from core.playwright_session import BrowserResources, launch_browser_session

logger = logging.getLogger(__name__)


class PlaywrightInvestigationEngine:
    """
    Core Evidence Collection Engine:
    Manages Playwright headed browser session, Priority Navigation, Auth Pause/Resume,
    Keyword & Payment detection, Bounding box extraction, and Evidence Persistence.
    """

    def __init__(self, db_manager: DatabaseManager, max_pages: int = DEFAULT_MAX_PAGES):
        self.db = db_manager
        self.max_pages = max_pages
        self.stop_requested = False
        self.pause_for_auth = False
        self.auth_resumed = asyncio.Event()

        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self._browser_resources: Optional[BrowserResources] = None

        self.keyword_detector = KeywordDetector()
        self.payment_detector = PaymentDetector()

    def request_stop(self):
        """Called when user clicks Stop Investigation button."""
        self.stop_requested = True
        self.auth_resumed.set()  # Unblock pause if waiting

    def resume_investigation(self):
        """Called when user completes manual login and clicks Resume Investigation."""
        self.pause_for_auth = False
        self.auth_resumed.set()

    async def init_browser(self):
        """Launches Playwright Chromium browser in Headed mode with a system-browser fallback."""
        self._browser_resources = await launch_browser_session(headless=HEADLESS)
        self.playwright = self._browser_resources.playwright
        self.browser = self._browser_resources.browser
        self.context = self._browser_resources.context
        self.page = await self.context.new_page()

    async def close_browser(self):
        """Safely closes Playwright browser instance."""
        try:
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
        except Exception as e:
            logger.error(f"Error closing browser: {e}")

    async def get_stable_page_content(self, attempts: int = 4) -> str:
        """Read the DOM while tolerating short redirect/navigation races."""
        if not self.page:
            raise RuntimeError("Browser page is not initialized")
        last_error: Exception | None = None
        for attempt in range(attempts):
            try:
                return await self.page.content()
            except Exception as exc:
                last_error = exc
                if "page is navigating" not in str(exc).lower() or attempt == attempts - 1:
                    raise
                try:
                    await self.page.wait_for_load_state(
                        "domcontentloaded", timeout=5000
                    )
                except Exception:
                    pass
                await asyncio.sleep(0.5)
        raise RuntimeError("Unable to read page content") from last_error

    async def check_login_required(
        self, page: Page, html_content: str, url: str
    ) -> bool:
        """Step 6: Checks if page or visible DOM overlays contain login forms, password inputs, or auth triggers."""
        url_lower = url.lower()
        if any(
            term in url_lower for term in ["/login", "/signin", "/auth", "/register"]
        ):
            return True

        # Check for visible password input fields or login forms in DOM
        try:
            password_inputs = page.locator(
                "input[type='password'], input[name*='pass' i]"
            )
            for i in range(await password_inputs.count()):
                if await password_inputs.nth(i).is_visible():
                    return True

            # Check for visible Login buttons (indicates user is not logged in)
            login_btns = page.locator(
                "button:has-text('Log in'), a:has-text('Log in'), button:has-text('LOGIN'), a:has-text('LOGIN'), button:has-text('Sign in'), a:has-text('Sign in')"
            ).filter(has_not_text="Sign up")
            for i in range(await login_btns.count()):
                if await login_btns.nth(i).is_visible():
                    return True
        except Exception:
            pass

        return False

    async def highlight_and_click(self, locator, delay_after: float = 1.5):
        """Highlights a DOM element with a glowing red highlight before clicking it (with forced overlay fallback)."""
        try:
            if await locator.is_visible():
                await locator.evaluate("""el => {
                    el.style.outline = '4px solid #FF0055';
                    el.style.boxShadow = '0 0 20px #FF0055';
                    el.style.transition = 'all 0.2s ease-in-out';
                }""")
                await asyncio.sleep(0.4)
                try:
                    await locator.click(timeout=3000)
                except Exception:
                    # Fallback to forced click if modal overlay intercepts pointer events
                    await locator.click(force=True, timeout=3000)
                await asyncio.sleep(delay_after)
                return True
        except Exception as e:
            logger.debug(f"Click warning ({e})")
        return False

    async def scroll_page(self, max_scroll_px: int = 2500):
        """Smoothly scrolls down the page to trigger lazy loading of images and links."""
        try:
            await self.page.evaluate(f"""async () => {{
                await new Promise((resolve) => {{
                    let totalHeight = 0;
                    let distance = 350;
                    let timer = setInterval(() => {{
                        let scrollHeight = document.body.scrollHeight;
                        window.scrollBy(0, distance);
                        totalHeight += distance;
                        if(totalHeight >= scrollHeight || totalHeight >= {max_scroll_px}){{
                            clearInterval(timer);
                            resolve();
                        }}
                    }}, 100);
                }});
            }}""")
            await asyncio.sleep(1.0)
        except Exception:
            pass

    async def run_investigation(
        self,
        target_url: str,
        investigation_id: str,
        log_callback: Optional[Callable[[str, str], None]] = None,
        auth_callback: Optional[Callable[[], None]] = None,
        progress_callback: Optional[Callable[[str], None]] = None,
        auth_user: str = "",
        auth_pass: str = "",
        auth_mode: str = "Auto-Detect",
        allow_manual_auth: bool = True,
    ) -> Dict[str, Any]:
        """
        Executes the full automated evidence collection workflow (Steps 3-11).
        """
        start_time = time.time()
        nav_engine = NavigationEngine(target_url)
        visited_urls: Set[str] = set()
        queue: List[Dict[str, str]] = []

        self.db.create_investigation(investigation_id, target_url)
        self._log(
            log_callback,
            investigation_id,
            f"Started investigation for {target_url}",
            "INFO",
        )

        deposit_inspected = False
        login_completed = False

        try:
            await self.init_browser()

            # Step 3: Launch Playwright & Open Homepage (LoadRoot Phase)
            self._log(log_callback, investigation_id, "Opening Homepage...", "INFO")
            try:
                await self.page.goto(
                    target_url,
                    wait_until="domcontentloaded",
                    timeout=DEFAULT_RENDER_TIMEOUT,
                )
            except Exception as goto_err:
                self._log(
                    log_callback,
                    investigation_id,
                    f"Initial page load warning ({goto_err}). Proceeding with current DOM...",
                    "WARNING",
                )
            await asyncio.sleep(2.5)  # Wait for dynamic rendering

            homepage_url = self.page.url
            homepage_html = await self.get_stable_page_content()

            # --- ROOT-LEVEL AUTHENTICATION CHECK ---
            try:
                # Prioritize Log In buttons, strictly avoiding "Sign up"
                login_btn = (
                    self.page.locator(
                        "button:has-text('Log in'), a:has-text('Log in'), button:has-text('LOGIN'), a:has-text('LOGIN'), button:has-text('Sign in'), a:has-text('Sign in'), text=/^Log in$/i, text=/^LOGIN$/i, text=/^Sign in$/i"
                    )
                    .filter(has_not_text="Sign up")
                    .first
                )
                if await login_btn.is_visible() and (
                    allow_manual_auth or (auth_user and auth_pass)
                ):
                    self._log(
                        log_callback,
                        investigation_id,
                        "Found visible 'Log in' button on homepage. Clicking with visual highlight...",
                        "INFO",
                    )
                    await self.highlight_and_click(login_btn, delay_after=2.0)
            except Exception:
                pass

            page_html = await self.get_stable_page_content()
            page_url = self.page.url

            if await self.check_login_required(self.page, page_html, page_url):
                self._log(
                    log_callback,
                    investigation_id,
                    "🔑 Login Required detected on homepage!",
                    "WARNING",
                )
                auto_login_success = False

                if auth_user and auth_pass:
                    self._log(
                        log_callback,
                        investigation_id,
                        f"🔑 Credentials provided for '{auth_user}'! Executing automated login...",
                        "INFO",
                    )
                    try:
                        # Wait up to 10s for login form inputs to dynamically mount in DOM
                        try:
                            self._log(
                                log_callback,
                                investigation_id,
                                "Waiting for login form input fields to render...",
                                "INFO",
                            )
                            await self.page.wait_for_selector(
                                "input[name='phone'], input[type='tel'], input[type='password'], input[type='text']",
                                state="visible",
                                timeout=10000,
                            )
                            self._log(
                                log_callback,
                                investigation_id,
                                "✅ Login form inputs detected in DOM!",
                                "INFO",
                            )
                        except Exception as wait_err:
                            self._log(
                                log_callback,
                                investigation_id,
                                f"Input render wait warning: {wait_err}",
                                "WARNING",
                            )

                        await asyncio.sleep(1.0)

                        clean_digits = "".join(filter(str.isdigit, auth_user))
                        is_email = "@" in auth_user or auth_mode == "Email"
                        is_phone = (auth_mode == "Phone / Mobile Number") or (
                            len(clean_digits) >= 10 and not is_email
                        )

                        # Format fill_val with country code '91' for Indian mobile numbers
                        if is_phone:
                            if len(clean_digits) == 10:
                                fill_val = "91" + clean_digits
                            elif len(clean_digits) == 12 and clean_digits.startswith(
                                "91"
                            ):
                                fill_val = clean_digits
                            else:
                                fill_val = clean_digits
                        else:
                            fill_val = auth_user.strip()

                        # Attempt to fill user/phone input with retries
                        user_filled = False
                        pass_filled = False

                        for attempt in range(3):
                            # Check if phone input is ALREADY visible (Default on Parimatch & major gaming portals)
                            phone_direct = self.page.locator(
                                "input[name='phone'], input[type='tel']"
                            ).first
                            phone_already_visible = False
                            try:
                                if await phone_direct.is_visible():
                                    phone_already_visible = True
                            except Exception:
                                pass

                            # Sub-tab switching ONLY if required input is not already visible
                            if not phone_already_visible and attempt == 0:
                                # If we are accidentally on a "Sign Up" modal, try to click the "Log in" toggle first
                                try:
                                    login_toggle = (
                                        self.page.locator(
                                            "a:has-text('Log in'), button:has-text('Log in'), div:has-text('Log in')"
                                        )
                                        .filter(has_not_text="Sign up")
                                        .first
                                    )
                                    if await login_toggle.is_visible():
                                        await self.highlight_and_click(
                                            login_toggle, delay_after=1.0
                                        )
                                except Exception:
                                    pass

                                if is_phone:
                                    try:
                                        phone_tab = self.page.locator(
                                            "text=/^Phone number$/i, span:has-text('Phone number')"
                                        ).first
                                        if await phone_tab.is_visible():
                                            await self.highlight_and_click(
                                                phone_tab, delay_after=1.0
                                            )
                                    except Exception:
                                        pass
                                elif is_email:
                                    try:
                                        email_tab = self.page.locator(
                                            "text=/E-mail|Email/i"
                                        ).first
                                        if await email_tab.is_visible():
                                            await self.highlight_and_click(
                                                email_tab, delay_after=1.0
                                            )
                                    except Exception:
                                        pass

                            # Locate user/phone input
                            user_inputs = self.page.locator(
                                "input[type='email'], input[name='phone'], input[type='tel'], input[name*='user' i], input[name*='login' i], input[name*='phone' i], input[name*='email' i], input[placeholder*='XXXX' i], input[placeholder*='number' i], input[placeholder*='Phone' i], input[type='text']"
                            )
                            for i in range(await user_inputs.count()):
                                target = user_inputs.nth(i)
                                if await target.is_visible():
                                    try:
                                        self._log(
                                            log_callback,
                                            investigation_id,
                                            f"Filling credential input with '{fill_val}'...",
                                            "INFO",
                                        )
                                        await target.evaluate(
                                            "el => el.style.outline = '4px solid #00FF66'"
                                        )
                                        await target.click(
                                            force=True, timeout=2000
                                        )  # Force click to bypass overlays
                                        await target.fill(
                                            ""
                                        )  # Clear input first to prevent double-typing
                                        await asyncio.sleep(
                                            0.3
                                        )  # Human pause before typing
                                        await target.press_sequentially(
                                            fill_val, delay=150
                                        )  # Slow, human-like typing
                                        await asyncio.sleep(0.5)
                                        user_filled = True
                                        break
                                    except Exception as e:
                                        logger.debug(f"Failed to fill user input: {e}")

                            # Locate password input
                            pass_inputs = self.page.locator(
                                "input[type='password'], input[name='password'], input[name*='pass' i], input[placeholder*='Password' i]"
                            )
                            for i in range(await pass_inputs.count()):
                                target = pass_inputs.nth(i)
                                if await target.is_visible():
                                    try:
                                        self._log(
                                            log_callback,
                                            investigation_id,
                                            "Filling password input...",
                                            "INFO",
                                        )
                                        await target.evaluate(
                                            "el => el.style.outline = '4px solid #00FF66'"
                                        )
                                        await target.click(force=True, timeout=2000)
                                        await target.fill(
                                            ""
                                        )  # Clear input first to prevent double-typing
                                        await asyncio.sleep(
                                            0.3
                                        )  # Human pause before typing
                                        await target.press_sequentially(
                                            auth_pass, delay=150
                                        )  # Slow, human-like typing
                                        await asyncio.sleep(0.5)
                                        await target.press(
                                            "Enter"
                                        )  # Bulletproof form submission fallback
                                        await asyncio.sleep(0.5)
                                        pass_filled = True
                                        break
                                    except Exception as e:
                                        logger.debug(f"Failed to fill password: {e}")

                            if user_filled and pass_filled:
                                # Auto-check any login consent checkboxes (e.g. age agreement on Fun88)
                                try:
                                    chkboxes = self.page.locator(
                                        "input[type='checkbox']"
                                    )
                                    for c_idx in range(await chkboxes.count()):
                                        chk = chkboxes.nth(c_idx)
                                        if (
                                            await chk.is_visible()
                                            and not await chk.is_checked()
                                        ):
                                            await chk.check()
                                            self._log(
                                                log_callback,
                                                investigation_id,
                                                "Checked login consent checkbox.",
                                                "INFO",
                                            )
                                except Exception:
                                    pass
                                break

                            self._log(
                                log_callback,
                                investigation_id,
                                f"Auto-fill attempt #{attempt+1} waiting for DOM elements...",
                                "WARNING",
                            )
                            await asyncio.sleep(1.5)

                        if user_filled and pass_filled:
                            self._log(
                                log_callback,
                                investigation_id,
                                "Submitting login form...",
                                "INFO",
                            )
                            submit_locs = self.page.locator(
                                "button:has-text('Log in'), button:has-text('LOGIN'), button:has-text('Sign in'), button[type='submit'], input[type='submit']"
                            )
                            submit_clicked = False
                            for s_idx in range(await submit_locs.count()):
                                btn = submit_locs.nth(s_idx)
                                if await btn.is_visible():
                                    submit_clicked = await self.highlight_and_click(
                                        btn, delay_after=4.0
                                    )
                                    if submit_clicked:
                                        break

                            if not submit_clicked:
                                self._log(
                                    log_callback,
                                    investigation_id,
                                    "No visible submit button found. Relying on 'Enter' key press...",
                                    "INFO",
                                )
                                await asyncio.sleep(2.0)

                            # Detect on-screen authentication error/status messages (e.g. Invalid User ID, wrong password)
                            try:
                                error_msg_locator = self.page.locator(
                                    "text=/invalid|incorrect|wrong|does not exist|failed|error/i"
                                ).first
                                if await error_msg_locator.is_visible():
                                    err_txt = await error_msg_locator.text_content()
                                    clean_err = (
                                        err_txt.strip()
                                        if err_txt
                                        else "Unknown Authentication Error"
                                    )
                                    self._log(
                                        log_callback,
                                        investigation_id,
                                        f"⚠️ Website Auth Alert: '{clean_err}'",
                                        "WARNING",
                                    )
                            except Exception:
                                pass

                            if not await self.check_login_required(
                                self.page, await self.get_stable_page_content(), self.page.url
                            ):
                                self._log(
                                    log_callback,
                                    investigation_id,
                                    f"✅ Automated login successful for '{auth_user}'!",
                                    "INFO",
                                )
                                auto_login_success = True
                            else:
                                self._log(
                                    log_callback,
                                    investigation_id,
                                    f"❌ Automated login failed! Login form is still present.",
                                    "WARNING",
                                )
                                auto_login_success = False
                    except Exception as auto_err:
                        self._log(
                            log_callback,
                            investigation_id,
                            f"Auto-login failed ({auto_err}). Falling back to manual auth...",
                            "WARNING",
                        )

                if not auto_login_success:
                    if not allow_manual_auth:
                        self._log(
                            log_callback,
                            investigation_id,
                            "Login is available, but this unattended job will continue with public pages only.",
                            "INFO",
                        )
                    else:
                        self._log(
                            log_callback,
                            investigation_id,
                            f"🔑 Manual Login Required! Please log in in the browser window on screen...",
                            "WARNING",
                        )
                        try:
                            await self.page.bring_to_front()
                        except Exception:
                            pass

                        self.pause_for_auth = True
                        if auth_callback:
                            auth_callback()
                        self.auth_resumed.clear()

                        while self.pause_for_auth and not self.stop_requested:
                            if self.auth_resumed.is_set():
                                self._log(
                                    log_callback,
                                    investigation_id,
                                    "Verifying manual login state before resuming...",
                                    "INFO",
                                )
                                try:
                                    if not await self.check_login_required(
                                        self.page, await self.get_stable_page_content(), self.page.url
                                    ):
                                        self._log(
                                            log_callback,
                                            investigation_id,
                                            f"✅ Manual login strictly verified! Resuming crawl...",
                                            "INFO",
                                        )
                                        self.pause_for_auth = False
                                        break
                                    else:
                                        self._log(
                                            log_callback,
                                            investigation_id,
                                            f"❌ Manual login failed! Form still present. Please log in.",
                                            "WARNING",
                                        )
                                        self.auth_resumed.clear()  # Block resumption and pause again
                                except Exception:
                                    pass
                            await asyncio.sleep(1)

            login_completed = True
            self._log(
                log_callback,
                investigation_id,
                "🔐 Login phase complete. Login checks & login page visits disabled for rest of crawl.",
                "INFO",
            )
            await asyncio.sleep(2.0)

            # Prevent crawler from ever visiting login/auth pages during deep crawl
            login_terms = ["/login", "/signin", "/auth", "/register", "/signup"]

            # Navigate back to root target_url to ensure we start crawl from homepage, not a login callback URL
            try:
                self._log(
                    log_callback,
                    investigation_id,
                    f"Navigating back to root URL ({target_url}) to start deep crawl...",
                    "INFO",
                )
                await self.page.goto(
                    target_url,
                    wait_until="domcontentloaded",
                    timeout=DEFAULT_RENDER_TIMEOUT,
                )
                await asyncio.sleep(2.5)
            except Exception as nav_err:
                pass

            homepage_url = target_url
            homepage_html = await self.get_stable_page_content()

            # Add homepage as initial target
            queue.append(
                {"url": homepage_url, "anchor_text": "Homepage", "priority": "High"}
            )

            # Step 7: Investigate Pages in Priority Queue
            pages_visited_count = 0

            while queue and pages_visited_count < self.max_pages:
                if self.stop_requested:
                    self._log(
                        log_callback,
                        investigation_id,
                        "Investigation manually stopped by user.",
                        "WARNING",
                    )
                    break

                target = queue.pop(0)
                page_url = target["url"]
                priority = target["priority"]

                # Skip visited URLs or login/auth pages post-login
                if page_url in visited_urls or (
                    login_completed
                    and any(term in page_url.lower() for term in login_terms)
                ):
                    continue

                visited_urls.add(page_url)
                pages_visited_count += 1

                self._log(
                    log_callback,
                    investigation_id,
                    f"[{pages_visited_count}/{self.max_pages}] Deep Crawl ({priority}): {page_url}",
                    "INFO",
                )

                try:
                    if page_url != self.page.url:
                        try:
                            await self.page.goto(
                                page_url,
                                wait_until="domcontentloaded",
                                timeout=DEFAULT_RENDER_TIMEOUT,
                            )
                        except Exception as p_err:
                            self._log(
                                log_callback,
                                investigation_id,
                                f"Navigation timeout on {page_url}, proceeding with available DOM...",
                                "WARNING",
                            )
                        await asyncio.sleep(1.5)

                    # Smooth scroll page down to lazy load content and footer links
                    await self.scroll_page(max_scroll_px=2000)

                    page_title = await self.page.title() or page_url
                    page_html = await self.get_stable_page_content()

                    # --- MID-CRAWL SECURITY GUARD ---
                    if login_completed and allow_manual_auth:
                        if await self.check_login_required(
                            self.page, page_html, page_url
                        ):
                            self._log(
                                log_callback,
                                investigation_id,
                                f"⚠️ Mid-Crawl Alert: Session lost or login modal detected on {page_url}!",
                                "WARNING",
                            )
                            self.pause_for_auth = True
                            if auth_callback:
                                auth_callback()
                            self.auth_resumed.clear()

                            while self.pause_for_auth and not self.stop_requested:
                                if self.auth_resumed.is_set():
                                    try:
                                        if not await self.check_login_required(
                                            self.page,
                                            await self.get_stable_page_content(),
                                            self.page.url,
                                        ):
                                            self._log(
                                                log_callback,
                                                investigation_id,
                                                "✅ Session restored! Resuming deep crawl...",
                                                "INFO",
                                            )
                                            self.pause_for_auth = False
                                            page_html = (
                                                await self.get_stable_page_content()
                                            )  # Refresh HTML after login
                                            break
                                        else:
                                            self.auth_resumed.clear()
                                    except Exception:
                                        pass
                                await asyncio.sleep(1)

                    if self.stop_requested:
                        break

                    # Deep Deposit & Payment QR Code Inspection Flow (Runs ONCE post-login)
                    if login_completed and not deposit_inspected:
                        try:
                            deposit_selector = "button:has-text('Deposit'), a:has-text('Deposit'), button:has-text('Recharge'), a:has-text('Recharge'), button:has-text('Cashier'), a:has-text('Cashier'), button:has-text('Add Money')"
                            deposit_btn = self.page.locator(deposit_selector).first
                            if await deposit_btn.is_visible():
                                deposit_inspected = True
                                self._log(
                                    log_callback,
                                    investigation_id,
                                    f"Navigating to Deposit section to inspect payment options & QR codes...",
                                    "INFO",
                                )
                                await self.highlight_and_click(
                                    deposit_btn, delay_after=2.5
                                )

                                # Locate and click UPI / Paytm / PhonePe method card
                                upi_card_selectors = [
                                    "div:has-text('UPI'):not(:has(*))",
                                    "div:has-text('Pay Tm'):not(:has(*))",
                                    "div:has-text('Paytm'):not(:has(*))",
                                    "div:has-text('Phone Pe'):not(:has(*))",
                                    "text=/UPI|Pay Tm|Paytm|Phone Pe/i",
                                ]

                                payment_clicked = False
                                for sel in upi_card_selectors:
                                    try:
                                        card = self.page.locator(sel).first
                                        if await card.is_visible():
                                            self._log(
                                                log_callback,
                                                investigation_id,
                                                f"Clicking Payment Method card: '{sel}'...",
                                                "INFO",
                                            )
                                            await self.highlight_and_click(
                                                card, delay_after=2.0
                                            )
                                            payment_clicked = True
                                            break
                                    except Exception:
                                        continue

                                # Handle amount or Continue button
                                if payment_clicked:
                                    try:
                                        amount_btn = self.page.locator(
                                            "button:has-text('500'), button:has-text('1000'), div:has-text('500')"
                                        ).first
                                        if await amount_btn.is_visible():
                                            await self.highlight_and_click(
                                                amount_btn, delay_after=1.0
                                            )

                                        submit_pay_btn = self.page.locator(
                                            "button:has-text('Continue'), button:has-text('Deposit'), button:has-text('Pay')"
                                        ).first
                                        if await submit_pay_btn.is_visible():
                                            self._log(
                                                log_callback,
                                                investigation_id,
                                                "Clicking 'Continue/Deposit' to generate active QR code & UPI VPA...",
                                                "INFO",
                                            )
                                            await self.highlight_and_click(
                                                submit_pay_btn, delay_after=3.0
                                            )
                                    except Exception as sub_err:
                                        logger.debug(f"Amount submit error: {sub_err}")

                                page_url = self.page.url
                                page_html = await self.get_stable_page_content()
                                page_title = (
                                    await self.page.title() or "Deposit Payment Page"
                                )
                        except Exception as dep_err:
                            logger.debug(f"Deposit flow error: {dep_err}")

                    # Step 4 & 5: Dynamic Queue Expansion (Extract & Prioritize High -> Medium -> Low links)
                    new_discovered = nav_engine.extract_and_prioritize_links(
                        page_html, page_url
                    )
                    for link in new_discovered:
                        u_lower = link["url"].lower()
                        if login_completed and any(
                            term in u_lower for term in login_terms
                        ):
                            continue
                        if link["url"] not in visited_urls and link["url"] not in [
                            q["url"] for q in queue
                        ]:
                            queue.append(link)

                    # Re-sort queue by priority: High -> Medium -> Low
                    priority_rank = {"High": 1, "Medium": 2, "Low": 3}
                    queue.sort(key=lambda x: priority_rank.get(x["priority"], 2))

                    # Save Page Record
                    page_id = self.db.add_page(
                        investigation_id, page_url, page_title, priority
                    )

                    # Save Navigation Link Graph
                    self.db.add_navigation_link(
                        investigation_id,
                        homepage_url if pages_visited_count > 1 else "ROOT",
                        page_url,
                        1 if pages_visited_count > 1 else 0,
                    )

                    # Step 8: Keyword Detection
                    keyword_findings = (
                        await self.keyword_detector.detect_and_locate_keywords(
                            self.page
                        )
                    )
                    if keyword_findings:
                        self.db.add_keyword_findings(page_id, keyword_findings)

                    # Step 10: Payment Detection
                    payment_findings = (
                        await self.payment_detector.detect_payment_indicators(
                            self.page, page_html
                        )
                    )
                    if payment_findings:
                        self.db.add_payment_findings(page_id, payment_findings)

                    # Step 9: Screenshot Capture & OpenCV Annotation
                    raw_screenshot = await self.page.screenshot(full_page=False)
                    screenshot_filename = f"inv_{investigation_id}_page_{page_id}.png"

                    highlighted_path = ImageAnnotator.annotate_and_save_screenshot(
                        raw_screenshot,
                        screenshot_filename,
                        keyword_findings,
                        payment_findings,
                    )

                    self.db.add_screenshot(page_id, highlighted_path)

                except Exception as page_err:
                    self._log(
                        log_callback,
                        investigation_id,
                        f"Error investigating {page_url}: {page_err}",
                        "ERROR",
                    )

            # Finalize Investigation Status
            status = "STOPPED" if self.stop_requested else "COMPLETED"
            duration = time.time() - start_time
            self.db.update_investigation(
                investigation_id, status, duration, pages_visited_count, login_completed
            )
            self._log(
                log_callback,
                investigation_id,
                f"Investigation {status}. Total pages: {pages_visited_count}, Duration: {duration:.2f}s",
                "INFO",
            )

            return {
                "status": status,
                "investigation_id": investigation_id,
                "total_pages": pages_visited_count,
                "duration": duration,
            }

        except Exception as err:
            self._log(
                log_callback,
                investigation_id,
                f"Fatal Investigation Error: {err}",
                "ERROR",
            )
            self.db.update_investigation(
                investigation_id, "FAILED", time.time() - start_time, 0, login_completed
            )
            return {
                "status": "FAILED",
                "error": str(err),
                "investigation_id": investigation_id,
            }
        finally:
            await self.close_browser()

    def _log(
        self,
        callback: Optional[Callable[[str, str], None]],
        inv_id: str,
        action: str,
        status: str,
    ):
        self.db.log_action(inv_id, action, status)
        if callback:
            callback(action, status)
