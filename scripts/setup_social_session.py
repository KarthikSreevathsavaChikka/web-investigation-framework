from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path

from config import DATA_DIR
from core.playwright_session import close_browser_session, launch_browser_session


@dataclass(frozen=True)
class PlatformLogin:
    label: str
    login_url: str
    cookie_names: frozenset[str] = frozenset()
    allow_origin_storage: bool = False


PLATFORMS = {
    "reddit": PlatformLogin(
        "Reddit", "https://www.reddit.com/login/",
        frozenset({"reddit_session", "token_v2"}),
    ),
    "instagram": PlatformLogin(
        "Instagram", "https://www.instagram.com/accounts/login/",
        frozenset({"sessionid"}),
    ),
    "facebook": PlatformLogin(
        "Facebook", "https://www.facebook.com/login/",
        frozenset({"c_user"}),
    ),
    "telegram": PlatformLogin(
        "Telegram Web", "https://web.telegram.org/k/",
        allow_origin_storage=True,
    ),
    "youtube": PlatformLogin(
        "YouTube/Google", "https://accounts.google.com/ServiceLogin?service=youtube&continue=https://www.youtube.com/",
        frozenset({"SID", "SAPISID", "__Secure-1PSID", "__Secure-3PSID"}),
    ),
    "quora": PlatformLogin(
        "Quora", "https://www.quora.com/",
        frozenset({"m-b", "m-s"}),
    ),
}


def session_path(platform: str) -> Path:
    return DATA_DIR / "browser_sessions" / f"{platform}.json"


def _has_origin_state(state: dict) -> bool:
    return any(
        origin.get("localStorage") or origin.get("indexedDB")
        for origin in state.get("origins", [])
    )


async def setup_platform_session(platform: str) -> None:
    try:
        specification = PLATFORMS[platform]
    except KeyError as exc:
        raise ValueError(f"Unsupported social platform: {platform}") from exc

    destination = session_path(platform)
    destination.parent.mkdir(parents=True, exist_ok=True)
    resources = None
    try:
        resources = await launch_browser_session(
            headless=False,
            viewport={"width": 1440, "height": 1000},
        )
        page = await resources.context.new_page()
        await page.goto(
            specification.login_url,
            wait_until="domcontentloaded",
            timeout=60_000,
        )
        print(
            f"Complete {specification.label} login, OTP, CAPTCHA, and any challenge "
            "in the visible browser."
        )
        print("Do not enter credentials in this terminal or save them in the project.")
        input(
            f"After the authenticated {specification.label} home page is fully visible, "
            "return here and press Enter: "
        )

        state = await resources.context.storage_state(indexed_db=True)
        cookie_names = {cookie["name"] for cookie in state.get("cookies", [])}
        cookie_valid = bool(specification.cookie_names & cookie_names)
        storage_valid = specification.allow_origin_storage and _has_origin_state(state)
        if not cookie_valid and not storage_valid:
            expected = ", ".join(sorted(specification.cookie_names)) or "authenticated browser storage"
            raise RuntimeError(
                f"{specification.label} authentication could not be verified. Expected {expected}. "
                "Keep the browser open until the signed-in home page is fully loaded, then run this command again."
            )

        await resources.context.storage_state(path=str(destination), indexed_db=True)
        destination.chmod(0o640)
        print(
            f"{specification.label} session saved to {destination}. "
            "The application did not store your password."
        )
    finally:
        await close_browser_session(resources)


def run(platform: str) -> None:
    asyncio.run(setup_platform_session(platform))
