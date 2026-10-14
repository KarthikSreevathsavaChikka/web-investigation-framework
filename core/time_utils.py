from __future__ import annotations

from datetime import datetime, timezone
import re
from zoneinfo import ZoneInfo


IST = ZoneInfo("Asia/Kolkata")
IST_DISPLAY_FORMAT = "%d-%m-%Y %H:%M:%S IST"


def now_ist() -> datetime:
    return datetime.now(IST)


def parse_timestamp(value: str | datetime | None) -> datetime | None:
    if value in {None, ""}:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        if not text:
            return None
        if re.fullmatch(r"\d{4}-\d{2}(-\d{2})?", text):
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def format_ist(value: str | datetime | None, *, fallback: str = "Unavailable") -> str:
    """Format an ISO timestamp as a 24-hour Indian Standard Time value."""
    parsed = parse_timestamp(value)
    if parsed is None:
        return str(value).strip() if value not in {None, ""} else fallback
    return parsed.astimezone(IST).strftime(IST_DISPLAY_FORMAT)
