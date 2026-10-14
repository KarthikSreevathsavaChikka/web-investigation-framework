"""Bounded worker-side checks; configuration is never called authenticated access."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import requests
from bs4 import BeautifulSoup

from core.time_utils import now_ist
from osint.cancellation import InvestigationCancelled
from osint.evidence_capture import classify_page_access
from osint.http import ResponseTooLargeError, get_public_url
from osint.models import CollectorResult, Observation


def session_readiness(path: Path) -> dict:
    try:
        if not path.is_file():
            return {"status": "unavailable", "reason": "Session file missing. Complete browser login and save the session."}
        if path.stat().st_size > 2_000_000:
            raise ValueError("Session file exceeds the supported size")
        state = json.loads(path.read_text())
        if not isinstance(state, dict) or not isinstance(state.get("cookies", []), list) or not isinstance(state.get("origins", []), list):
            raise ValueError("Invalid browser state structure")
        if not state.get("cookies") and not state.get("origins"):
            raise ValueError("Saved browser state is empty")
        for cookie in state.get("cookies", []):
            if not isinstance(cookie, dict) or not all(isinstance(cookie.get(key), str) for key in ("name", "value")):
                raise ValueError("Invalid cookie entry")
        for origin in state.get("origins", []):
            if not isinstance(origin, dict) or not isinstance(origin.get("origin"), str) or not isinstance(origin.get("localStorage", []), list):
                raise ValueError("Invalid origin entry")
            for item in origin.get("localStorage", []):
                if not isinstance(item, dict) or not all(isinstance(item.get(key), str) for key in ("name", "value")):
                    raise ValueError("Invalid local storage entry")
        return {"status": "configured", "reason": "Saved state found; the collector must verify live access before extracting posts."}
    except (OSError, ValueError, TypeError):
        return {"status": "unavailable", "reason": "Session file is unreadable, empty or invalid. Save a new browser session."}


def llm_readiness() -> dict:
    base = os.getenv("LM_STUDIO_BASE_URL", "http://10.244.1.54:1234").rstrip("/")
    try:
        parsed = urlsplit(base)
        parsed.port
    except ValueError:
        return {"status": "unavailable", "reason": "Invalid LM Studio server address."}
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        return {"status": "unavailable", "reason": "Invalid LM Studio server address."}
    path = parsed.path.removesuffix("/chat/completions").rstrip("/")
    if not path.endswith("/v1"):
        path += "/v1"
    endpoint = urlunsplit((parsed.scheme, parsed.netloc, path + "/models", "", ""))
    headers = {}
    if key := os.getenv("LM_STUDIO_API_KEY"):
        headers["Authorization"] = "Bearer " + key
    try:
        with requests.get(endpoint, headers=headers, timeout=3, allow_redirects=False) as response:
            if response.status_code != 200:
                return {"status": "unavailable", "reason": f"Model listing returned HTTP {response.status_code}."}
            models = response.json().get("data", [])
            model = os.getenv("LM_STUDIO_MODEL", "google/gemma-4-e4b")
            if not any(isinstance(item, dict) and item.get("id") == model for item in models):
                return {"status": "unavailable", "reason": "Configured model is absent from the server model list."}
            return {"status": "ready", "reason": "Server lists the configured model; inference is checked during review."}
    except (requests.RequestException, ValueError, TypeError, AttributeError):
        return {"status": "unavailable", "reason": "Model server could not be reached or returned an invalid model list."}


def website_readiness(target, timeout: int) -> dict:
    try:
        response = get_public_url(target.url, timeout=min(timeout, 5), max_bytes=200_000)
        try:
            soup = BeautifulSoup(response.text, "html.parser")
            for node in soup.select("script, style, template"):
                node.decompose()
            status, reason = classify_page_access(response.status_code, soup.get_text(" ", strip=True)[:4000].lower())
            if status:
                return {"status": "limited", "reason": reason or status, "http_status": response.status_code}
            if not 200 <= response.status_code < 300:
                return {"status": "limited", "reason": f"Website returned HTTP {response.status_code}.", "http_status": response.status_code}
            return {"status": "ready", "reason": "Worker received the target over HTTP; browser rendering is checked separately.", "http_status": response.status_code}
        finally:
            response.close()
    except ResponseTooLargeError:
        return {"status": "reachable", "reason": "Worker received content larger than the readiness sample; full collection will assess it."}
    except Exception as exc:
        return {"status": "limited", "reason": f"Worker website request failed ({type(exc).__name__}). Browser capture will still be attempted."}


def run_readiness(target, collectors, *, timeout=5, cancel_check=None) -> CollectorResult:
    checks = []

    def check_cancelled():
        if cancel_check and cancel_check():
            raise InvestigationCancelled("Cancelled during collection readiness checks")

    check_cancelled()
    checks.append({"component": "Target website", **website_readiness(target, timeout)})
    for collector in collectors:
        check_cancelled()
        session_path = getattr(collector, "session_path", None)
        if isinstance(session_path, Path):
            checks.append({"component": collector.name, **session_readiness(session_path)})
    check_cancelled()
    if os.getenv("OSINT_LLM_REVIEW_ENABLED", "false").lower() in {"1", "true", "yes"}:
        checks.append({"component": "AI relevance review", **llm_readiness()})
    check_cancelled()
    degraded = any(x["status"] in {"limited", "unavailable"} for x in checks)
    metadata = {"checks": checks, "selected_collectors": [x.name for x in collectors],
                "checked_at": now_ist().isoformat(), "execution_location": "investigation_worker"}
    return CollectorResult("collection_readiness", "PARTIAL" if degraded else "COMPLETED", [
        Observation("collection_readiness", "Collection diagnostics", "COLLECTION_READINESS",
                    "limited" if degraded else "ready", target.url, confidence=0.0, metadata=metadata),
    ], error="Some initial checks were limited; see readiness details. Collection will record actual outcomes." if degraded else None)
