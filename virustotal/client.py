from __future__ import annotations

import base64
from datetime import datetime, timezone
import ipaddress
import re
from urllib.parse import quote, urlsplit

import requests
from core.time_utils import now_ist


class VirusTotalError(RuntimeError):
    """A safe, user-facing VirusTotal API error."""


def classify_target(value: str) -> tuple[str, str, str]:
    raw = value.strip()
    if not raw:
        raise ValueError("Enter a domain, URL, IP address, or file hash.")
    if raw.startswith(("http://", "https://")):
        parsed = urlsplit(raw)
        if not parsed.hostname:
            raise ValueError("Enter a valid HTTP or HTTPS URL.")
        object_id = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
        return "url", raw, object_id
    try:
        address = str(ipaddress.ip_address(raw))
        return "ip_address", address, address
    except ValueError:
        pass
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", raw):
        return "file", raw.lower(), raw.lower()
    domain = raw.lower().rstrip(".")
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
        raise ValueError("Enter a valid domain, URL, IP address, or MD5/SHA-1/SHA-256 hash.")
    return "domain", domain, domain


class VirusTotalClient:
    BASE_URL = "https://www.virustotal.com/api/v3"
    COLLECTIONS = {"domain": "domains", "url": "urls", "ip_address": "ip_addresses", "file": "files"}

    def __init__(self, api_key: str, *, timeout: int = 20, session=None):
        self.api_key = api_key.strip()
        self.timeout = timeout
        self.session = session or requests.Session()
        if not self.api_key:
            raise ValueError("VIRUSTOTAL_API_KEY is not configured.")

    def lookup(self, value: str) -> dict:
        target_type, normalized, object_id = classify_target(value)
        endpoint = f"{self.BASE_URL}/{self.COLLECTIONS[target_type]}/{quote(object_id, safe='')}"
        try:
            params = None
            if target_type == "domain":
                # Include lightweight relationship descriptors in the same API call.
                # This avoids multiplying requests against the Community API quota.
                params = {"relationships": "resolutions,subdomains"}
            response = self.session.get(
                endpoint,
                headers={"x-apikey": self.api_key, "accept": "application/json"},
                params=params,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise VirusTotalError(f"VirusTotal could not be reached: {exc}") from exc
        if response.status_code == 401:
            raise VirusTotalError("VirusTotal rejected the API key.")
        if response.status_code == 404:
            raise VirusTotalError("VirusTotal has no existing report for this target.")
        if response.status_code == 429:
            raise VirusTotalError("VirusTotal API quota or rate limit was reached. Try again later.")
        try:
            payload = response.json()
        except ValueError as exc:
            raise VirusTotalError("VirusTotal returned an invalid response.") from exc
        if not response.ok:
            message = payload.get("error", {}).get("message") or f"HTTP {response.status_code}"
            raise VirusTotalError(f"VirusTotal request failed: {message}")
        return normalize_vt_report(normalized, target_type, object_id, payload)


def _utc_timestamp(value) -> str | None:
    if not isinstance(value, (int, float)):
        return None
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat(timespec="seconds")


def normalize_vt_report(target: str, target_type: str, object_id: str, payload: dict) -> dict:
    data = payload.get("data") or {}
    attributes = data.get("attributes") or {}
    detections = []
    for engine, result in (attributes.get("last_analysis_results") or {}).items():
        category = str(result.get("category") or "unknown")
        if category in {"malicious", "suspicious"}:
            detections.append({"engine": result.get("engine_name") or engine, "category": category, "result": result.get("result") or "", "method": result.get("method") or ""})
    gui_type = "ip-address" if target_type == "ip_address" else target_type
    resolved_id = data.get("id") or object_id
    relationships = {}
    for name, relationship in (data.get("relationships") or {}).items():
        related_data = relationship.get("data") if isinstance(relationship, dict) else None
        if isinstance(related_data, dict):
            related_data = [related_data]
        relationships[name] = {
            "count": ((relationship.get("meta") or {}).get("count") if isinstance(relationship, dict) else None),
            "items": [
                {
                    "id": related.get("id"),
                    "type": related.get("type"),
                    "attributes": related.get("attributes") or {},
                }
                for related in (related_data or [])
                if isinstance(related, dict)
            ],
        }
    return {
        "target": target, "target_type": target_type, "object_id": resolved_id,
        "permalink": f"https://www.virustotal.com/gui/{gui_type}/{quote(str(resolved_id), safe='')}",
        "retrieved_at": now_ist().isoformat(timespec="seconds"),
        "analysis_stats": attributes.get("last_analysis_stats") or {},
        "reputation": attributes.get("reputation"), "categories": attributes.get("categories") or {},
        "tags": attributes.get("tags") or [], "registrar": attributes.get("registrar"),
        "network": attributes.get("network"), "country": attributes.get("country"),
        "as_owner": attributes.get("as_owner"),
        "creation_date": _utc_timestamp(attributes.get("creation_date")),
        "last_modification_date": _utc_timestamp(attributes.get("last_modification_date")),
        "last_update_date": _utc_timestamp(attributes.get("last_update_date")),
        "whois_date": _utc_timestamp(attributes.get("whois_date")),
        "last_dns_records_date": _utc_timestamp(attributes.get("last_dns_records_date")),
        "last_https_certificate_date": _utc_timestamp(attributes.get("last_https_certificate_date")),
        "last_analysis_date": _utc_timestamp(attributes.get("last_analysis_date")),
        "first_submission_date": _utc_timestamp(attributes.get("first_submission_date")),
        "last_submission_date": _utc_timestamp(attributes.get("last_submission_date")),
        "dns_records": attributes.get("last_dns_records") or [],
        "https_certificate": attributes.get("last_https_certificate") or {},
        "whois": attributes.get("whois") or "",
        "total_votes": attributes.get("total_votes") or {},
        "popularity_ranks": attributes.get("popularity_ranks") or {},
        "jarm": attributes.get("jarm"),
        "relationships": relationships,
        "detections": detections,
        "raw_response": payload,
    }


def expand_stored_report(report: dict) -> dict:
    """Backfill newly supported fields from a report's persisted raw response."""
    payload = report.get("raw_response")
    if not isinstance(payload, dict) or not payload.get("data"):
        return report
    expanded = normalize_vt_report(
        report.get("target") or str((payload.get("data") or {}).get("id") or ""),
        report.get("target_type") or str((payload.get("data") or {}).get("type") or "domain"),
        report.get("object_id") or str((payload.get("data") or {}).get("id") or ""),
        payload,
    )
    expanded.update(report)
    return expanded
