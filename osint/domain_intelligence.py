"""Safe, non-rendering domain availability and optional traffic checks."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import date
import ipaddress
import os
import socket
import time
from typing import Callable
from urllib.parse import urlsplit

import requests

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36"
VALID_CODES = {200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403, 405, 429}


def http_status_meaning(status: str, detailed_status: str = "") -> str:
    """Return a concise analyst-facing explanation of an HTTP check result."""
    normalized = str(status or "Unavailable").strip()
    if normalized == "403":
        return "Server exists but blocks automated access, your location, or this user."
    if normalized == "401":
        return "Server exists but requires authentication."
    if normalized == "405":
        return "Server exists but does not allow the requested HTTP method."
    if normalized == "429":
        return "Server exists but is temporarily rate-limiting requests."
    if normalized in {"301", "302", "303", "307", "308"}:
        return "Server redirects requests to another URL."
    if normalized.isdigit():
        code = int(normalized)
        if 200 <= code < 300:
            if "Redirected" in detailed_status:
                return "Server responded successfully after redirecting to the final URL."
            return "Server responded successfully."
        if code == 404:
            return "Server exists, but this page was not found."
        if 400 <= code < 500:
            return "Server returned a client-request error."
        if 500 <= code < 600:
            return "Server exists but currently has a server-side error."
    meanings = {
        "DNS Failed": "Domain did not resolve in DNS.",
        "Connection Refused": "Host was reached but refused the connection.",
        "Timeout": "No response arrived before the timeout.",
        "Blocked": "The redirect destination was blocked by safety validation.",
        "Unavailable": "No conclusive HTTP response was available.",
    }
    return meanings.get(normalized, "HTTP result requires analyst review.")


@dataclass
class DomainCheck:
    domain: str
    domain_status: str = "Unknown"
    detailed_status: str = "Unknown"
    http_status: str = "Unavailable"
    final_url: str = ""
    response_time_ms: int | None = None
    error: str = ""
    checked_at: str = ""
    monthly_visits: int | None = None
    yearly_visits: int | None = None
    yearly_visits_kind: str = "Unavailable"
    traffic_source: str = "Unavailable"
    traffic_data_date: str = ""


def _public_host(host: str) -> bool:
    """Resolve and reject loopback/private/reserved targets before every request."""
    try:
        answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    for answer in answers:
        address = ipaddress.ip_address(answer[4][0])
        if not address.is_global:
            return False
    return bool(answers)


def _safe_url(url: str) -> bool:
    parsed = urlsplit(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.hostname) and _public_host(parsed.hostname)


class SimilarwebTrafficProvider:
    """Optional Similarweb API client. It never fabricates a traffic estimate."""

    name = "Similarweb"

    def __init__(self, api_key: str | None = None, request: Callable = requests.get):
        self.api_key = api_key or os.getenv("SIMILARWEB_API_KEY", "")
        self.request = request

    @property
    def available(self) -> bool:
        return bool(self.api_key) and os.getenv("TRAFFIC_PROVIDER", "").casefold() == "similarweb"

    def lookup(self, domain: str) -> dict:
        if not self.available:
            return {"traffic_source": "Unavailable"}
        try:
            response = self.request(
                f"https://api.similarweb.com/v1/website/{domain}/total-traffic-and-engagement/visits",
                params={"api_key": self.api_key, "granularity": "monthly", "main_domain_only": "false"},
                timeout=(5, 15),
            )
            if response.status_code == 429:
                return {"traffic_source": self.name, "error": "Traffic provider rate limited"}
            if response.status_code != 200:
                return {"traffic_source": self.name, "error": f"Traffic provider HTTP {response.status_code}"}
            payload = response.json()
            visits = payload.get("visits") or payload.get("data", {}).get("visits") or []
            if isinstance(visits, (int, float)):
                visits = [{"visits": visits, "date": payload.get("date", "")}]
            values = [int(item.get("visits", 0)) for item in visits if item.get("visits") is not None]
            if not values:
                return {"traffic_source": self.name, "error": "No traffic data"}
            return {
                "monthly_visits": values[-1], "yearly_visits": sum(values[-12:]) if len(values) >= 12 else values[-1] * 12,
                "yearly_visits_kind": "Actual" if len(values) >= 12 else "Projected",
                "traffic_source": self.name,
                "traffic_data_date": str(visits[-1].get("date") or ""),
            }
        except requests.RequestException as exc:
            return {"traffic_source": self.name, "error": f"Traffic provider unavailable: {exc}"}


class DomainIntelligenceService:
    def __init__(self, traffic_provider=None, request: Callable = requests.request, retries: int = 2, public_host: Callable[[str], bool] = _public_host):
        self.traffic_provider = traffic_provider or SimilarwebTrafficProvider()
        self.request = request
        self.retries = retries
        self.public_host = public_host

    def check_many(self, domains: list[str], progress: Callable[[int, int], None] | None = None, traffic_cache: dict | None = None, refresh_traffic: bool = False) -> list[DomainCheck]:
        unique = list(dict.fromkeys(domain.casefold().strip() for domain in domains if domain.strip()))
        results: list[DomainCheck] = []
        with ThreadPoolExecutor(max_workers=min(6, max(1, len(unique)))) as pool:
            futures = {pool.submit(self.check, domain, (traffic_cache or {}).get(domain), refresh_traffic): domain for domain in unique}
            for count, future in enumerate(as_completed(futures), 1):
                try:
                    results.append(future.result())
                except Exception as exc:  # one target must never stop the batch
                    results.append(DomainCheck(domain=futures[future], error=str(exc), checked_at=date.today().isoformat()))
                if progress:
                    progress(count, len(unique))
        return results

    def check(self, domain: str, cached_traffic: dict | None = None, refresh_traffic: bool = False) -> DomainCheck:
        checked = DomainCheck(domain=domain, checked_at=date.today().isoformat())
        if not self.public_host(domain):
            checked.domain_status, checked.detailed_status, checked.http_status = "Inactive", "Inactive – DNS Failure", "DNS Failed"
            return checked
        last_error = ""
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}/"
            for attempt in range(self.retries + 1):
                started = time.monotonic()
                try:
                    response = self._request_following_safe_redirects(url)
                    checked.http_status = str(response.status_code)
                    checked.final_url = response.url
                    checked.response_time_ms = round((time.monotonic() - started) * 1000)
                    checked.domain_status = "Active"
                    if response.status_code in {401, 403, 405, 429}:
                        checked.detailed_status = "Active – Access Restricted"
                    elif response.history:
                        checked.detailed_status = "Active – Redirected"
                    elif "captcha" in response.text[:4096].casefold() or "cloudflare" in response.text[:4096].casefold():
                        checked.detailed_status = "Active – CAPTCHA/WAF"
                    else:
                        checked.detailed_status = "Active"
                    response.close()
                    if cached_traffic and not refresh_traffic:
                        checked.__dict__.update({key: cached_traffic.get(key) for key in (
                            "monthly_visits", "yearly_visits", "yearly_visits_kind", "traffic_source", "traffic_data_date"
                        )})
                    else:
                        checked.__dict__.update(self.traffic_provider.lookup(domain))
                    return checked
                except requests.Timeout:
                    last_error = "Timeout"
                except requests.ConnectionError as exc:
                    last_error = str(exc)
                except ValueError as exc:
                    checked.domain_status, checked.detailed_status, checked.http_status, checked.error = "Unknown", "Unknown – Redirect blocked", "Blocked", str(exc)
                    return checked
                if attempt < self.retries:
                    time.sleep(0.15 * (attempt + 1))
        checked.error = last_error
        if last_error == "Timeout":
            checked.domain_status, checked.detailed_status, checked.http_status = "Unknown", "Unknown – Timeout", "Timeout"
        elif "refused" in last_error.casefold():
            checked.domain_status, checked.detailed_status, checked.http_status = "Inactive", "Inactive – Connection Refused", "Connection Refused"
        else:
            checked.domain_status, checked.detailed_status, checked.http_status = "Unknown", "Unknown – Network Error", "Unavailable"
        return checked

    def _request_following_safe_redirects(self, url: str):
        history = []
        for _ in range(6):
            parsed = urlsplit(url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or not self.public_host(parsed.hostname):
                raise ValueError("Redirect destination is not a public address")
            headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"}
            response = self.request("HEAD", url, headers=headers, timeout=(5, 12), allow_redirects=False, stream=True)
            if response.status_code in {405, 501}:
                response.close()
                response = self.request("GET", url, headers=headers, timeout=(5, 12), allow_redirects=False, stream=True)
            if response.is_redirect and response.headers.get("Location"):
                from urllib.parse import urljoin
                history.append(response)
                url = urljoin(url, response.headers["Location"])
                continue
            response.history = history
            response.url = url
            return response
        raise ValueError("Too many redirects")
