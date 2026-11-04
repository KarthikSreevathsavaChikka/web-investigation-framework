"""Safe, non-rendering domain availability and optional traffic checks."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone, timedelta
from decimal import Decimal, InvalidOperation
import ipaddress
import os
import socket
import time
from typing import Callable
from urllib.parse import urlsplit

from core.time_utils import now_ist, parse_timestamp
import requests
from osint.normalizer import DomainNormalizer, TargetNormalizationError

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
    traffic_status: str = "not_checked"
    traffic_error: str = ""
    traffic_refreshed_at: str = ""


TRAFFIC_FIELDS = ("monthly_visits", "yearly_visits", "yearly_visits_kind", "traffic_source",
                  "traffic_data_date", "traffic_status", "traffic_error", "traffic_refreshed_at")


def _month_shift(value: date, months: int) -> date:
    ordinal = value.year * 12 + value.month - 1 + months
    return date(ordinal // 12, ordinal % 12 + 1, 1)


def traffic_failure(status: str, reason: str, source="Similarweb") -> dict:
    return dict(monthly_visits=None, yearly_visits=None, yearly_visits_kind="Unavailable",
                traffic_source=source, traffic_data_date="", traffic_status=status,
                traffic_error=reason, error=reason,
                traffic_refreshed_at=now_ist().isoformat())


def summarize_monthly_visits(visits, *, today: date | None = None) -> dict:
    """Use dated completed months; twelve rows are not necessarily twelve months."""
    current = (today or date.today()).replace(day=1)
    monthly = {}
    if not isinstance(visits, list):
        raise ValueError("Expected a dated monthly series")
    for item in visits:
        if not isinstance(item, dict) or item.get("visits") is None:
            continue
        raw_date = str(item.get("date", ""))
        try:
            month = date.fromisoformat(raw_date[:7] + "-01")
            if month >= current:
                continue
            if isinstance(item["visits"], bool):
                raise ValueError("Boolean visit count")
            value = Decimal(str(item["visits"]))
            if not value.is_finite() or value < 0 or value > 2**63 // 12 - 1:
                raise ValueError("Invalid visit count")
            count = int(value)
        except (ValueError, InvalidOperation):
            raise ValueError("Invalid dated monthly traffic data") from None
        if month in monthly and monthly[month] != count:
            raise ValueError("Conflicting values for the same month")
        monthly[month] = count
    if not monthly:
        return traffic_failure("no_data", "The provider returned no completed-month visit estimates.")
    latest = max(monthly)
    last_year = [_month_shift(latest, -offset) for offset in range(12)]
    complete_year = all(month in monthly for month in last_year)
    return dict(monthly_visits=monthly[latest],
                yearly_visits=sum(monthly[month] for month in last_year) if complete_year else monthly[latest] * 12,
                yearly_visits_kind="12-month estimate" if complete_year else "Projected",
                traffic_source="Similarweb", traffic_data_date=latest.strftime("%Y-%m"),
                traffic_status="available", traffic_error="",
                traffic_refreshed_at=now_ist().isoformat())


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
        self.api_key = (os.getenv("SIMILARWEB_API_KEY", "") if api_key is None else api_key).strip()
        self.request = request

    @property
    def available(self) -> bool:
        return bool(self.api_key) and os.getenv("TRAFFIC_PROVIDER", "similarweb").strip().casefold() == "similarweb"

    def lookup(self, domain: str) -> dict:
        if not self.available:
            reason = "SIMILARWEB_API_KEY is missing. Configure a Similarweb API key to retrieve visit estimates." if not self.api_key else "TRAFFIC_PROVIDER must be set to similarweb."
            return traffic_failure("not_configured", reason, "Unavailable")
        response = None
        try:
            domain = DomainNormalizer.normalize(domain).domain.removeprefix("www.")
            end_month = _month_shift(date.today().replace(day=1), -1)
            response = self.request(
                f"https://api.similarweb.com/v1/website/{domain}/total-traffic-and-engagement/visits",
                params={"api_key": self.api_key, "granularity": "monthly", "main_domain_only": "false",
                        "country": "world", "format": "json", "start_date": _month_shift(end_month, -11).strftime("%Y-%m"),
                        "end_date": end_month.strftime("%Y-%m")},
                timeout=(5, 15), allow_redirects=False,
            )
            if response.status_code == 429:
                return traffic_failure("rate_limited", "Traffic provider rate limited the request. Retry later.")
            if response.status_code in {401, 403}:
                return traffic_failure("access_denied", f"Similarweb HTTP {response.status_code}: check the API key, subscription and endpoint permissions.")
            if response.status_code != 200:
                return traffic_failure("provider_error", f"Traffic provider HTTP {response.status_code}.")
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("Invalid traffic payload")
            nested = payload.get("data") if isinstance(payload.get("data"), dict) else {}
            return summarize_monthly_visits(payload.get("visits", nested.get("visits", [])))
        except TargetNormalizationError:
            return traffic_failure("invalid_domain", "Traffic lookup requires a valid domain name.")
        except (ValueError, TypeError):
            return traffic_failure("invalid_response", "Similarweb returned invalid or undated monthly estimates.")
        except requests.RequestException as exc:
            # Request exception strings may include the API key in the URL.
            return traffic_failure("unavailable", f"Traffic provider request failed ({type(exc).__name__}).")
        finally:
            if response is not None and callable(getattr(response, "close", None)):
                response.close()


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
        traffic = self.lookup_traffic(domain, cached_traffic, refresh_traffic)
        checked.__dict__.update({key: value for key, value in traffic.items() if key in TRAFFIC_FIELDS})
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

    def lookup_traffic(self, domain: str, cached: dict | None = None, refresh: bool = False) -> dict:
        usable = bool(cached and cached.get("monthly_visits") is not None and cached.get("traffic_data_date"))
        refreshed = (cached or {}).get("traffic_refreshed_at") or (cached or {}).get("refreshed_at") or ""
        fresh = False
        if usable:
            try:
                refreshed_at = parse_timestamp(refreshed)
                if refreshed_at is not None:
                    age = datetime.now(timezone.utc) - refreshed_at.astimezone(timezone.utc)
                    fresh = timedelta(0) <= age < timedelta(days=7)
            except (ValueError, TypeError):
                pass
        if usable and fresh and not refresh:
            return {**{key: cached.get(key) for key in TRAFFIC_FIELDS}, "traffic_refreshed_at": refreshed,
                    "traffic_status": "cached", "traffic_error": ""}
        try:
            result = self.traffic_provider.lookup(domain)
        except Exception as exc:
            result = traffic_failure("unavailable", f"Traffic provider failed ({type(exc).__name__}).")
        if result.get("monthly_visits") is None and usable:
            return {**{key: cached.get(key) for key in TRAFFIC_FIELDS}, "traffic_refreshed_at": refreshed,
                    "traffic_status": "stale", "traffic_error": result.get("traffic_error") or result.get("error") or "Refresh unavailable; retaining previous estimate."}
        return result

    def lookup_traffic_many(self, domains, *, traffic_cache=None, refresh=True, progress=None):
        unique = list(dict.fromkeys(domains))
        results = []
        with ThreadPoolExecutor(max_workers=min(4, max(1, len(unique)))) as pool:
            futures = {pool.submit(self.lookup_traffic, domain, (traffic_cache or {}).get(domain), refresh): domain for domain in unique}
            for count, future in enumerate(as_completed(futures), 1):
                results.append({"domain": futures[future], **future.result()})
                if progress:
                    progress(count, len(unique))
        return results

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
