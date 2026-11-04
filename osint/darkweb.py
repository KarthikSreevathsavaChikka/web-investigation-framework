"""Bounded, supplied-source collection. No search-engine scraping or link crawling."""
from __future__ import annotations

import hashlib
import os
import re
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import requests
from bs4 import BeautifulSoup

from osint.cancellation import InvestigationCancelled
from osint.normalizer import DomainNormalizer
from osint.onion_urls import normalize_onion_url

MAX_BYTES = 1_000_000
SOURCE_SECONDS = 60
RUN_SECONDS = 300


def check_cancel(cancel_check):
    if cancel_check and cancel_check():
        raise InvestigationCancelled("Dark-web collection cancelled")


def fetch_onion(session, url, *, deadline, cancel_check=None):
    current = normalize_onion_url(url)
    original_host = urlsplit(current).hostname
    for _ in range(4):
        check_cancel(cancel_check)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Source time budget reached")
        session.cookies.clear()
        with session.get(current, allow_redirects=False, stream=True,
                         timeout=(min(15, remaining), min(10, remaining))) as response:
            if response.is_redirect:
                destination = normalize_onion_url(urljoin(current, response.headers.get("Location", "")))
                if urlsplit(destination).hostname != original_host:
                    raise ValueError("Redirect leaves the supplied onion host; supply the destination separately.")
                current = destination
                continue
            if response.status_code in {401, 403, 429}:
                return {"status": "restricted", "http_status": response.status_code, "final_url": current}
            response.raise_for_status()
            content_type = response.headers.get("Content-Type", "").split(";")[0].lower().strip()
            if content_type not in {"text/html", "application/xhtml+xml", "text/plain"}:
                return {"status": "unsupported_content", "final_url": current, "content_type": content_type}
            chunks, size = [], 0
            for chunk in response.iter_content(8192):
                check_cancel(cancel_check)
                size += len(chunk)
                if size > MAX_BYTES:
                    raise ValueError("Page exceeds the 1 MB collection limit")
                if time.monotonic() > deadline:
                    raise TimeoutError("Source time budget reached")
                chunks.append(chunk)
            return {"status": "retrieved", "final_url": current,
                    "http_status": response.status_code, "content_type": content_type,
                    "body": b"".join(chunks), "encoding": response.encoding or "utf-8"}
    raise ValueError("Redirect limit reached")


def extract_evidence(body, content_type, encoding, domain):
    title = ""
    if content_type == "text/plain":
        text = body.decode(encoding, errors="replace")
        links = []
        restricted = False
    else:
        soup = BeautifulSoup(body, "html.parser")
        title = soup.title.get_text(" ", strip=True)[:500] if soup.title else ""
        restricted = bool(soup.select('input[type="password"], .g-recaptcha, .h-captcha'))
        for tag in soup(["script", "style", "noscript", "template"]):
            tag.decompose()
        text = soup.get_text(" ", strip=True)
        links = [str(a.get("href", "")) for a in soup.select("a[href]")]
    # A domain embedded in a longer hostname is not an exact-domain mention.
    pattern = re.compile(r"(?<![\w.-])" + re.escape(domain) + r"(?![\w-]|\.[\w-])", re.I)
    matches = []
    for match in pattern.finditer(text):
        matches.append({"field": "text", "excerpt": text[max(0, match.start()-160):match.end()+240],
                        "start": match.start(), "end": match.end()})
        if len(matches) == 20:
            break
    for link in links:
        try:
            parsed = urlsplit(link)
            if parsed.scheme in {"http", "https"} and parsed.hostname == domain:
                matches.append({"field": "link", "excerpt": link[:2000]})
        except ValueError:
            continue
        if len(matches) >= 25:
            break
    challenge = any(term in (title + " " + text[:1000]).lower() for term in
                    ("verify you are human", "checking your browser", "complete the captcha"))
    return {"title": title, "matches": matches, "text_excerpt": text[:2000],
            "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "status": "restricted" if restricted or challenge else "matched" if matches else "no_match",
            "match_scope": "Exact target hostname in extracted text or HTTP(S) links; no identity inference"}


def collect_darkweb(payload, cancel_check=None):
    domain = DomainNormalizer.normalize(payload["target"]).domain
    sources = list(dict.fromkeys(normalize_onion_url(url) for url in payload["onion_urls"]))
    if not 1 <= len(sources) <= 10:
        raise ValueError("Supply between 1 and 10 onion URLs")
    proxy = os.getenv("DARKWEB_TOR_PROXY", "").strip()
    parsed = urlsplit(proxy)
    if parsed.scheme != "socks5h" or not parsed.hostname or not parsed.port:
        raise RuntimeError("Tor is not configured. Set DARKWEB_TOR_PROXY to a socks5h://host:port endpoint in the worker.")
    deadline = time.monotonic() + RUN_SECONDS
    rows = []
    with requests.Session() as session:
        session.trust_env = False
        session.proxies = {"http": proxy, "https": proxy}
        session.headers.update({"User-Agent": "Web-Investigator/1.0", "Accept": "text/html,text/plain"})
        for index, url in enumerate(sources):
            check_cancel(cancel_check)
            row = {"source_url": url, "retrieved_at": datetime.now(timezone.utc).isoformat(),
                   "discovery_method": "user_supplied", "matches": []}
            if time.monotonic() >= deadline:
                row.update(status="budget_exceeded", error="Collection time budget reached")
            else:
                if index:
                    time.sleep(1)
                try:
                    fetched = fetch_onion(session, url, deadline=min(deadline, time.monotonic()+SOURCE_SECONDS),
                                          cancel_check=cancel_check)
                    body = fetched.pop("body", None)
                    row.update(fetched)
                    if body is not None:
                        row["content_sha256"] = hashlib.sha256(body).hexdigest()
                        row["bytes_received"] = len(body)
                        row.update(extract_evidence(body, row["content_type"], row.pop("encoding"), domain))
                except InvestigationCancelled:
                    raise
                except (requests.RequestException, ValueError, TimeoutError, LookupError) as exc:
                    # Do not persist proxy connection details or credentials from request exceptions.
                    row.update(status="unavailable", error=(str(exc) if isinstance(exc, (ValueError, TimeoutError))
                                                          else f"{type(exc).__name__}: source could not be retrieved through Tor"))
            rows.append(row)
    successful = sum(row["status"] in {"matched", "no_match"} for row in rows)
    return {"component": "darkweb", "target": domain, "sources": rows,
            "coverage": "COMPLETED" if successful == len(rows) else "PARTIAL",
            "matched_sources": sum(row["status"] == "matched" for row in rows),
            "retrieved_sources": successful, "supplied_sources": len(rows),
            "scope": "Only supplied URLs were checked. No automatic discovery, link crawling, or JavaScript rendering. A mention does not establish ownership or wrongdoing.",
            "evidence_scope": "Stored excerpts and content hashes; raw pages are not retained."}
