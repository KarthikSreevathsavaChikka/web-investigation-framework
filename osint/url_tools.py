from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import tldextract


_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
TRACKING_PARAMETERS = {
    "fbclid",
    "gclid",
    "msclkid",
    "ref",
    "referrer",
    "source",
}


def registrable_domain(hostname: str) -> str:
    extracted = _extract(hostname.lower().strip("."))
    if not extracted.domain or not extracted.suffix:
        return hostname.lower().strip(".")
    return f"{extracted.domain}.{extracted.suffix}"


def normalize_result_url(url: str) -> str:
    parsed = urlsplit(url.strip())
    scheme = parsed.scheme.lower() if parsed.scheme else "https"
    hostname = (parsed.hostname or "").lower().strip(".")
    if not hostname:
        raise ValueError("Search result URL has no hostname.")
    port = f":{parsed.port}" if parsed.port and not (scheme == "https" and parsed.port == 443) else ""
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    query = urlencode(
        [
            (key, value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
            if key.lower() not in TRACKING_PARAMETERS and not key.lower().startswith("utm_")
        ],
        doseq=True,
    )
    return urlunsplit((scheme, f"{hostname}{port}", path, query, ""))
