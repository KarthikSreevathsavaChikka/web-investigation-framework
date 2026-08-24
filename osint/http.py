from __future__ import annotations

from urllib.parse import urljoin, urlsplit

import requests

from osint.normalizer import DomainNormalizer


class UnsafeTargetError(ValueError):
    """Raised when an HTTP target resolves outside the public internet."""


class ResponseTooLargeError(ValueError):
    """Raised when a public artifact exceeds the configured collection limit."""


def get_public_url(
    url: str,
    *,
    timeout: int,
    headers: dict[str, str] | None = None,
    max_redirects: int = 5,
    max_bytes: int | None = None,
) -> requests.Response:
    """GET a public URL while validating every redirect destination."""
    current_url = url
    for _ in range(max_redirects + 1):
        parsed = urlsplit(current_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise UnsafeTargetError("Collector URL must use HTTP(S) and include a hostname.")
        if not DomainNormalizer.public_addresses(parsed.hostname):
            raise UnsafeTargetError(f"Collector URL does not resolve to a public address: {parsed.hostname}")

        response = requests.get(
            current_url,
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
            stream=max_bytes is not None,
        )
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            if not location:
                return response
            response.close()
            current_url = urljoin(current_url, location)
            continue
        if max_bytes is not None:
            chunks = []
            size = 0
            for chunk in response.iter_content(chunk_size=65_536):
                size += len(chunk)
                if size > max_bytes:
                    response.close()
                    raise ResponseTooLargeError(f"Public artifact exceeds {max_bytes} bytes: {url}")
                chunks.append(chunk)
            response._content = b"".join(chunks)
            response._content_consumed = True
        return response
    raise requests.TooManyRedirects(f"More than {max_redirects} redirects for {url}")
