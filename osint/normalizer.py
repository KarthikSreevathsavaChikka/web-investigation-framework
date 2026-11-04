from __future__ import annotations

import ipaddress
import socket
import re
from urllib.parse import quote, urlsplit, urlunsplit

from osint.models import NormalizedTarget
from osint.url_tools import registrable_domain


class TargetNormalizationError(ValueError):
    """Raised when an OSINT target is not a valid public domain."""


class DomainNormalizer:
    @staticmethod
    def normalize(raw_target: str) -> NormalizedTarget:
        candidate = raw_target.strip()
        if not candidate:
            raise TargetNormalizationError("Enter a website URL or domain name.")

        if any(ord(character) < 32 or ord(character) == 127 for character in candidate):
            raise TargetNormalizationError("The target URL contains control characters.")
        try:
            parsed = urlsplit(candidate if "://" in candidate else f"https://{candidate}")
            hostname = (parsed.hostname or "").strip(".").lower()
            port = parsed.port
        except ValueError as exc:
            raise TargetNormalizationError("The target URL is malformed.") from exc
        if parsed.scheme.lower() not in {"http", "https"}:
            raise TargetNormalizationError("The target URL must use HTTP or HTTPS.")
        if parsed.username is not None or parsed.password is not None:
            raise TargetNormalizationError("Use a target URL without embedded credentials.")
        if not hostname:
            raise TargetNormalizationError("The target does not contain a valid hostname.")

        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise TargetNormalizationError("Use a public domain name, not an IP address.")

        try:
            domain = hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise TargetNormalizationError("The internationalized domain is invalid.") from exc

        labels = domain.split(".")
        if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
            raise TargetNormalizationError("Enter a fully qualified domain such as example.com.")
        if any(label.startswith("-") or label.endswith("-") for label in labels):
            raise TargetNormalizationError("The domain contains an invalid label.")
        if len(domain) > 253 or any(not re.fullmatch(r"[a-z0-9-]+", label) for label in labels):
            raise TargetNormalizationError("The domain contains an invalid label.")

        authority = f"{domain}:{port}" if port is not None else domain
        url = urlunsplit((
            parsed.scheme.lower(), authority,
            quote(parsed.path, safe="/%:@!$&'()*+,;=-._~"),
            quote(parsed.query, safe="%/?@!$&'()*+,;=:-._~"), "",
        ))
        return NormalizedTarget(raw_input=raw_target, domain=domain, url=url)

    @staticmethod
    def public_addresses(domain: str) -> list[str]:
        try:
            records = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return []

        addresses = sorted({record[4][0] for record in records})
        public = []
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if not any(
                (
                    ip.is_private,
                    ip.is_loopback,
                    ip.is_link_local,
                    ip.is_multicast,
                    ip.is_reserved,
                    ip.is_unspecified,
                )
            ):
                public.append(address)
            else:
                # Reject mixed public/private answers to avoid DNS-rebinding paths.
                return []
        return public


def target_for_domain(raw_input: str, domain: str) -> str:
    """Keep the supplied URL for its primary candidate, not related domains.

    Resolution groups candidates by registrable domain. A user-supplied www or
    regional subdomain and its case-sensitive path/query still identify the exact
    page to collect for that primary candidate.
    """
    try:
        supplied = DomainNormalizer.normalize(raw_input)
        selected = DomainNormalizer.normalize(domain)
    except TargetNormalizationError:
        return domain
    if selected.domain in {supplied.domain, registrable_domain(supplied.domain)}:
        return supplied.url
    return domain
