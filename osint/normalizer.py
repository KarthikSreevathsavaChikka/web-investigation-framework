from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

from osint.models import NormalizedTarget


class TargetNormalizationError(ValueError):
    """Raised when an OSINT target is not a valid public domain."""


class DomainNormalizer:
    @staticmethod
    def normalize(raw_target: str) -> NormalizedTarget:
        candidate = raw_target.strip()
        if not candidate:
            raise TargetNormalizationError("Enter a website URL or domain name.")

        parsed = urlsplit(candidate if "://" in candidate else f"https://{candidate}")
        hostname = (parsed.hostname or "").strip(".").lower()
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

        return NormalizedTarget(raw_input=raw_target, domain=domain, url=f"https://{domain}")

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
