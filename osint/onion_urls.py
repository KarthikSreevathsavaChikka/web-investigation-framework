"""Validation shared by the API and the Tor-only collector."""
import base64
import hashlib
import re
from urllib.parse import urlsplit, urlunsplit


def normalize_onion_url(value: str) -> str:
    value = value.strip()
    if len(value) > 2000 or any(ord(c) < 33 for c in value) or "\\" in value:
        raise ValueError("Onion URLs must be at most 2000 characters without whitespace.")
    parsed = urlsplit(value)
    host = (parsed.hostname or "").lower()
    if (parsed.scheme not in {"http", "https"} or parsed.username is not None
            or parsed.password is not None or parsed.port not in {None, 80, 443}
            or not re.fullmatch(r"[a-z2-7]{56}\.onion", host)):
        raise ValueError("Supply a complete HTTP(S) v3 onion URL on port 80 or 443.")
    decoded = base64.b32decode(host[:-6].upper())
    checksum = hashlib.sha3_256(b".onion checksum" + decoded[:32] + decoded[-1:]).digest()[:2]
    if decoded[-1:] != b"\x03" or decoded[32:34] != checksum:
        raise ValueError("The onion address checksum is invalid; check the copied URL.")
    authority = host + (f":{parsed.port}" if parsed.port else "")
    return urlunsplit((parsed.scheme, authority, parsed.path or "/", parsed.query, ""))
