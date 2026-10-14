from __future__ import annotations

from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit
from pathlib import PurePosixPath
from dataclasses import dataclass
import re

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


NON_CONTENT_SUFFIXES = frozenset({
    ".css", ".js", ".mjs", ".map", ".json", ".xml", ".woff", ".woff2", ".ttf", ".eot",
    ".ico", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".avif",
    ".mp4", ".mp3", ".webm", ".wav", ".zip", ".gz", ".apk", ".ipa", ".exe",
})

MEDIA_SUFFIXES = frozenset({
    ".ico", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".avif", ".bmp", ".tif", ".tiff",
    ".mp4", ".mp3", ".webm", ".wav", ".ogg", ".m4a", ".mov", ".avi", ".flac",
})
DOCUMENT_SUFFIXES = frozenset({".pdf", ".docx", ".doc", ".odt", ".rtf", ".ppt", ".pptx", ".xls", ".xlsx"})
PDF_MEDIA_TYPES = frozenset({"application/pdf", "application/x-pdf"})
DOCX_MEDIA_TYPES = frozenset({"application/vnd.openxmlformats-officedocument.wordprocessingml.document"})
DOCUMENT_MEDIA_TYPES = PDF_MEDIA_TYPES | DOCX_MEDIA_TYPES | frozenset({
    "application/msword", "application/rtf", "text/rtf", "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.oasis.opendocument.text", "application/vnd.oasis.opendocument.spreadsheet",
    "application/vnd.oasis.opendocument.presentation",
})
_ASSET_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


@dataclass(frozen=True)
class ResourceClassification:
    kind: str
    reason: str

    @property
    def is_content(self) -> bool:
        return self.kind in {"page", "document"}


def classify_source_url(url: str) -> ResourceClassification:
    """Classify explicit resource signals; unknown endpoints remain content leads.

    This is a selection hint, not a statement that an asset is irrelevant. Media
    URLs should be retained separately, without spending page or text-review slots.
    """
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ResourceClassification("invalid", "URL must have an HTTP(S) hostname")
        path = unquote(parsed.path).rstrip("/")
        suffix = PurePosixPath(path).suffix.lower()
        if suffix in DOCUMENT_SUFFIXES:
            return ResourceClassification("document", f"Document suffix {suffix}")
        if suffix in MEDIA_SUFFIXES:
            return ResourceClassification("media", f"Media suffix {suffix}")
        if suffix in NON_CONTENT_SUFFIXES:
            return ResourceClassification("asset", f"Static resource suffix {suffix}")

        # Image transformers commonly serve extensionless resources. Do not
        # classify generic width/id/download parameters as proof of media.
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            if key.casefold() not in {"format", "fm", "output", "ext"}:
                continue
            requested_format = value.casefold().split(";", 1)[0].strip()
            requested_suffix = "." + requested_format.removeprefix(".")
            if requested_suffix in DOCUMENT_SUFFIXES:
                return ResourceClassification("document", f"Document format parameter {key}={value}")
            if requested_suffix in MEDIA_SUFFIXES or requested_format.startswith(("image/", "video/", "audio/")):
                return ResourceClassification("media", f"Media format parameter {key}={value}")
            if requested_suffix in NON_CONTENT_SUFFIXES:
                return ResourceClassification("asset", f"Static resource format parameter {key}={value}")

        segments = [segment for segment in path.split("/") if segment]
        if len(segments) >= 2 and segments[-2].casefold() == "cms-assets" and _ASSET_ID.fullmatch(segments[-1]):
            return ResourceClassification("asset", "Extensionless CMS asset identifier")
        return ResourceClassification("page", "No explicit non-content resource signal")
    except (ValueError, TypeError):
        return ResourceClassification("invalid", "Malformed URL")


def classify_response_content(url: str, content_type: str, prefix: bytes = b"") -> ResourceClassification:
    """Use the response's media type before attempting HTML/text extraction.

    Real HTML document viewers remain pages even when their URL resembles a PDF
    or image. A PDF magic header also permits extensionless binary downloads.
    """
    media_type = (content_type or "").split(";", 1)[0].strip().lower()
    if media_type in {"text/html", "application/xhtml+xml", "text/plain"}:
        return ResourceClassification("page", f"Response content type {media_type}")
    if media_type in DOCUMENT_MEDIA_TYPES or prefix.lstrip().startswith(b"%PDF-"):
        return ResourceClassification("document", f"Document response ({media_type or 'PDF signature'})")
    if media_type.startswith(("image/", "audio/", "video/")):
        return ResourceClassification("media", f"Response content type {media_type}")
    if media_type in {"text/css", "text/javascript", "application/javascript", "application/ecmascript"} or media_type.startswith("font/"):
        return ResourceClassification("asset", f"Response content type {media_type}")
    if media_type in {"application/json", "application/xml", "text/xml", "application/rss+xml", "application/atom+xml"} or media_type.endswith(("+json", "+xml")):
        return ResourceClassification("structured_data", f"Structured response content type {media_type}")
    hint = classify_source_url(url)
    if media_type in {"application/octet-stream", "binary/octet-stream", "application/zip"}:
        if hint.kind == "document":
            return hint
        return ResourceClassification("binary", f"Binary response content type {media_type}")
    if media_type.startswith("application/"):
        if hint.kind == "document":
            return hint
        return ResourceClassification("binary", f"Unsupported response content type {media_type}")
    return hint


def is_content_page_url(url: str) -> bool:
    """Retain document/content leads but do not spend page budgets on static assets."""
    return classify_source_url(url).is_content
