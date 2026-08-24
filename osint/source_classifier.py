from __future__ import annotations

from pathlib import PurePosixPath
from urllib.parse import urlsplit

from osint.url_tools import registrable_domain


class SourceClassifier:
    HOST_TYPES = {
        "x.com": "social_x",
        "twitter.com": "social_x",
        "facebook.com": "social_facebook",
        "instagram.com": "social_instagram",
        "youtube.com": "social_youtube",
        "youtu.be": "social_youtube",
        "reddit.com": "social_reddit",
        "quora.com": "social_quora",
        "t.me": "telegram",
        "telegram.me": "telegram",
        "crt.sh": "certificate_transparency",
    }
    REVIEW_HOSTS = {"trustpilot.com", "sitejabber.com", "mouthshut.com"}
    APP_HOSTS = {"play.google.com", "apps.apple.com", "apkpure.com", "apkmirror.com"}

    @classmethod
    def classify(cls, url: str, target_domain: str) -> str:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        target_root = registrable_domain(target_domain)
        source_root = registrable_domain(host)
        if host == target_domain or source_root == target_root:
            return "target_domain" if host in {target_domain, target_root, f"www.{target_root}"} else "target_subdomain"
        for known_host, source_type in cls.HOST_TYPES.items():
            if host == known_host or host.endswith(f".{known_host}"):
                return source_type
        if source_root in cls.REVIEW_HOSTS:
            return "review_site"
        if source_root in cls.APP_HOSTS or parsed.path.lower().endswith((".apk", ".ipa")):
            return "app_download"
        suffix = PurePosixPath(parsed.path.lower()).suffix
        if suffix == ".pdf":
            return "pdf_document"
        if suffix in {".doc", ".docx", ".xls", ".xlsx", ".csv", ".txt"}:
            return "other_document"
        if host.endswith((".gov", ".gov.in", ".nic.in")):
            return "government"
        if any(token in host for token in ("regulator", "authority", "commission")):
            return "regulator"
        if any(token in host for token in ("court", "judiciary", "legal")):
            return "court_legal"
        if any(token in host for token in ("news", "times", "post", "journal")):
            return "news"
        return "unknown"
