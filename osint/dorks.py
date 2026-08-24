from __future__ import annotations

from pathlib import Path
import re

import yaml

from config import BASE_DIR
from osint.models import DorkQuery, NormalizedTarget
from osint.resolver import TargetResolver


class QueryConfigurationError(ValueError):
    """Raised when the evidence-query catalog is missing or malformed."""


class DorkGenerator:
    """Load and render provider-neutral evidence queries from YAML."""

    SOCIAL_SITES = {
        "X": "x.com",
        "Reddit": "reddit.com",
        "Telegram": "t.me",
        "Facebook": "facebook.com",
        "Instagram": "instagram.com",
        "LinkedIn": "linkedin.com",
        "YouTube": "youtube.com",
        "TikTok": "tiktok.com",
        "Discord": "discord.com",
        "GitHub": "github.com",
    }

    PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    def __init__(self, config_path: Path | str | None = None):
        self.config_path = Path(config_path or BASE_DIR / "config" / "search_queries.yaml")

    def load(self) -> list[dict]:
        if not self.config_path.exists():
            raise QueryConfigurationError(f"Search query configuration not found: {self.config_path}")
        try:
            payload = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise QueryConfigurationError(f"Unable to load search queries: {exc}") from exc
        entries = payload.get("queries")
        if not isinstance(entries, list):
            raise QueryConfigurationError("search_queries.yaml must contain a 'queries' list.")

        required = {"id", "category", "name", "priority", "enabled", "query"}
        seen = set()
        for entry in entries:
            missing = required.difference(entry or {})
            if missing:
                raise QueryConfigurationError(f"Query entry is missing: {', '.join(sorted(missing))}")
            if entry["id"] in seen:
                raise QueryConfigurationError(f"Duplicate query id: {entry['id']}")
            seen.add(entry["id"])
        return entries

    def generate(self, target: NormalizedTarget, brand: str | None = None) -> list[DorkQuery]:
        resolved_brand = (brand or target.brand or target.domain.split(".", 1)[0]).strip()
        main_brand = TargetResolver.derive_main_brand(resolved_brand)
        queries = []
        for entry in self.load():
            if not entry["enabled"]:
                continue
            try:
                rendered = str(entry["query"]).format(
                    domain=target.domain,
                    brand=resolved_brand,
                    main_brand=main_brand,
                )
            except KeyError as exc:
                raise QueryConfigurationError(f"Unknown placeholder in {entry['id']}: {exc}") from exc
            configured_keywords = entry.get("evidence_keywords") or self._derive_keywords(str(entry["query"]))
            queries.append(
                DorkQuery(
                    query_id=str(entry["id"]),
                    category=str(entry["category"]),
                    name=str(entry["name"]),
                    priority=str(entry["priority"]).lower(),
                    query=" ".join(rendered.split()),
                    description=str(entry.get("description", entry["name"])),
                    provider=str(entry.get("provider", "any")),
                    enabled=True,
                    evidence_keywords=tuple(self._normalize_keywords(configured_keywords)),
                    target_requirement=str(entry.get("target_requirement", "required")),
                    document_type=str(entry.get("document_type", "pdf" if "filetype:pdf" in rendered.casefold() else "")),
                )
            )
        return sorted(queries, key=lambda item: (self.PRIORITY_ORDER.get(item.priority, 9), item.query_id))

    @staticmethod
    def _derive_keywords(query_template: str) -> list[str]:
        without_placeholders = re.sub(r'"\{[^}]+\}"', "", query_template)
        quoted = re.findall(r'"([^"{}]+)"', without_placeholders)
        inurl_terms = re.findall(r"inurl:([a-zA-Z0-9_-]+)", query_template, flags=re.IGNORECASE)
        file_terms = re.findall(r"filetype:([a-zA-Z0-9]+)", query_template, flags=re.IGNORECASE)
        return quoted + inurl_terms + file_terms

    @staticmethod
    def _normalize_keywords(keywords: list[str]) -> list[str]:
        excluded = {"india", "app", "official link", "working link"}
        normalized = []
        seen = set()
        for keyword in keywords:
            cleaned = " ".join(str(keyword).strip().split())
            key = cleaned.casefold()
            if len(cleaned) < 2 or key in excluded or key in seen:
                continue
            seen.add(key)
            normalized.append(cleaned)
        return normalized
