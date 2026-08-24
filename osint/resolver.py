from __future__ import annotations

import re
import os
import time
from collections import defaultdict
from urllib.parse import urlsplit

from rapidfuzz import fuzz

from osint.models import NormalizedTarget, SearchIdentity, SearchResult, TargetCandidate, TargetResolution
from osint.normalizer import DomainNormalizer, TargetNormalizationError
from osint.search import SearchProvider
from osint.url_tools import registrable_domain


class ResolutionProviderUnavailable(RuntimeError):
    """Raised when a brand/partial target needs search but no provider is configured."""


class TargetResolver:
    DISCOVERY_QUERIES = (
        '"{brand}"',
        '"{brand}" official site',
        '"{brand}" login',
        '"{brand}" betting',
        '"{brand}" casino',
        '"{brand}" app',
        '"{brand}" India',
        '"{brand}" mirror',
        '"{brand}" mirrors',
        '"{brand}" alternative domain',
        '"{brand}" new domain',
        '"{brand}" official website India',
        'inurl:{compact_brand} "{brand}"',
    )
    EXCLUDED_DOMAINS = {
        "facebook.com", "instagram.com", "linkedin.com", "reddit.com", "t.me",
        "twitter.com", "x.com", "youtube.com", "wikipedia.org",
    }

    @staticmethod
    def classify(raw_input: str) -> str:
        value = raw_input.strip()
        if value.lower().startswith(("http://", "https://")):
            return "url"
        try:
            DomainNormalizer.normalize(value)
        except TargetNormalizationError:
            if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9-]*", value) and any(char.isdigit() for char in value):
                return "partial_name"
            return "brand_or_app_name"
        return "domain"

    @staticmethod
    def derive_main_brand(value: str) -> str:
        """Reduce mirror/domain suffixes while retaining a recognisable parent brand."""
        label = value.casefold().removeprefix("www.").split(".", 1)[0]
        words = re.sub(r"[-_]+", " ", label)
        numeric_match = re.fullmatch(r"(.+?)(\d+)", words.strip())
        # Digits are part of short brands (for example Fun88).  They are only stripped
        # from recognisable mirror-style labels such as parimatchs123/parimatch123.
        if numeric_match and len(numeric_match.group(1).replace(" ", "")) >= 7:
            words = numeric_match.group(1).strip()
        # Mirror labels commonly pluralize the parent brand before a numeric suffix.
        if label[-1:].isdigit() and words.endswith("s") and len(words) >= 7:
            words = words[:-1]
        return " ".join(part.capitalize() for part in words.split()) or value.strip().title()

    def resolve(self, raw_input: str, provider: SearchProvider | None = None) -> TargetResolution:
        normalized_input = " ".join(raw_input.strip().split())
        input_type = self.classify(normalized_input)
        if input_type in {"url", "domain"}:
            target = DomainNormalizer.normalize(normalized_input)
            root = registrable_domain(target.domain)
            brand = self.derive_main_brand(root)
            candidate = TargetCandidate(root, 1.0, "Valid domain supplied directly", 1)
            return TargetResolution(raw_input, normalized_input.lower(), input_type, brand, [candidate])

        if provider is None or not provider.available:
            raise ResolutionProviderUnavailable(
                "Brand and partial-name resolution requires an enabled search provider."
            )
        results = []
        provider_errors = []
        request_delay = max(0.0, min(float(os.getenv("OSINT_SEARCH_REQUEST_DELAY", "1.5")), 5.0))
        compact_brand = re.sub(r"[^a-zA-Z0-9]", "", normalized_input)
        for index, template in enumerate(self.DISCOVERY_QUERIES, start=1):
            query = template.format(brand=normalized_input, compact_brand=compact_brand)
            try:
                results.extend(provider.search(query, query_id=f"RESOLVE_{index:02d}", count=20))
            except Exception as exc:
                provider_errors.append(str(exc))
                break
            if request_delay and index < len(self.DISCOVERY_QUERIES):
                time.sleep(request_delay)
        if not results and provider_errors:
            raise ResolutionProviderUnavailable(
                "Public search could not resolve this brand without being rate-limited. "
                f"{provider_errors[-1]} You can still enter a full domain directly."
            )
        candidates = self.rank_candidates(normalized_input, results)
        return TargetResolution(
            raw_input,
            normalized_input.lower(),
            input_type,
            self.derive_main_brand(normalized_input),
            candidates,
        )

    def rank_candidates(self, input_value: str, results: list[SearchResult]) -> list[TargetCandidate]:
        grouped: dict[str, list[SearchResult]] = defaultdict(list)
        for result in results:
            hostname = (urlsplit(result.url).hostname or "").lower()
            domain = registrable_domain(hostname)
            if not domain or domain in self.EXCLUDED_DOMAINS:
                continue
            grouped[domain].append(result)

        needle = re.sub(r"[^a-z0-9]", "", input_value.lower())
        derived = re.sub(r"[^a-z0-9]", "", self.derive_main_brand(input_value).lower())
        # The derived identity is deliberately accepted only for long mirror labels;
        # short numeric brands such as Fun88 retain their digits.
        identities = {value for value in (needle, derived) if len(value) >= 4}
        scored = []
        for domain, matches in grouped.items():
            domain_label = re.sub(r"[^a-z0-9]", "", domain.split(".", 1)[0])
            domain_match = any(identity in domain_label or domain_label in identity for identity in identities)
            direct_text_matches = [
                item for item in matches
                if any(re.search(rf"(?<![a-z0-9]){re.escape(identity)}(?![a-z0-9])", re.sub(r"[^a-z0-9]+", " ", f"{item.title} {item.snippet}".lower())) for identity in identities)
            ]
            # Fuzzy similarity alone produced false targets such as youtubekids.com
            # for Puntit. A candidate must contain the identity directly in its domain,
            # title, or snippet; results without that proof are discarded.
            if not domain_match and not direct_text_matches:
                continue
            domain_similarity = max((fuzz.ratio(identity, domain_label) / 100 for identity in identities), default=0.0)
            title_similarity = max(
                (fuzz.partial_ratio(input_value.lower(), item.title.lower()) / 100 for item in matches),
                default=0.0,
            )
            combined_text = " ".join(f"{item.title} {item.snippet}" for item in matches).lower()
            relevance = 1.0 if any(word in combined_text for word in ("official", "betting", "casino", "sportsbook")) else 0.0
            official_signal = any(word in combined_text for word in ("official", "official site", "official app", "login"))
            recurrence = min(len(matches) / 4, 1.0)
            score = min(0.55 * (1.0 if domain_match else 0.0) + 0.2 * title_similarity + 0.15 * relevance + 0.1 * recurrence, 1.0)
            # Text-only mentions are retained only when the result itself signals an
            # official/app destination; review and generic third-party domains cannot
            # become the default target.
            if not domain_match and not official_signal:
                continue
            reason = (
                f"direct {'domain' if domain_match else 'title/snippet'} match; domain similarity {domain_similarity:.0%}; title similarity {title_similarity:.0%}; "
                f"appeared {len(matches)} time(s)"
            )
            scored.append(TargetCandidate(domain, round(score, 2), reason, len(matches)))
        candidate_limit = max(8, min(int(os.getenv("OSINT_RESOLUTION_CANDIDATE_LIMIT", "100")), 500))
        return sorted(scored, key=lambda item: (-item.confidence, -item.appearances, item.domain))[:candidate_limit]

    @staticmethod
    def build_search_identities(target: NormalizedTarget) -> list[SearchIdentity]:
        """Build conservative, auditable aliases without inventing unrelated brands."""
        domain = target.domain.casefold().removeprefix("www.")
        label = domain.split(".", 1)[0]
        brand = " ".join((target.brand or label).split())
        identities = [SearchIdentity(domain, "DOMAIN", 1.0, "Resolved target domain")]
        mirror_brand = label.replace("-", " ").title()
        if mirror_brand.casefold() != domain:
            identities.append(SearchIdentity(mirror_brand, "EXACT_BRAND", 0.96, "Exact brand label derived from the resolved domain"))
        if brand and brand.casefold() != domain:
            identities.append(SearchIdentity(brand, "MAIN_BRAND", 0.95, "Resolved parent brand"))
        label_words = re.sub(r"[-_]+", " ", label).strip()
        if label_words and label_words.casefold() not in {item.value.casefold() for item in identities}:
            identities.append(SearchIdentity(label_words, "DOMAIN_LABEL", 0.9, "Label derived from resolved domain"))
        match = re.fullmatch(r"([a-z][a-z-]*?)(\d+)", label)
        if match:
            word, digits = match.groups()
            spaced = f"{word.replace('-', ' ')} {digits}"
            if spaced.casefold() not in {item.value.casefold() for item in identities}:
                identities.append(SearchIdentity(spaced, "NORMALIZED_BRAND", 0.78, "Conservative spacing of domain label and numeric suffix"))
            parent_word = word[:-1] if word.endswith("s") and len(word) >= 7 else word
            parent_spaced = f"{parent_word.replace('-', ' ').title()} {digits}"
            if parent_spaced.casefold() not in {item.value.casefold() for item in identities}:
                identities.append(SearchIdentity(parent_spaced, "NORMALIZED_BRAND", 0.76, "Parent brand combined with the mirror numeric suffix"))
        main_brand = TargetResolver.derive_main_brand(label)
        if main_brand.casefold() not in {item.value.casefold() for item in identities}:
            identities.append(SearchIdentity(main_brand, "MAIN_BRAND", 0.72, "Parent brand derived by removing a mirror-style numeric suffix"))
        return identities
