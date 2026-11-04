"""Bounded, source-cited target associations; these are claims, never ownership proof."""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from osint.models import Observation

PROFILE_VERSION = "observed-target-v1"
MAX_FACTS_PER_KIND = 20
FACT_TYPES = {
    "BRAND_ALIAS": "aliases", "ORGANIZATION_NAME": "organizations",
    "OPERATOR_NAME": "operators", "PAGE_LANGUAGE": "languages",
    "SOCIAL_PROFILE": "social_accounts",
}


def _public_url(value):
    try:
        parsed = urlsplit(str(value))
        return parsed.scheme in {"http", "https"} and bool(parsed.hostname) and not parsed.username and not parsed.password
    except ValueError:
        return False


def _target_host(source_url, domain):
    if not _public_url(source_url):
        return False
    host = (urlsplit(source_url).hostname or "").lower().rstrip(".")
    domain = domain.lower().rstrip(".")
    return host == domain or host.endswith("." + domain)


def build_target_profile(target, observations=()):
    """Only explicit facts observed on target-host pages become target associations.

    Similar domains, search snippets, title guesses and model-generated aliases are
    deliberately insufficient. A target-host claim still does not prove ownership.
    """
    profile = {
        "version": PROFILE_VERSION,
        "target": {"url": target.url, "domain": target.domain, "brand": target.brand,
                   "provenance": "investigation_input_or_resolution", "ownership_verified": False},
        **{kind: [] for kind in FACT_TYPES.values()},
    }
    seen = set()
    for item in observations:
        row = item.as_dict() if isinstance(item, Observation) else item
        if not isinstance(row, dict):
            continue
        kind = FACT_TYPES.get(row.get("entity_type"))
        value = row.get("value")
        source_url = row.get("source_url", "")
        if not kind or not isinstance(value, str) or not value.strip() or len(value) > 500:
            continue
        if not _target_host(source_url, target.domain) or len(profile[kind]) >= MAX_FACTS_PER_KIND:
            continue
        metadata = row.get("metadata")
        if not isinstance(metadata, dict):
            try:
                metadata = json.loads(row.get("metadata_json") or "{}")
            except (TypeError, ValueError):
                metadata = {}
        if not isinstance(metadata, dict):
            metadata = {}
        # Non-link identity facts require the collector's explicit source field.
        evidence_field = metadata.get("evidence_field", "")
        if kind != "social_accounts" and not evidence_field:
            continue
        if kind == "social_accounts" and not _public_url(value):
            continue
        key = (kind, value.casefold(), source_url)
        if key in seen:
            continue
        seen.add(key)
        fact = {
            "value": value, "source_url": source_url,
            "collector": str(row.get("collector", "")),
            "observation_id": row.get("id"),
            "evidence_field": str(evidence_field or "page_link"),
            "evidence_text": str(metadata.get("evidence_text") or value)[:1000],
            "association": "website_linked" if kind == "social_accounts" else "website_declared",
            "ownership_verified": False,
        }
        if kind == "social_accounts":
            fact["platform"] = str(metadata.get("platform", ""))[:80]
        profile[kind].append(fact)
    return profile


def profile_reference_terms(target=None, profile=None):
    """Search terms are supported labels/URLs, with no generated spelling variants."""
    values = []
    if target is not None:
        values.extend([target.url, target.domain, target.brand])
    if isinstance(profile, dict):
        base = profile.get("target", {})
        if isinstance(base, dict):
            values.extend(base.get(key, "") for key in ("url", "domain", "brand"))
        for kind in ("aliases", "organizations", "operators", "social_accounts"):
            for fact in profile.get(kind, [])[:MAX_FACTS_PER_KIND]:
                if isinstance(fact, dict) and fact.get("source_url") and fact.get("evidence_field"):
                    values.append(fact.get("value", ""))
    unique = {}
    for value in values:
        if isinstance(value, str) and 2 <= len(value.strip()) <= 500:
            unique.setdefault(value.casefold(), value.strip())
    return list(unique.values())[:32]


def extract_profile_observations(html, source_url):
    """Extract explicit page metadata, keeping the source field and exact value.

    Organization metadata describes what the page declares. It is not upgraded
    to a legal-operator assertion, and nested article authors are not harvested.
    """
    soup = BeautifulSoup(html, "html.parser")
    observations = []
    seen = set()

    def add(entity_type, value, field):
        if not isinstance(value, str) or not value.strip() or len(value) > 500:
            return
        key = (entity_type, value, field)
        if key in seen or len(observations) >= 60:
            return
        seen.add(key)
        observations.append(Observation(
            "public_web", "Target profile.Observed claims", entity_type, value, source_url,
            confidence=0.7, metadata={"evidence_field": field, "evidence_text": value,
                                      "association": "website_declared", "ownership_verified": False},
        ))

    if soup.html and re.fullmatch(r"[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*", str(soup.html.get("lang", ""))):
        add("PAGE_LANGUAGE", soup.html["lang"], "html@lang")
    for meta in soup.select('meta[property="og:site_name"], meta[name="application-name"]')[:20]:
        add("BRAND_ALIAS", meta.get("content"), "meta:" + str(meta.get("property") or meta.get("name")))
    for script in soup.select('script[type="application/ld+json"]')[:10]:
        raw = script.string or script.get_text()
        if len(raw) > 100_000:
            continue
        try:
            data = json.loads(raw)
        except (TypeError, ValueError):
            continue
        nodes = data if isinstance(data, list) else [data]
        # Inspect top-level nodes and @graph, without recursively treating authors as operators.
        graph_nodes = [node for root in nodes[:30] if isinstance(root, dict)
                       for node in (root.get("@graph") if isinstance(root.get("@graph"), list) else [])[:30]]
        for node in (nodes[:30] + graph_nodes)[:60]:
            if not isinstance(node, dict):
                continue
            types = node.get("@type", [])
            types = [types] if isinstance(types, str) else types
            if not isinstance(types, list) or not any(t in {"Organization", "Corporation", "LocalBusiness", "WebSite"}
                                                       for t in types if isinstance(t, str)):
                continue
            # If the declaration identifies another website, do not attach its aliases.
            declared_url = node.get("url")
            if declared_url and (not _public_url(declared_url) or
                                 urlsplit(declared_url).hostname != urlsplit(source_url).hostname):
                continue
            for field, entity in (("name", "BRAND_ALIAS" if "WebSite" in types else "ORGANIZATION_NAME"),
                                  ("alternateName", "BRAND_ALIAS"), ("legalName", "ORGANIZATION_NAME")):
                values = node.get(field, [])
                values = values if isinstance(values, list) else [values]
                for value in values[:10]:
                    add(entity, value, "jsonld:" + "/".join(str(t) for t in types[:3]) + "." + field)
    return observations
