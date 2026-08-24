from __future__ import annotations

import os
import time
import hashlib
import json
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass

import requests
from bs4 import BeautifulSoup
from urllib.parse import parse_qs, unquote, urljoin, urlsplit
from xml.etree import ElementTree

from config import DB_PATH
from osint.models import SearchResult


@dataclass(frozen=True)
class SearchProviderCapabilities:
    supports_site_operator: str
    supports_negative_site: str
    supports_filetype: str
    supports_exact_phrase: str
    supports_complex_boolean: str

    def quality_for(self, query: str) -> str:
        requirements = []
        lowered = query.casefold()
        if "site:" in lowered:
            requirements.append(self.supports_site_operator)
        if "-site:" in lowered:
            requirements.append(self.supports_negative_site)
        if "filetype:" in lowered:
            requirements.append(self.supports_filetype)
        if '"' in query:
            requirements.append(self.supports_exact_phrase)
        if " or " in lowered:
            requirements.append(self.supports_complex_boolean)
        return "full" if requirements and all(item == "reliable" for item in requirements) else "partial"


class SearchProvider(ABC):
    name = "search"
    capabilities = SearchProviderCapabilities("unknown", "unknown", "unknown", "unknown", "unknown")

    @property
    @abstractmethod
    def available(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def search(self, query: str, *, query_id: str, count: int) -> list[SearchResult]:
        raise NotImplementedError


class AggregatingSearchProvider(SearchProvider):
    """Query every available provider and merge their distinct result URLs."""

    name = "aggregated"

    def __init__(self, providers: list[SearchProvider]):
        self.providers = [provider for provider in providers if provider.available]

    @property
    def available(self) -> bool:
        return bool(self.providers)

    def search(self, query: str, *, query_id: str, count: int) -> list[SearchResult]:
        merged: list[SearchResult] = []
        seen: set[str] = set()
        errors: list[str] = []
        for provider in self.providers:
            try:
                results = provider.search(query, query_id=query_id, count=count)
            except Exception as exc:
                errors.append(f"{provider.name}: {exc}")
                continue
            for result in results:
                normalized = result.url.casefold().rstrip("/")
                if normalized not in seen:
                    merged.append(result)
                    seen.add(normalized)
        if not merged and errors:
            raise RuntimeError("; ".join(errors))
        return merged


class BraveSearchProvider(SearchProvider):
    name = "brave"
    endpoint = "https://api.search.brave.com/res/v1/web/search"
    capabilities = SearchProviderCapabilities("reliable", "reliable", "reliable", "reliable", "partial")

    def __init__(self, api_key: str | None = None, timeout: int = 10, max_retries: int = 2):
        self.api_key = api_key or os.getenv("BRAVE_SEARCH_API_KEY", "")
        self.timeout = timeout
        self.max_retries = max_retries
        self.cache_ttl = max(0, int(os.getenv("OSINT_SEARCH_CACHE_TTL", "86400")))
        self._init_cache()

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def search(self, query: str, *, query_id: str, count: int) -> list[SearchResult]:
        if not self.available:
            return []
        cached = self._get_cached(query, query_id, count)
        if cached is not None:
            return cached
        response = None
        for attempt in range(self.max_retries + 1):
            response = requests.get(
                self.endpoint,
                headers={"Accept": "application/json", "X-Subscription-Token": self.api_key},
                params={"q": query, "count": min(max(count, 1), 20), "safesearch": "moderate"},
                timeout=self.timeout,
            )
            if response.status_code not in {429, 500, 502, 503, 504}:
                break
            if attempt < self.max_retries:
                retry_after = response.headers.get("Retry-After")
                delay = min(float(retry_after) if retry_after else 2**attempt, 10.0)
                time.sleep(delay)
        assert response is not None
        response.raise_for_status()
        results = []
        for rank, item in enumerate(response.json().get("web", {}).get("results", []), start=1):
            if not item.get("url"):
                continue
            results.append(SearchResult(
                query_id=query_id, query_text=query, search_engine=self.name, rank=rank,
                title=item.get("title") or item["url"], url=item["url"],
                snippet=item.get("description", ""),
            ))
        self._set_cached(query, count, results)
        return results

    @staticmethod
    def _cache_key(query: str, count: int) -> str:
        return hashlib.sha256(f"brave\0{count}\0{query}".encode("utf-8")).hexdigest()

    @staticmethod
    def _init_cache() -> None:
        with sqlite3.connect(str(DB_PATH)) as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS osint_search_cache (
                    cache_key TEXT PRIMARY KEY, provider TEXT NOT NULL,
                    payload_json TEXT NOT NULL, created_at REAL NOT NULL
                )"""
            )

    def _get_cached(self, query: str, query_id: str, count: int) -> list[SearchResult] | None:
        if not self.cache_ttl:
            return None
        with sqlite3.connect(str(DB_PATH)) as connection:
            row = connection.execute(
                "SELECT payload_json, created_at FROM osint_search_cache WHERE cache_key = ?",
                (self._cache_key(query, count),),
            ).fetchone()
        if not row or time.time() - row[1] > self.cache_ttl:
            return None
        return [SearchResult(query_id=query_id, query_text=query, **item) for item in json.loads(row[0])]

    def _set_cached(self, query: str, count: int, results: list[SearchResult]) -> None:
        if not self.cache_ttl:
            return
        payload = [{
            "search_engine": item.search_engine, "rank": item.rank, "title": item.title,
            "url": item.url, "snippet": item.snippet,
        } for item in results]
        with sqlite3.connect(str(DB_PATH)) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO osint_search_cache (cache_key, provider, payload_json, created_at) VALUES (?, ?, ?, ?)",
                (self._cache_key(query, count), self.name, json.dumps(payload), time.time()),
            )


class GoogleSearchProvider(SearchProvider):
    """Public Google result-page collector with no CAPTCHA or anti-bot bypass."""

    name = "google"
    endpoint = "https://www.google.com/search"
    capabilities = SearchProviderCapabilities("reliable", "reliable", "reliable", "reliable", "reliable")

    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.api_key = os.getenv("GOOGLE_SEARCH_API_KEY", "")
        self.cse_id = os.getenv("GOOGLE_SEARCH_CSE_ID", "")
        self.cache_ttl = max(0, int(os.getenv("OSINT_SEARCH_CACHE_TTL", "86400")))
        BraveSearchProvider._init_cache()

    @property
    def available(self) -> bool:
        return os.getenv("OSINT_DISABLE_GOOGLE_SEARCH", "false").lower() not in {"1", "true", "yes"}

    def search(self, query: str, *, query_id: str, count: int) -> list[SearchResult]:
        if not self.available:
            return []
        cached = self._get_cached(query, query_id, count)
        if cached is not None:
            return cached
        if self.api_key and self.cse_id:
            return self._search_json_api(query, query_id=query_id, count=count)
        response = requests.get(
            self.endpoint,
            params={"q": query, "num": min(max(count, 1), 20), "filter": "0", "hl": "en"},
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
                ),
                "Accept-Language": "en-US,en;q=0.9",
            },
            timeout=self.timeout,
        )
        lowered = response.text.casefold()
        if response.status_code == 429 or "our systems have detected unusual traffic" in lowered or "/sorry/" in response.url:
            raise RuntimeError(
                "Google rate-limited the public search request. Wait before retrying or configure "
                "GOOGLE_SEARCH_API_KEY and GOOGLE_SEARCH_CSE_ID; no bypass was attempted."
            )
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        results = []
        seen = set()
        for heading in soup.select("a:has(h3)"):
            href = heading.get("href", "")
            if href.startswith("/url?"):
                href = parse_qs(urlsplit(href).query).get("q", [""])[0]
            href = urljoin(response.url, href)
            hostname = (urlsplit(href).hostname or "").casefold()
            if not href.startswith(("http://", "https://")) or hostname.endswith("google.com") or href in seen:
                continue
            seen.add(href)
            container = heading.find_parent("div")
            snippet_node = container.select_one("div[data-sncf], div.VwiC3b, span.aCOpRe") if container else None
            results.append(SearchResult(
                query_id=query_id,
                query_text=query,
                search_engine=self.name,
                rank=len(results) + 1,
                title=heading.get_text(" ", strip=True) or href,
                url=href,
                snippet=snippet_node.get_text(" ", strip=True) if snippet_node else "",
            ))
            if len(results) >= min(max(count, 1), 20):
                break
        if not results:
            page_title = soup.title.get_text(" ", strip=True) if soup.title else "untitled response"
            raise RuntimeError(
                f"Google returned no parseable organic results ({page_title}). "
                "Configure GOOGLE_SEARCH_API_KEY and GOOGLE_SEARCH_CSE_ID for reliable Google results."
            )
        self._set_cached(query, count, results)
        return results

    def _search_json_api(self, query: str, *, query_id: str, count: int) -> list[SearchResult]:
        response = requests.get(
            "https://www.googleapis.com/customsearch/v1",
            params={"key": self.api_key, "cx": self.cse_id, "q": query, "num": min(max(count, 1), 10)},
            timeout=self.timeout,
        )
        response.raise_for_status()
        results = [SearchResult(
            query_id=query_id,
            query_text=query,
            search_engine="google_api",
            rank=rank,
            title=item.get("title") or item.get("link", ""),
            url=item.get("link", ""),
            snippet=item.get("snippet", ""),
        ) for rank, item in enumerate(response.json().get("items", []), 1) if item.get("link")]
        if not results:
            raise RuntimeError("Google Custom Search returned no results for this query")
        self._set_cached(query, count, results)
        return results

    def _cache_key(self, query: str, count: int) -> str:
        return hashlib.sha256(f"{self.name}\0{count}\0{query}".encode("utf-8")).hexdigest()

    def _get_cached(self, query: str, query_id: str, count: int) -> list[SearchResult] | None:
        if not self.cache_ttl:
            return None
        with sqlite3.connect(str(DB_PATH)) as connection:
            row = connection.execute(
                "SELECT payload_json, created_at FROM osint_search_cache WHERE cache_key = ?",
                (self._cache_key(query, count),),
            ).fetchone()
        if not row or time.time() - row[1] > self.cache_ttl:
            return None
        payload = json.loads(row[0])
        if not payload:
            with sqlite3.connect(str(DB_PATH)) as connection:
                connection.execute("DELETE FROM osint_search_cache WHERE cache_key = ?", (self._cache_key(query, count),))
            return None
        return [SearchResult(query_id=query_id, query_text=query, **item) for item in payload]

    def _set_cached(self, query: str, count: int, results: list[SearchResult]) -> None:
        if not self.cache_ttl:
            return
        payload = [{
            "search_engine": item.search_engine, "rank": item.rank, "title": item.title,
            "url": item.url, "snippet": item.snippet,
        } for item in results]
        with sqlite3.connect(str(DB_PATH)) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO osint_search_cache (cache_key, provider, payload_json, created_at) VALUES (?, ?, ?, ?)",
                (self._cache_key(query, count), self.name, json.dumps(payload), time.time()),
            )
class DuckDuckGoSearchProvider(SearchProvider):
    """Keyless, conservatively throttled provider using DuckDuckGo's HTML search page."""

    name = "duckduckgo"
    endpoint = "https://html.duckduckgo.com/html/"
    capabilities = SearchProviderCapabilities("partial", "partial", "partial", "partial", "partial")

    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.cache_ttl = max(0, int(os.getenv("OSINT_SEARCH_CACHE_TTL", "86400")))
        BraveSearchProvider._init_cache()

    @property
    def available(self) -> bool:
        return os.getenv("OSINT_DISABLE_KEYLESS_SEARCH", "false").lower() not in {"1", "true", "yes"}

    def search(self, query: str, *, query_id: str, count: int) -> list[SearchResult]:
        if not self.available:
            return []
        cached = self._get_cached(query, query_id, count)
        if cached is not None:
            return cached
        response = requests.get(
            self.endpoint,
            params={"q": query, "kl": os.getenv("OSINT_DDG_REGION", "wt-wt")},
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                )
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        results = []
        for result in soup.select(".result"):
            link = result.select_one("a.result__a")
            if not link or not link.get("href"):
                continue
            destination = self._destination_url(link["href"])
            if not destination.startswith(("http://", "https://")):
                continue
            snippet = result.select_one(".result__snippet")
            results.append(
                SearchResult(
                    query_id=query_id,
                    query_text=query,
                    search_engine=self.name,
                    rank=len(results) + 1,
                    title=link.get_text(" ", strip=True) or destination,
                    url=destination,
                    snippet=snippet.get_text(" ", strip=True) if snippet else "",
                )
            )
            if len(results) >= min(max(count, 1), 20):
                break
        self._set_cached(query, count, results)
        return results

    @staticmethod
    def _destination_url(url: str) -> str:
        parsed = urlsplit(url)
        encoded = parse_qs(parsed.query).get("uddg", [""])[0]
        return unquote(encoded) if encoded else url

    def _cache_key(self, query: str, count: int) -> str:
        return hashlib.sha256(f"{self.name}\0{count}\0{query}".encode("utf-8")).hexdigest()

    def _get_cached(self, query: str, query_id: str, count: int) -> list[SearchResult] | None:
        if not self.cache_ttl:
            return None
        with sqlite3.connect(str(DB_PATH)) as connection:
            row = connection.execute(
                "SELECT payload_json, created_at FROM osint_search_cache WHERE cache_key = ?",
                (self._cache_key(query, count),),
            ).fetchone()
        if not row or time.time() - row[1] > self.cache_ttl:
            return None
        return [SearchResult(query_id=query_id, query_text=query, **item) for item in json.loads(row[0])]

    def _set_cached(self, query: str, count: int, results: list[SearchResult]) -> None:
        if not self.cache_ttl:
            return
        payload = [
            {
                "search_engine": item.search_engine, "rank": item.rank, "title": item.title,
                "url": item.url, "snippet": item.snippet,
            }
            for item in results
        ]
        with sqlite3.connect(str(DB_PATH)) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO osint_search_cache (cache_key, provider, payload_json, created_at) VALUES (?, ?, ?, ?)",
                (self._cache_key(query, count), self.name, json.dumps(payload), time.time()),
            )


class BingRSSSearchProvider(DuckDuckGoSearchProvider):
    """Keyless search using Bing's public RSS result representation."""

    name = "bing_rss"
    endpoint = "https://www.bing.com/search"
    capabilities = SearchProviderCapabilities("unreliable", "unreliable", "unreliable", "partial", "partial")

    def search(self, query: str, *, query_id: str, count: int) -> list[SearchResult]:
        if not self.available:
            return []
        cached = self._get_cached(query, query_id, count)
        if cached is not None:
            return cached
        response = requests.get(
            self.endpoint,
            params={"q": query, "format": "rss", "setlang": os.getenv("OSINT_SEARCH_LANGUAGE", "en")},
            headers={"User-Agent": "Mozilla/5.0 (compatible; Web-Investigator/1.0; public OSINT)"},
            timeout=self.timeout,
        )
        response.raise_for_status()
        results = []
        root = ElementTree.fromstring(response.content)
        for item in root.findall(".//item"):
            destination = (item.findtext("link") or "").strip()
            if not destination.startswith(("http://", "https://")):
                continue
            results.append(
                SearchResult(
                    query_id=query_id,
                    query_text=query,
                    search_engine=self.name,
                    rank=len(results) + 1,
                    title=(item.findtext("title") or destination).strip(),
                    url=destination,
                    snippet=(item.findtext("description") or "").strip(),
                )
            )
            if len(results) >= min(max(count, 1), 20):
                break
        self._set_cached(query, count, results)
        return results
