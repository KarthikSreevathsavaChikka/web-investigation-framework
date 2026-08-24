from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from osint.collectors.base import Collector, CollectorContext
from osint.dorks import DorkGenerator
from osint.http import get_public_url
from osint.models import NormalizedTarget, Observation
from osint.normalizer import DomainNormalizer


class PublicWebCollector(Collector):
    name = "public_web"
    document_extensions = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv")
    app_extensions = (".apk", ".ipa")

    def collect(self, target: NormalizedTarget, context: CollectorContext) -> list[Observation]:
        if not DomainNormalizer.public_addresses(target.domain):
            return []
        response = get_public_url(
            target.url,
            headers={"User-Agent": "Web-Investigator-OSINT/1.0"},
            timeout=context.request_timeout,
        )
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        observations = [
            Observation(self.name, "Domain footprint", "PAGE_TITLE", soup.title.string.strip(), response.url, 0.9)
        ] if soup.title and soup.title.string else []

        social_hosts = {host: platform for platform, host in DorkGenerator.SOCIAL_SITES.items()}
        seen = set()
        for element in soup.select("a[href], script[src]"):
            raw_url = element.get("href") or element.get("src")
            absolute = urljoin(response.url, raw_url)
            if absolute in seen or urlsplit(absolute).scheme not in {"http", "https"}:
                continue
            seen.add(absolute)
            host = (urlsplit(absolute).hostname or "").lower()
            path = urlsplit(absolute).path.lower()

            platform = next((name for social_host, name in social_hosts.items() if host == social_host or host.endswith(f".{social_host}")), None)
            if platform:
                observations.append(
                    Observation(self.name, "Communications.Social media", "SOCIAL_PROFILE", absolute, response.url, 0.9, metadata={"platform": platform})
                )
            elif path.endswith(self.document_extensions):
                observations.append(
                    Observation(self.name, "Exposure.Documents", "DOCUMENT_URL", absolute, response.url, 0.85)
                )
            elif path.endswith(self.app_extensions):
                observations.append(
                    Observation(self.name, "Applications.Direct downloads", "APPLICATION_URL", absolute, response.url, 0.9, risk_points=10)
                )
            elif element.name == "script" and path.endswith(".js"):
                observations.append(
                    Observation(self.name, "Infrastructure.JavaScript", "JAVASCRIPT_URL", absolute, response.url, 0.85)
                )

        for path, entity_type in (("/robots.txt", "ROBOTS_TXT"), ("/sitemap.xml", "SITEMAP")):
            url = urljoin(response.url, path)
            try:
                artifact_response = get_public_url(
                    url,
                    headers={"User-Agent": "Web-Investigator-OSINT/1.0"},
                    timeout=context.request_timeout,
                )
                if artifact_response.ok and artifact_response.text.strip():
                    observations.append(
                        Observation(self.name, "Domain footprint", entity_type, url, url, 0.95, metadata={"size": len(artifact_response.content)})
                    )
            except Exception:
                continue
        return observations
