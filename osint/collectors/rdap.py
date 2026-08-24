from __future__ import annotations

from osint.collectors.base import Collector, CollectorContext
from osint.http import get_public_url
from osint.models import NormalizedTarget, Observation


class RDAPCollector(Collector):
    name = "rdap"

    def collect(self, target: NormalizedTarget, context: CollectorContext) -> list[Observation]:
        source = f"https://rdap.org/domain/{target.domain}"
        response = get_public_url(
            source,
            headers={"Accept": "application/rdap+json", "User-Agent": "Web-Investigator-OSINT/1.0"},
            timeout=context.request_timeout,
        )
        response.raise_for_status()
        payload = response.json()
        observations = []

        for event in payload.get("events", []):
            action, date = event.get("eventAction"), event.get("eventDate")
            if action and date:
                observations.append(
                    Observation(self.name, "Identity.Registration", "DOMAIN_EVENT", f"{action}: {date}", source, 0.95)
                )
        for nameserver in payload.get("nameservers", []):
            hostname = nameserver.get("ldhName")
            if hostname:
                observations.append(
                    Observation(self.name, "Infrastructure.DNS", "NAMESERVER", hostname.lower(), source, 0.95)
                )
        for entity in payload.get("entities", []):
            handle = entity.get("handle")
            roles = entity.get("roles", [])
            if handle and "registrar" in roles:
                observations.append(
                    Observation(self.name, "Identity.Registration", "REGISTRAR", handle, source, 0.9, metadata={"roles": roles})
                )
        return observations
