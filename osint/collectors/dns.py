from __future__ import annotations

from osint.collectors.base import Collector, CollectorContext
from osint.models import NormalizedTarget, Observation
from osint.normalizer import DomainNormalizer


class DNSCollector(Collector):
    name = "dns"

    def collect(self, target: NormalizedTarget, context: CollectorContext) -> list[Observation]:
        return [
            Observation(
                collector=self.name,
                category="Infrastructure.DNS",
                entity_type="IP_ADDRESS",
                value=address,
                source_url=f"dns://{target.domain}",
                confidence=1.0,
            )
            for address in DomainNormalizer.public_addresses(target.domain)
        ]
