from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Sequence

from osint.models import DorkQuery, NormalizedTarget, Observation


@dataclass(frozen=True)
class CollectorContext:
    queries: Sequence[DorkQuery]
    request_timeout: int = 10
    search_query_budget: int = 12
    results_per_query: int = 10


class Collector(ABC):
    name = "collector"

    @abstractmethod
    def collect(self, target: NormalizedTarget, context: CollectorContext) -> list[Observation]:
        raise NotImplementedError
