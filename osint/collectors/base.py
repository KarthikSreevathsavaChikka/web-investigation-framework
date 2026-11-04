from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable, Sequence

from osint.models import DorkQuery, NormalizedTarget, Observation


@dataclass(frozen=True)
class CollectorContext:
    queries: Sequence[DorkQuery]
    request_timeout: int = 10
    search_query_budget: int = 12
    results_per_query: int = 10
    cancel_check: Callable[[], bool] | None = None

    def cancellation_requested(self) -> bool:
        return bool(self.cancel_check and self.cancel_check())


class Collector(ABC):
    name = "collector"

    @abstractmethod
    def collect(self, target: NormalizedTarget, context: CollectorContext) -> list[Observation]:
        raise NotImplementedError
