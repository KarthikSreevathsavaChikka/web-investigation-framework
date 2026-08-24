from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable

from investigator.core.context import InvestigationContext
from investigator.core.models import StageResult, StageStatus


@dataclass(frozen=True, slots=True)
class StageProgress:
    case_id: str
    stage_name: str
    status: StageStatus
    completed_stages: int
    total_stages: int
    message: str = ""


ProgressCallback = Callable[[StageProgress], None]


class InvestigationStage(ABC):
    """Contract implemented by every framework pipeline stage."""

    name: str
    dependencies: tuple[str, ...] = ()

    def enabled(self, context: InvestigationContext) -> bool:
        return True

    @abstractmethod
    def execute(self, context: InvestigationContext) -> StageResult:
        """Execute the stage and return its standardized result."""
