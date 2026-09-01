from __future__ import annotations

from dataclasses import dataclass, field
from threading import Event
from typing import Any

from investigator.core.models import Evidence, Finding, InvestigationCase, InvestigationTarget, StageResult


@dataclass(slots=True)
class InvestigationContext:
    """Mutable state passed between stages during one pipeline run."""

    case: InvestigationCase
    targets: list[InvestigationTarget] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    stage_results: dict[str, StageResult] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    _cancel_event: Event = field(default_factory=Event, repr=False)

    @property
    def cancellation_requested(self) -> bool:
        return self._cancel_event.is_set()

    def request_cancellation(self) -> None:
        self._cancel_event.set()

    def record(self, result: StageResult) -> None:
        self.stage_results[result.stage_name] = result
        self.evidence.extend(result.evidence)
        self.findings.extend(result.findings)
