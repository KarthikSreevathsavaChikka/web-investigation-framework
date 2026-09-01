from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class InvestigationStatus(str, Enum):
    CREATED = "CREATED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    WAITING_FOR_INPUT = "WAITING_FOR_INPUT"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class StageStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    WAITING_FOR_INPUT = "WAITING_FOR_INPUT"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    SKIPPED = "SKIPPED"


@dataclass(frozen=True, slots=True)
class InvestigationTarget:
    value: str
    target_type: str = "unknown"
    normalized_value: str | None = None
    confidence: float = 1.0
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise ValueError("Investigation target value cannot be empty")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Target confidence must be between 0.0 and 1.0")


@dataclass(frozen=True, slots=True)
class Evidence:
    evidence_type: str
    source: str
    value: str
    confidence: float = 1.0
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.evidence_type.strip():
            raise ValueError("Evidence type cannot be empty")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Evidence confidence must be between 0.0 and 1.0")


@dataclass(frozen=True, slots=True)
class Finding:
    finding_type: str
    value: str
    severity: str = "informational"
    confidence: float = 1.0
    evidence_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.finding_type.strip():
            raise ValueError("Finding type cannot be empty")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Finding confidence must be between 0.0 and 1.0")


@dataclass(slots=True)
class InvestigationCase:
    case_id: str
    original_target: str
    status: InvestigationStatus = InvestigationStatus.CREATED
    selected_modules: tuple[str, ...] = ()
    created_at: datetime = field(default_factory=utc_now)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(cls, original_target: str, *, selected_modules: tuple[str, ...] = (), metadata: Mapping[str, Any] | None = None) -> InvestigationCase:
        if not original_target.strip():
            raise ValueError("Original target cannot be empty")
        return cls(
            case_id=f"CASE_{uuid.uuid4().hex[:12].upper()}",
            original_target=original_target.strip(),
            selected_modules=selected_modules,
            metadata=dict(metadata or {}),
        )


@dataclass(frozen=True, slots=True)
class StageResult:
    stage_name: str
    status: StageStatus
    message: str = ""
    evidence: tuple[Evidence, ...] = ()
    findings: tuple[Finding, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)
    error: str | None = None
    started_at: datetime = field(default_factory=utc_now)
    completed_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if not self.stage_name.strip():
            raise ValueError("Stage result name cannot be empty")
        if self.completed_at < self.started_at:
            raise ValueError("Stage completion time cannot precede its start time")
        if self.status is StageStatus.FAILED and not self.error:
            raise ValueError("A failed stage result must include an error")

    @classmethod
    def completed(cls, stage_name: str, *, message: str = "", evidence: tuple[Evidence, ...] = (), findings: tuple[Finding, ...] = (), metadata: Mapping[str, Any] | None = None, started_at: datetime | None = None) -> StageResult:
        return cls(
            stage_name=stage_name,
            status=StageStatus.COMPLETED,
            message=message,
            evidence=evidence,
            findings=findings,
            metadata=dict(metadata or {}),
            started_at=started_at or utc_now(),
            completed_at=utc_now(),
        )
