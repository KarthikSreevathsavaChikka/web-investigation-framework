from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from investigator.core.context import InvestigationContext
from investigator.core.exceptions import PipelineConfigurationError, PipelineExecutionError
from investigator.core.models import InvestigationStatus, StageResult, StageStatus, utc_now
from investigator.core.stage import InvestigationStage, ProgressCallback, StageProgress


@dataclass(frozen=True, slots=True)
class PipelineRunResult:
    case_id: str
    status: InvestigationStatus
    stage_results: tuple[StageResult, ...]


class InvestigationPipeline:
    """Deterministic, sequential execution engine for investigation stages."""

    def __init__(self, stages: Iterable[InvestigationStage]):
        self.stages = tuple(stages)
        self._validate()

    def _validate(self) -> None:
        names = [stage.name for stage in self.stages]
        if any(not name.strip() for name in names):
            raise PipelineConfigurationError("Pipeline stage names cannot be empty")
        if len(names) != len(set(names)):
            raise PipelineConfigurationError("Pipeline stage names must be unique")
        available: set[str] = set()
        for stage in self.stages:
            missing = set(stage.dependencies) - available
            if missing:
                raise PipelineConfigurationError(
                    f"Stage '{stage.name}' has unavailable dependencies: {', '.join(sorted(missing))}"
                )
            available.add(stage.name)

    def run(self, context: InvestigationContext, *, progress_callback: ProgressCallback | None = None) -> PipelineRunResult:
        case = context.case
        if case.status not in {InvestigationStatus.CREATED, InvestigationStatus.QUEUED, InvestigationStatus.PARTIAL, InvestigationStatus.WAITING_FOR_INPUT}:
            raise PipelineExecutionError(f"Case '{case.case_id}' cannot run from status '{case.status.value}'")
        case.status = InvestigationStatus.RUNNING
        case.started_at = case.started_at or utc_now()
        ordered_results: list[StageResult] = []
        completed_count = 0

        for stage in self.stages:
            previous = context.stage_results.get(stage.name)
            if previous and previous.status in {StageStatus.COMPLETED, StageStatus.SKIPPED}:
                ordered_results.append(previous)
                completed_count += 1
                continue
            if context.cancellation_requested:
                result = self._instant_result(stage.name, StageStatus.CANCELLED, "Cancellation requested")
                context.record(result)
                ordered_results.append(result)
                case.status = InvestigationStatus.CANCELLED
                break
            if not stage.enabled(context):
                result = self._instant_result(stage.name, StageStatus.SKIPPED, "Stage disabled")
            else:
                self._notify(progress_callback, context, stage.name, StageStatus.RUNNING, completed_count, "Stage started")
                started_at = utc_now()
                try:
                    result = stage.execute(context)
                    if result.stage_name != stage.name:
                        raise PipelineExecutionError(f"Stage '{stage.name}' returned a result for '{result.stage_name}'")
                except Exception as exc:
                    result = StageResult(stage.name, StageStatus.FAILED, message="Stage execution failed", error=str(exc), started_at=started_at, completed_at=utc_now())
            context.record(result)
            ordered_results.append(result)
            if result.status in {StageStatus.COMPLETED, StageStatus.SKIPPED}:
                completed_count += 1
            self._notify(progress_callback, context, stage.name, result.status, completed_count, result.message)
            if result.status is StageStatus.WAITING_FOR_INPUT:
                case.status = InvestigationStatus.WAITING_FOR_INPUT
                break
            if result.status is StageStatus.CANCELLED:
                case.status = InvestigationStatus.CANCELLED
                break
            if result.status is StageStatus.FAILED:
                case.status = InvestigationStatus.FAILED
                break
        else:
            case.status = InvestigationStatus.PARTIAL if any(result.status is StageStatus.PARTIAL for result in ordered_results) else InvestigationStatus.COMPLETED

        if case.status in {InvestigationStatus.COMPLETED, InvestigationStatus.PARTIAL, InvestigationStatus.FAILED, InvestigationStatus.CANCELLED}:
            case.completed_at = utc_now()
        return PipelineRunResult(case.case_id, case.status, tuple(ordered_results))

    @staticmethod
    def _instant_result(stage_name: str, status: StageStatus, message: str) -> StageResult:
        timestamp = utc_now()
        return StageResult(stage_name, status, message=message, started_at=timestamp, completed_at=timestamp)

    def _notify(self, callback: ProgressCallback | None, context: InvestigationContext, stage_name: str, status: StageStatus, completed_stages: int, message: str) -> None:
        if callback:
            callback(StageProgress(context.case.case_id, stage_name, status, completed_stages, len(self.stages), message))
