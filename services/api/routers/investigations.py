from fastapi import APIRouter, Depends, HTTPException, Query

from database.db_manager import DatabaseManager
from osint.storage import OSINTRepository
from services.api.dependencies import get_dynamic_repository, get_osint_repository
from services.api.schemas import (
    ComponentName,
    InvestigationDetailResponse,
    InvestigationListResponse,
    InvestigationSummary,
)

router = APIRouter(prefix="/api/v1/investigations", tags=["investigations"])


def _dynamic_summary(item: dict) -> InvestigationSummary:
    return InvestigationSummary(
        id=item["id"],
        component=ComponentName.DYNAMIC,
        target=item.get("website_url", ""),
        status=item.get("investigation_status", "Unknown"),
        started_at=item.get("start_time"),
        completed_at=item.get("end_time"),
    )


def _osint_summary(item: dict) -> InvestigationSummary:
    return InvestigationSummary(
        id=item["id"],
        component=ComponentName.OSINT,
        target=item.get("target_domain", item.get("target_url", "")),
        status=item.get("status", "Unknown"),
        started_at=item.get("started_at"),
        completed_at=item.get("completed_at"),
    )


@router.get("", response_model=InvestigationListResponse)
def list_investigations(
    component: ComponentName | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    dynamic: DatabaseManager = Depends(get_dynamic_repository),
    osint: OSINTRepository = Depends(get_osint_repository),
) -> InvestigationListResponse:
    items: list[InvestigationSummary] = []
    if component in {None, ComponentName.DYNAMIC}:
        items.extend(_dynamic_summary(item) for item in dynamic.get_all_investigations())
    if component in {None, ComponentName.OSINT}:
        items.extend(_osint_summary(item) for item in osint.list_investigations())
    items.sort(key=lambda item: item.started_at or "", reverse=True)
    selected = items[:limit]
    return InvestigationListResponse(items=selected, total=len(items))


@router.get("/{component}/{investigation_id}", response_model=InvestigationDetailResponse)
def get_investigation(
    component: ComponentName,
    investigation_id: str,
    dynamic: DatabaseManager = Depends(get_dynamic_repository),
    osint: OSINTRepository = Depends(get_osint_repository),
) -> InvestigationDetailResponse:
    if component == ComponentName.DYNAMIC:
        summary = dynamic.get_investigation_summary(investigation_id)
        investigation = summary.get("investigation", {})
    else:
        investigation = osint.get_investigation(investigation_id)
        summary = osint.get_summary_counts(investigation_id) if investigation else {}
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return InvestigationDetailResponse(
        id=investigation_id,
        component=component,
        investigation=investigation,
        summary=summary,
    )
