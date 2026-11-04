from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, Response

from config import EVIDENCE_DIR
from osint.docx_report import OSINTDocxReportBuilder
from osint.report import OSINTReportBuilder

from osint.storage import OSINTRepository
from services.api.dependencies import get_osint_repository
from services.api.schemas import (
    ComponentName,
    InvestigationDetailResponse,
    InvestigationListResponse,
    InvestigationResultsResponse,
    InvestigationSummary,
)

router = APIRouter(prefix="/api/v1/investigations", tags=["investigations"])


def _osint_summary(item: dict) -> InvestigationSummary:
    return InvestigationSummary(
        id=item["id"],
        component=ComponentName.OSINT,
        target=item.get("target_domain") or item.get("resolved_brand") or item.get("original_input") or item.get("target_url", ""),
        status=item.get("status", "Unknown"),
        started_at=item.get("started_at"),
        completed_at=item.get("completed_at"),
    )


@router.get("", response_model=InvestigationListResponse)
def list_investigations(
    component: ComponentName | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    osint: OSINTRepository = Depends(get_osint_repository),
) -> InvestigationListResponse:
    items: list[InvestigationSummary] = []
    if component in {None, ComponentName.OSINT}:
        items.extend(_osint_summary(item) for item in osint.list_investigations())
    items.sort(key=lambda item: item.started_at or "", reverse=True)
    selected = items[:limit]
    return InvestigationListResponse(items=selected, total=len(items))


@router.get("/{component}/{investigation_id}", response_model=InvestigationDetailResponse)
def get_investigation(
    component: ComponentName,
    investigation_id: str,
    osint: OSINTRepository = Depends(get_osint_repository),
) -> InvestigationDetailResponse:
    if component == ComponentName.OSINT:
        investigation = osint.get_investigation(investigation_id)
        summary = osint.get_summary_counts(investigation_id) if investigation else {}
    else:
        raise HTTPException(
            status_code=404,
            detail="VirusTotal results are available through their batch job and workspace",
        )
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return InvestigationDetailResponse(
        id=investigation_id,
        component=component,
        investigation=investigation,
        summary=summary,
    )


@router.get("/osint/{investigation_id}/results", response_model=InvestigationResultsResponse)
def get_osint_results(
    investigation_id: str,
    osint: OSINTRepository = Depends(get_osint_repository),
) -> InvestigationResultsResponse:
    """Return the complete persisted investigation workspace for the React UI."""
    investigation = osint.get_investigation(investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    summaries = {
        row.get("screenshot_path"): row.get("summary")
        for row in osint.get_screenshot_summaries(investigation_id)
    }
    evidence = osint.get_evidence(investigation_id)
    from services.screenshot_groups import annotate_groups
    annotate_groups(evidence, EVIDENCE_DIR)
    for item in evidence:
        item["screenshot_url"] = (
            f"/api/v1/investigations/osint/{investigation_id}/screenshots/evidence/{item['id']}"
        )
        item["screenshot_summary"] = summaries.get(item.get("screenshot_path"))
        item.pop("screenshot_path", None)
    findings = osint.get_social_findings(investigation_id)
    social_shots = []
    for item in findings:
        item['screenshot_groups'] = []
        for path in item.get('screenshot_paths') or []:
            shot = {'screenshot_path': path, 'source_url': item.get('post_url'), 'context_text': item.get('post_text')}
            social_shots.append(shot)
            item['screenshot_groups'].append(shot)
    annotate_groups(social_shots, EVIDENCE_DIR)
    for shot in social_shots:
        shot.pop('screenshot_path', None)
    for item in findings:
        item["screenshot_urls"] = [
            f"/api/v1/investigations/osint/{investigation_id}/screenshots/social/{item['id']}/{index}"
            for index, _ in enumerate(item.get("screenshot_paths") or [])
        ]
        item["screenshot_summaries"] = [
            summaries.get(path) for path in item.get("screenshot_paths") or []
        ]
        item.pop("screenshot_paths", None)
        item.pop("post_screenshot_path", None)
    return InvestigationResultsResponse(
        id=investigation_id,
        component=ComponentName.OSINT,
        investigation=investigation,
        summary=osint.get_summary_counts(investigation_id),
        domains=osint.get_candidates(investigation_id),
        findings=findings,
        evidence=evidence,
        page_captures=osint.get_page_captures(investigation_id),
        screenshot_summaries=osint.get_screenshot_summaries(investigation_id),
        queries=osint.get_queries(investigation_id),
        query_metrics=osint.get_query_metrics(investigation_id),
        sources=osint.get_sources(investigation_id),
        documents=osint.get_documents(investigation_id),
        collector_runs=osint.get_collector_runs(investigation_id),
        risk_indicators=osint.get_risk_indicators(investigation_id),
        analyst_notes=osint.get_analyst_notes(investigation_id),
    )


def _confined_screenshot(path_text: str) -> FileResponse:
    evidence_root = EVIDENCE_DIR.resolve()
    path = Path(path_text).resolve()
    if (
        not path.is_relative_to(evidence_root)
        or not path.is_file()
        or path.suffix.lower() not in {".png", ".jpg", ".jpeg", ".webp"}
    ):
        raise HTTPException(status_code=404, detail="Screenshot not found")
    media_type = {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp"}.get(
        path.suffix.lower(), "image/png"
    )
    return FileResponse(path, media_type=media_type)


@router.get("/osint/{investigation_id}/screenshots/evidence/{evidence_id}")
def get_evidence_screenshot(
    investigation_id: str,
    evidence_id: int,
    osint: OSINTRepository = Depends(get_osint_repository),
) -> FileResponse:
    item = next((row for row in osint.get_evidence(investigation_id) if row["id"] == evidence_id), None)
    if not item:
        raise HTTPException(status_code=404, detail="Screenshot not found")
    return _confined_screenshot(item["screenshot_path"])


@router.get("/osint/{investigation_id}/screenshots/social/{finding_id}/{index}")
def get_social_screenshot(
    investigation_id: str,
    finding_id: int,
    index: int,
    osint: OSINTRepository = Depends(get_osint_repository),
) -> FileResponse:
    item = next((row for row in osint.get_social_findings(investigation_id) if row["id"] == finding_id), None)
    paths = item.get("screenshot_paths") if item else []
    if index < 0 or index >= len(paths):
        raise HTTPException(status_code=404, detail="Screenshot not found")
    return _confined_screenshot(paths[index])


@router.get("/osint/{investigation_id}/reports/{report_format}")
def get_osint_report(
    investigation_id: str,
    report_format: str,
    download: bool = Query(default=True),
    osint: OSINTRepository = Depends(get_osint_repository),
) -> Response:
    investigation = osint.get_investigation(investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Scraping result not found")
    builder = OSINTReportBuilder(osint)
    report_format = report_format.lower()
    filename = f"webscraping-{investigation_id}.{report_format}"
    if report_format == "json":
        body, media_type = builder.build_json(investigation_id).encode(), "application/json"
    elif report_format == "html":
        body, media_type = builder.build_html(investigation_id).encode(), "text/html"
    elif report_format == "csv":
        body, media_type = builder.build_domain_csv(investigation_id).encode(), "text/csv"
    elif report_format == "docx":
        body = OSINTDocxReportBuilder(osint).build(investigation_id)
        media_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    else:
        raise HTTPException(status_code=404, detail="Report format must be json, html, csv, or docx")
    disposition = "attachment" if download else "inline"
    return Response(body, media_type=media_type, headers={
        "Content-Disposition": f'{disposition}; filename="{filename}"',
        "X-Content-Type-Options": "nosniff",
    })
