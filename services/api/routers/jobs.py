from fastapi import APIRouter, Depends, HTTPException, Query, status

from services.api.dependencies import get_job_queue, get_job_repository
from services.api.schemas import (
    ExternalInvestigationJobRequest,
    JobListResponse,
    JobResponse,
    OSINTJobRequest,
    DarkwebJobRequest,
    VirusTotalJobRequest,
)
from services.jobs.queue import RedisJobQueue
from services.jobs.repository import JobRepository

router = APIRouter(prefix="/api/v1/jobs", tags=["jobs"])


def _require_authorization(authorized: bool) -> None:
    if not authorized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization confirmation is required",
        )


def _create_job(
    component: str,
    target: str,
    payload: dict,
    repository: JobRepository,
    queue: RedisJobQueue,
) -> dict:
    job = repository.create(component, target, payload)
    try:
        queue.enqueue(job["id"])
    except Exception as exc:
        repository.mark_failed(job["id"], f"Queue unavailable: {exc}")
        raise HTTPException(status_code=503, detail="Investigation queue is unavailable") from exc
    return repository.get(job["id"]) or job


@router.post("/osint", response_model=JobResponse, status_code=status.HTTP_202_ACCEPTED)
def create_osint_job(
    request: OSINTJobRequest,
    repository: JobRepository = Depends(get_job_repository),
    queue: RedisJobQueue = Depends(get_job_queue),
) -> dict:
    _require_authorization(request.authorized)
    return _create_job("osint", request.target, request.model_dump(), repository, queue)


@router.post("/virustotal", response_model=JobResponse, status_code=status.HTTP_202_ACCEPTED)
def create_virustotal_job(
    request: VirusTotalJobRequest,
    repository: JobRepository = Depends(get_job_repository),
    queue: RedisJobQueue = Depends(get_job_queue),
) -> dict:
    _require_authorization(request.authorized)
    domains = list(dict.fromkeys(domain.strip().lower() for domain in request.domains if domain.strip()))
    if not domains:
        raise HTTPException(status_code=400, detail="At least one domain is required")
    payload = request.model_dump()
    payload["domains"] = domains
    return _create_job("virustotal", f"{len(domains)} selected domain(s)", payload, repository, queue)


@router.post("/darkweb", response_model=JobResponse, status_code=status.HTTP_202_ACCEPTED)
def create_darkweb_job(
    request: DarkwebJobRequest,
    repository: JobRepository = Depends(get_job_repository),
    queue: RedisJobQueue = Depends(get_job_queue),
) -> dict:
    _require_authorization(request.authorized)
    return _create_job("darkweb", request.target, request.model_dump(), repository, queue)


@router.post("/external", response_model=JobResponse, status_code=status.HTTP_202_ACCEPTED)
def create_external_job(
    request: ExternalInvestigationJobRequest,
    repository: JobRepository = Depends(get_job_repository),
    queue: RedisJobQueue = Depends(get_job_queue),
) -> dict:
    """Queue one externally identified target for OSINT, VirusTotal, report, and callback."""
    _require_authorization(request.authorized)
    payload = request.model_dump()
    payload["external_job_id"] = payload.pop("job_id")
    return _create_job("external", request.target, payload, repository, queue)


@router.get("", response_model=JobListResponse)
def list_jobs(
    limit: int = Query(default=50, ge=1, le=200),
    repository: JobRepository = Depends(get_job_repository),
) -> JobListResponse:
    items = repository.list(limit)
    return JobListResponse(items=items, total=len(items))


@router.get("/{job_id}", response_model=JobResponse)
def get_job(
    job_id: str,
    repository: JobRepository = Depends(get_job_repository),
) -> dict:
    job = repository.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@router.post("/{job_id}/cancel", response_model=JobResponse)
def cancel_job(
    job_id: str,
    repository: JobRepository = Depends(get_job_repository),
    queue: RedisJobQueue = Depends(get_job_queue),
) -> dict:
    job = repository.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job["status"] in {"COMPLETED", "FAILED", "CANCELLED"}:
        return job

    queue.request_cancel(job_id)
    if job["status"] == "QUEUED" and queue.remove_pending(job_id):
        repository.mark_cancelled(job_id)
        queue.clear_cancellation(job_id)
    else:
        repository.mark_cancelling(job_id)
    return repository.get(job_id) or job
