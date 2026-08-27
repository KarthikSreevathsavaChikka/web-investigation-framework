from fastapi import APIRouter, Depends, HTTPException, Query, status

from services.api.dependencies import get_job_queue, get_job_repository
from services.api.schemas import (
    DynamicJobRequest,
    JobListResponse,
    JobResponse,
    OSINTJobRequest,
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


@router.post("/dynamic", response_model=JobResponse, status_code=status.HTTP_202_ACCEPTED)
def create_dynamic_job(
    request: DynamicJobRequest,
    repository: JobRepository = Depends(get_job_repository),
    queue: RedisJobQueue = Depends(get_job_queue),
) -> dict:
    _require_authorization(request.authorized)
    return _create_job("dynamic", request.target, request.model_dump(), repository, queue)


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
