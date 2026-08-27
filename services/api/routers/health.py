from fastapi import APIRouter, HTTPException

from database.connection import connect_database
from services.api.schemas import HealthResponse
from services.jobs.queue import RedisJobQueue

router = APIRouter(tags=["health"])


@router.get("/health/live", response_model=HealthResponse)
def liveness() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get("/health/ready", response_model=HealthResponse)
def readiness() -> HealthResponse:
    try:
        with connect_database() as connection:
            connection.execute("SELECT 1").fetchone()
        RedisJobQueue().ping()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Database or job queue is unavailable") from exc
    return HealthResponse(status="ready")
