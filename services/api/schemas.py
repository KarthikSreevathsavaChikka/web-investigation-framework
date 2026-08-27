from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ComponentName(str, Enum):
    DYNAMIC = "dynamic"
    OSINT = "osint"


class HealthResponse(BaseModel):
    status: str
    service: str = "web-investigation-api"


class InvestigationSummary(BaseModel):
    id: str
    component: ComponentName
    target: str
    status: str
    started_at: str | None = None
    completed_at: str | None = None


class InvestigationListResponse(BaseModel):
    items: list[InvestigationSummary]
    total: int = Field(ge=0)


class InvestigationDetailResponse(BaseModel):
    id: str
    component: ComponentName
    investigation: dict[str, Any]
    summary: dict[str, Any]


class JobStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class OSINTJobRequest(BaseModel):
    target: str = Field(min_length=1, max_length=500)
    collectors: list[str] = Field(min_length=1)
    brand: str = Field(default="", max_length=200)
    resolution: dict[str, Any] | None = None
    authorized: bool


class DynamicJobRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2000)
    max_pages: int = Field(default=10, ge=1, le=100)
    authorized: bool


class JobResponse(BaseModel):
    id: str
    component: ComponentName
    target: str
    status: JobStatus
    attempts: int
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    result: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class JobListResponse(BaseModel):
    items: list[JobResponse]
    total: int = Field(ge=0)
