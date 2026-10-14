from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ComponentName(str, Enum):
    OSINT = "osint"
    VIRUSTOTAL = "virustotal"
    EXTERNAL = "external"
    DARKWEB = "darkweb"


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


class InvestigationResultsResponse(InvestigationDetailResponse):
    domains: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    page_captures: list[dict[str, Any]] = Field(default_factory=list)
    screenshot_summaries: list[dict[str, Any]] = Field(default_factory=list)
    queries: list[dict[str, Any]] = Field(default_factory=list)
    query_metrics: list[dict[str, Any]] = Field(default_factory=list)
    sources: list[dict[str, Any]] = Field(default_factory=list)
    documents: list[dict[str, Any]] = Field(default_factory=list)
    collector_runs: list[dict[str, Any]] = Field(default_factory=list)
    risk_indicators: list[dict[str, Any]] = Field(default_factory=list)
    analyst_notes: list[dict[str, Any]] = Field(default_factory=list)


class JobStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLING = "CANCELLING"
    CANCELLED = "CANCELLED"


class OSINTJobRequest(BaseModel):
    target: str = Field(min_length=1, max_length=500)
    collectors: list[str] = Field(min_length=1)
    brand: str = Field(default="", max_length=200)
    resolution: dict[str, Any] | None = None
    query_budget: int = Field(default=12, ge=1, le=100)
    authorized: bool


class DarkwebJobRequest(BaseModel):
    target: str = Field(min_length=1, max_length=500)
    onion_urls: list[str] = Field(min_length=1, max_length=10)
    authorized: bool

    @field_validator("target")
    @classmethod
    def validate_target(cls, value):
        from osint.normalizer import DomainNormalizer
        target = DomainNormalizer.normalize(value)
        if target.domain.endswith(".onion"):
            raise ValueError("Enter the gaming website domain as the target, and onion URLs as sources.")
        return target.domain

    @field_validator("onion_urls")
    @classmethod
    def validate_sources(cls, values):
        from osint.onion_urls import normalize_onion_url
        return list(dict.fromkeys(normalize_onion_url(value) for value in values))


class VirusTotalJobRequest(BaseModel):
    domains: list[str] = Field(min_length=1, max_length=25)
    brand: str = Field(default="", max_length=200)
    authorized: bool


class ExternalInvestigationJobRequest(BaseModel):
    job_id: str = Field(min_length=1, max_length=200)
    complaint_id: str = Field(min_length=1, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    target: str = Field(min_length=1, max_length=2000)
    collectors: list[str] | None = None
    query_budget: int = Field(default=12, ge=1, le=100)
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
    payload: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class JobListResponse(BaseModel):
    items: list[JobResponse]
    total: int = Field(ge=0)
