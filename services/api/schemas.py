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
