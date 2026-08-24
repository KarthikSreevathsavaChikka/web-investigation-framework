from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class NormalizedTarget:
    raw_input: str
    domain: str
    url: str
    brand: str = ""


@dataclass(frozen=True)
class DorkQuery:
    query_id: str
    category: str
    name: str
    priority: str
    query: str
    description: str
    provider: str = "any"
    enabled: bool = True
    evidence_keywords: tuple[str, ...] = ()
    target_requirement: str = "required"
    document_type: str = ""


@dataclass(frozen=True)
class SearchIdentity:
    value: str
    identity_type: str
    confidence: float
    reason: str


@dataclass(frozen=True)
class SearchResult:
    query_id: str
    query_text: str
    search_engine: str
    rank: int
    title: str
    url: str
    snippet: str = ""


@dataclass(frozen=True)
class TargetCandidate:
    domain: str
    confidence: float
    reason: str
    appearances: int = 1


@dataclass(frozen=True)
class TargetResolution:
    original_input: str
    normalized_input: str
    input_type: str
    resolved_brand: str
    candidates: List[TargetCandidate] = field(default_factory=list)

    @property
    def selected(self) -> Optional[TargetCandidate]:
        return self.candidates[0] if self.candidates else None


@dataclass
class Observation:
    collector: str
    category: str
    entity_type: str
    value: str
    source_url: str
    confidence: float = 0.7
    risk_points: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CollectorResult:
    collector: str
    status: str
    observations: List[Observation] = field(default_factory=list)
    error: Optional[str] = None
    duration_seconds: float = 0.0


@dataclass
class EvidenceScreenshotRecord:
    query_id: str
    query_name: str
    query_category: str
    search_engine: str
    serp_rank: int
    matched_keywords: List[str]
    matched_phrases: List[str]
    evidence_text: str
    context_text: str
    match_method: str
    screenshot_path: str
    screenshot_sha256: str
    confidence: float
    matched_target_variant: str = ""
    target_keyword_distance: Optional[int] = None


@dataclass
class PageCaptureRecord:
    source_id: int
    source_url: str
    final_url: str = ""
    page_title: str = ""
    http_status: Optional[int] = None
    accessibility_status: str = "pending"
    failure_reason: Optional[str] = None
    matched_target_variant: str = ""
    relevance_field: str = ""
    screenshots: List[EvidenceScreenshotRecord] = field(default_factory=list)
