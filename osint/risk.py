from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from osint.models import Observation


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    level: str
    confidence: float
    indicators: list[dict]


class RiskScorer:
    CATEGORY_CAPS = {
        "Applications": 20,
        "Exposure": 25,
        "Financial": 25,
        "Mirrors": 20,
        "Infrastructure": 15,
        "Reputation": 20,
    }

    @classmethod
    def assess(cls, observations: list[Observation]) -> RiskAssessment:
        totals = defaultdict(int)
        indicators = []
        confidence_values = []
        seen = set()
        for observation in observations:
            if observation.risk_points <= 0:
                continue
            key = (observation.entity_type, observation.value.lower())
            if key in seen:
                continue
            seen.add(key)
            group = observation.category.split(".", 1)[0]
            cap = cls.CATEGORY_CAPS.get(group, 20)
            available = max(cap - totals[group], 0)
            applied = min(observation.risk_points, available)
            if not applied:
                continue
            totals[group] += applied
            confidence_values.append(observation.confidence)
            indicators.append(
                {
                    "category": observation.category,
                    "indicator": observation.entity_type,
                    "value": observation.value,
                    "points": applied,
                    "confidence": observation.confidence,
                    "source_url": observation.source_url,
                }
            )

        score = min(sum(totals.values()), 100)
        level = "Informational"
        for threshold, label in ((80, "Critical"), (60, "High"), (40, "Medium"), (20, "Low")):
            if score >= threshold:
                level = label
                break
        confidence = sum(confidence_values) / len(confidence_values) if confidence_values else 0.0
        return RiskAssessment(score, level, round(confidence, 2), indicators)
