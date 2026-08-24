"""Web intelligence and passive OSINT engine."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from osint.orchestrator import IntelligenceOrchestrator

__all__ = ["IntelligenceOrchestrator"]


def __getattr__(name: str):
    """Keep lightweight submodules importable without loading every optional dependency."""
    if name == "IntelligenceOrchestrator":
        from osint.orchestrator import IntelligenceOrchestrator

        return IntelligenceOrchestrator
    raise AttributeError(name)
