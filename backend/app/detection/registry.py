"""Detection-engine registry.

Engines register themselves here; the API layer runs all registered engines and
merges their findings. This keeps the pipeline modular so new engines can be
added without touching the endpoint code.
"""

from __future__ import annotations

from typing import List

from ..models import Finding
from .engine import DetectionContext, DetectionEngine, PlaceholderDetectionEngine

_ENGINES: List[DetectionEngine] = []


def register_engine(engine: DetectionEngine) -> None:
    """Register a detection engine instance."""
    if not isinstance(engine, DetectionEngine):
        raise TypeError("engine must be a DetectionEngine instance")
    # Replace an existing engine with the same name, otherwise append.
    for i, existing in enumerate(_ENGINES):
        if existing.name == engine.name:
            _ENGINES[i] = engine
            return
    _ENGINES.append(engine)


def get_engines() -> List[DetectionEngine]:
    return list(_ENGINES)


def clear_engines() -> None:
    """Remove all registered engines (useful for tests)."""
    _ENGINES.clear()


def run_detection(context: DetectionContext) -> List[Finding]:
    """Run every registered engine and merge findings."""
    findings: List[Finding] = []
    for engine in _ENGINES:
        try:
            result = engine.analyze(context)
        except Exception:
            # One broken engine must not take down the whole request.
            continue
        if result:
            findings.extend(result)
    return findings


# Register the built-in placeholder so the pipeline always has at least one
# engine until the real detection module is connected.
register_engine(PlaceholderDetectionEngine())
