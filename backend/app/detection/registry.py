"""Detection-engine registry.

Engines register themselves here; the API layer runs all registered engines and
merges their findings. This keeps the pipeline modular so new engines can be
added without touching the endpoint code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from ..models import Finding
from .engine import DetectionContext, DetectionEngine, PlaceholderDetectionEngine

_ENGINES: List[DetectionEngine] = []


@dataclass(frozen=True)
class DetectionReport:
    """Result of a detection run: the findings plus which engines failed.

    ``failed_engines`` lets callers tell "no rule matched" (engines ran,
    evidence is clean) apart from "the engine crashed" (evidence is
    missing). The latter must never be scored as if the URL were safe.
    """

    findings: List[Finding]
    failed_engines: List[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        """True when every registered engine ran without error."""
        return not self.failed_engines


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


def run_detection_report(context: DetectionContext) -> DetectionReport:
    """Run every registered engine, returning findings *and* failures."""
    findings: List[Finding] = []
    failed: List[str] = []
    for engine in _ENGINES:
        try:
            result = engine.analyze(context)
        except Exception:
            # One broken engine must not take down the whole request, but it
            # IS recorded so the verdict can stay "unknown" instead of
            # silently degrading to "no findings".
            failed.append(engine.name)
            continue
        if result:
            findings.extend(result)
    return DetectionReport(findings=findings, failed_engines=failed)


def run_detection(context: DetectionContext) -> List[Finding]:
    """Run every registered engine and merge findings."""
    return run_detection_report(context).findings


# Register the built-in placeholder so the pipeline always has at least one
# engine until the real detection module is connected.
register_engine(PlaceholderDetectionEngine())
