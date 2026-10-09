"""Modular detection-engine interface.

This is the extension point for LinkShield's pluggable detectors. To connect a
teammate's Python module later:

    from app.detection import register_engine
    from app.detection.engine import DetectionContext, DetectionEngine
    from app.models import Finding, Severity, Confidence

    class MyTeamEngine(DetectionEngine):
        name = "my_team_engine"

        def analyze(self, context: DetectionContext) -> list[Finding]:
            # Inspect context.normalized_url / context.host and return findings.
            return [Finding(engine=self.name, title="...", severity=Severity.MEDIUM)]

    register_engine(MyTeamEngine())

Engines must be pure analysis: they inspect the URL string and return Findings.
They must NOT fetch/open the URL or any external resource.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List

from ..models import Finding


@dataclass(frozen=True)
class DetectionContext:
    """Input handed to every detection engine."""

    url: str
    normalized_url: str
    host: str


class DetectionEngine(ABC):
    """Base class for pluggable detection engines.

    Subclass this and override ``name`` and ``analyze``. Register the instance
    with ``app.detection.register_engine``.
    """

    name: str = "base"

    @abstractmethod
    def analyze(self, context: DetectionContext) -> List[Finding]:
        """Return a list of findings for the given URL context."""
        raise NotImplementedError


class PlaceholderDetectionEngine(DetectionEngine):
    """No-op placeholder proving the pipeline is wired up.

    This is intentionally an empty detector. It is NOT a real detection module
    and produces no findings. The teammate's real engine replaces it.
    """

    name = "placeholder"

    def analyze(self, context: DetectionContext) -> List[Finding]:
        return []
