"""Threat-intelligence provider interface.

A provider answers one question: "is this URL on any known threat list?"
It must return an honest three-way result (confirmed match / no known match /
unavailable) and must never fabricate a verdict.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional

from ..models import ReputationMatch, ReputationStatus


@dataclass
class ReputationResult:
    """Outcome of a reputation lookup.

    status:
        THREAT_DETECTED - provider confirmed a known-threat match.
        NO_KNOWN_THREAT - provider reports no known threat (NOT a guarantee).
        UNAVAILABLE     - lookup failed; no conclusion can be drawn.
    """

    status: ReputationStatus
    provider: str
    matches: List[ReputationMatch] = field(default_factory=list)
    error_reason: Optional[str] = None

    @classmethod
    def threat_detected(cls, provider: str, matches: List[ReputationMatch]) -> "ReputationResult":
        return cls(status=ReputationStatus.THREAT_DETECTED, provider=provider, matches=matches)

    @classmethod
    def no_known_threat(cls, provider: str) -> "ReputationResult":
        return cls(status=ReputationStatus.NO_KNOWN_THREAT, provider=provider)

    @classmethod
    def unavailable(cls, provider: str, reason: str) -> "ReputationResult":
        return cls(status=ReputationStatus.UNAVAILABLE, provider=provider, error_reason=reason)


class ThreatIntelProvider(ABC):
    """Abstract threat-intelligence provider."""

    name: str = "provider"

    @abstractmethod
    async def check(self, url: str) -> ReputationResult:
        """Check a single URL against the provider's threat lists."""
        raise NotImplementedError
