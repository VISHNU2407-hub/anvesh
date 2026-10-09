"""Pydantic models and enums shared across the backend.

The response schema is intentionally explicit so the frontend always receives a
consistent shape with these required fields:

    risk_level, score, findings, reputation_status, advice
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Overall risk verdict. 'unknown' means we could not determine a risk."""

    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Verdict(str, Enum):
    """Evidence-based verdict that distinguishes four clearly different
    outcomes (kept separate from the graded ``risk_level``):

    - CONFIRMED_MALICIOUS: an external threat-intelligence source confirmed a
      known-threat match. This is the only status backed by reliable evidence
      of malice.
    - SUSPICIOUS: detection engines produced findings that need human review.
    - UNKNOWN: evidence was insufficient - nothing matched but checks were
      unavailable or detection could not run. This means *needs
      verification* and is NEVER a claim that the URL is safe.
    - VERIFIED_SAFE: the reputation lookup completed with no known-threat
      match AND no detection signal fired AND detection ran to completion.
      Still not an absolute guarantee (advice says so explicitly).
    """

    CONFIRMED_MALICIOUS = "confirmed_malicious"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"
    VERIFIED_SAFE = "verified_safe"


class ReputationStatus(str, Enum):
    """Outcome of the external reputation check.

    - THREAT_DETECTED: Google confirmed the URL matches a known threat list.
    - NO_KNOWN_THREAT: Google reported no known threat for this URL (not a
      guarantee of safety).
    - UNAVAILABLE: The check could not be completed (missing key, timeout,
      quota, auth, or API failure). We must NOT claim the URL is safe.
    """

    THREAT_DETECTED = "threat_detected"
    NO_KNOWN_THREAT = "no_known_threat"
    UNAVAILABLE = "unavailable"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AnalyzeRequest(BaseModel):
    url: str = Field(..., description="The URL to analyze.", max_length=2048)


class Finding(BaseModel):
    """A single detection-engine finding."""

    engine: str
    rule_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM


class ReputationMatch(BaseModel):
    """A confirmed threat-list match returned by the reputation provider."""

    threat_type: str
    platform_type: Optional[str] = None
    threat_entry_type: Optional[str] = None


class ReputationReport(BaseModel):
    """Non-secret details about the reputation check (never includes the key)."""

    provider: str
    status: ReputationStatus
    matches: List[ReputationMatch] = Field(default_factory=list)
    # Reason the check was unavailable, e.g. 'timeout', 'quota_exceeded'.
    error_reason: Optional[str] = None


class AnalyzeResponse(BaseModel):
    url: str
    risk_level: RiskLevel
    verdict: Verdict
    score: int = Field(..., ge=0, le=100)
    findings: List[Finding] = Field(default_factory=list)
    reputation_status: ReputationStatus
    advice: str
    reputation: ReputationReport
