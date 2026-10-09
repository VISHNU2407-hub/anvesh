"""Combine reputation + detection findings into a consistent verdict.

Produces the core response fields: risk_level, score, findings,
reputation_status, advice. Results are never fabricated:
- UNAVAILABLE reputation never counts as "safe".
- A confirmed threat always yields a HIGH risk level.
"""

from __future__ import annotations

from typing import List

from .models import (
    AnalyzeResponse,
    Finding,
    ReputationReport,
    ReputationStatus,
    RiskLevel,
    Severity,
)
from .threat_intel.base import ReputationResult

SEVERITY_WEIGHTS = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 30,
    Severity.CRITICAL: 40,
}
FINDINGS_CAP = 50
THREAT_SCORE_FLOOR = 75

_HIGH = 75
_MEDIUM = 40


def compute_score(findings: List[Finding], reputation: ReputationResult) -> int:
    score = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    score = min(score, FINDINGS_CAP)
    if reputation.status == ReputationStatus.THREAT_DETECTED:
        score = max(score, THREAT_SCORE_FLOOR)
    return min(score, 100)


def compute_risk_level(
    score: int, findings: List[Finding], reputation: ReputationResult
) -> RiskLevel:
    if reputation.status == ReputationStatus.THREAT_DETECTED:
        return RiskLevel.HIGH
    # Reputation unavailable and nothing else to go on -> we cannot judge.
    if reputation.status == ReputationStatus.UNAVAILABLE and not findings:
        return RiskLevel.UNKNOWN
    if score >= _HIGH:
        return RiskLevel.HIGH
    if score >= _MEDIUM:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _build_advice(
    risk_level: RiskLevel, findings: List[Finding], reputation: ReputationResult
) -> str:
    parts: List[str] = []

    if reputation.status == ReputationStatus.THREAT_DETECTED:
        types = ", ".join(sorted({m.threat_type for m in reputation.matches})) or "known threat"
        parts.append(
            f"Google Safe Browsing confirms this URL matches known threat list(s): {types}. "
            "Do not visit, download from, or share this URL."
        )
    elif reputation.status == ReputationStatus.UNAVAILABLE:
        reason = reputation.error_reason or "unknown_error"
        parts.append(
            f"The reputation check could not be completed ({reason}). "
            "No conclusion about known threats can be drawn - treat this URL with caution."
        )
    else:  # NO_KNOWN_THREAT
        parts.append(
            "Google Safe Browsing has no known threat matching this URL. "
            "This is not a guarantee of safety."
        )

    if findings:
        titles = "; ".join(f.title for f in findings)
        parts.append(f"Detection engine(s) flagged: {titles}.")

    if risk_level == RiskLevel.UNKNOWN:
        parts.append("Automated analysis was inconclusive; verify manually before trusting this URL.")

    return " ".join(parts)


def build_response(
    url: str, findings: List[Finding], reputation: ReputationResult
) -> AnalyzeResponse:
    score = compute_score(findings, reputation)
    risk_level = compute_risk_level(score, findings, reputation)
    advice = _build_advice(risk_level, findings, reputation)
    return AnalyzeResponse(
        url=url,
        risk_level=risk_level,
        score=score,
        findings=findings,
        reputation_status=reputation.status,
        advice=advice,
        reputation=ReputationReport(
            provider=reputation.provider,
            status=reputation.status,
            matches=reputation.matches,
            error_reason=reputation.error_reason,
        ),
    )
