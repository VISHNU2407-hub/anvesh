"""Combine reputation + detection findings into a consistent verdict.

Produces the core response fields: risk_level, verdict, score, findings,
reputation_status, advice. Results are never fabricated:
- UNAVAILABLE reputation never counts as "safe".
- A confirmed threat always yields a HIGH risk level.
- "verified_safe" requires BOTH a completed reputation lookup with no known
  threat AND detection findings that are empty AND detection that ran to
  completion - it is never granted merely because no pattern matched.
- Failed detection engines (``detection_ok=False``) force an "unknown"
  verdict when there is nothing else to go on: missing evidence is not
  evidence of safety.
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
    Verdict,
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
    score: int,
    findings: List[Finding],
    reputation: ReputationResult,
    detection_ok: bool = True,
) -> RiskLevel:
    if reputation.status == ReputationStatus.THREAT_DETECTED:
        return RiskLevel.HIGH
    # Nothing to judge on: reputation unavailable or detection failed with no
    # findings to compensate -> we cannot determine a risk.
    if not findings and (
        reputation.status == ReputationStatus.UNAVAILABLE or not detection_ok
    ):
        return RiskLevel.UNKNOWN
    if score >= _HIGH:
        return RiskLevel.HIGH
    if score >= _MEDIUM:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def compute_verdict(
    findings: List[Finding],
    reputation: ReputationResult,
    detection_ok: bool = True,
) -> Verdict:
    """Map the evidence to one of the four explicit verdicts.

    Order of evidence (strongest first):
    1. Provider-confirmed threat match -> CONFIRMED_MALICIOUS (the only
       status that claims confirmed malice; only reliable external evidence
       may produce it).
    2. Any detection finding -> SUSPICIOUS (something must be reviewed).
    3. Detection could not run to completion -> UNKNOWN (missing evidence
       must never be scored as clean).
    4. Completed lookup with no known threat AND no findings ->
       VERIFIED_SAFE (two independent signals; advice still caveats it).
    5. Everything else (no findings, reputation unavailable) -> UNKNOWN.
    """
    if reputation.status == ReputationStatus.THREAT_DETECTED:
        return Verdict.CONFIRMED_MALICIOUS
    if findings:
        return Verdict.SUSPICIOUS
    if not detection_ok:
        return Verdict.UNKNOWN
    if reputation.status == ReputationStatus.NO_KNOWN_THREAT:
        return Verdict.VERIFIED_SAFE
    return Verdict.UNKNOWN


def _build_advice(
    risk_level: RiskLevel,
    findings: List[Finding],
    reputation: ReputationResult,
    verdict: Verdict,
    detection_ok: bool,
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

    if not detection_ok:
        parts.append(
            "One or more detection engines failed during this analysis, so "
            "the URL could not be fully inspected - verification is needed."
        )

    if verdict == Verdict.VERIFIED_SAFE:
        parts.append(
            "Verified: the reputation lookup completed with no known-threat "
            "match and no detection signal fired. This is a positive signal, "
            "not an absolute guarantee - if the link arrived unexpectedly, "
            "verify it before use."
        )

    if risk_level == RiskLevel.UNKNOWN:
        parts.append("Automated analysis was inconclusive; verify manually before trusting this URL.")

    return " ".join(parts)


def build_response(
    url: str,
    findings: List[Finding],
    reputation: ReputationResult,
    detection_ok: bool = True,
) -> AnalyzeResponse:
    score = compute_score(findings, reputation)
    verdict = compute_verdict(findings, reputation, detection_ok)
    risk_level = compute_risk_level(score, findings, reputation, detection_ok)
    advice = _build_advice(risk_level, findings, reputation, verdict, detection_ok)
    return AnalyzeResponse(
        url=url,
        risk_level=risk_level,
        verdict=verdict,
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
