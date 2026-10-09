"""Combine reputation + detection findings into a consistent verdict.

Produces the core response fields: risk_level, verdict, score, findings,
reputation_status, advice. Results are never fabricated:

- UNAVAILABLE reputation never counts as "safe".
- A provider-confirmed threat always yields a HIGH risk level and is the only
  source of the ``confirmed_malicious`` verdict.
- Heuristic findings alone can never confirm malice; at most they escalate to
  ``suspicious``.
- ``risk_level`` is derived from the score using explicit thresholds, then
  floored so it can never contradict the strongest finding's severity (a HIGH
  finding can no longer sit under a LOW risk level).
- Weak signals (credential-lure keywords) never produce a ``suspicious``
  verdict on their own: with nothing but weak evidence the result is
  ``unknown`` (needs verification).
- ``verified_safe`` is reserved for an explicit, documented positive-
  verification step. This implementation has none: "Google Safe Browsing
  returned no match" is NOT proof of safety, so a clean lookup is reported as
  ``unknown`` with the advice "No known threats found; safety is not
  guaranteed."
- Failed detection engines (``detection_ok=False``) force an "unknown" verdict
  when there is nothing else to go on: missing evidence is not evidence of
  safety.

Consistency contract (enforced by regression tests)::

    confirmed_malicious -> risk_level high          (provider match)
    suspicious          -> risk_level low/medium    (>= 1 strong finding; high only via provider)
    unknown             -> risk_level unknown/low   (weak or missing evidence)
    verified_safe       -> risk_level low           (reserved; not emitted)
"""

from __future__ import annotations

from typing import Dict, List

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

#: Points contributed by a finding of each severity.
SEVERITY_WEIGHTS = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 30,
    Severity.CRITICAL: 40,
}

# Heuristic findings are deliberately capped below the "high" threshold: only
# reliable external evidence (a provider threat match) can make a URL high
# risk. The cap keeps a pile of weak rules from impersonating a confirmed hit.
FINDINGS_CAP = 50
THREAT_SCORE_FLOOR = 75

# Clear score -> risk thresholds. A finding's severity can only *raise* the
# level above what the score alone implies (never lower it).
_HIGH_RISK_SCORE = 70
_MEDIUM_RISK_SCORE = 40

#: Ordering used to take the max of a score-derived level and a severity floor.
_RISK_ORDER: Dict[RiskLevel, int] = {
    RiskLevel.UNKNOWN: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
}

#: The minimum risk level implied by a single finding's severity. A HIGH (or
#: CRITICAL) finding must never be reported under a LOW risk level, but a
#: heuristic finding still never reaches HIGH on its own.
_SEVERITY_RISK_FLOOR = {
    Severity.INFO: RiskLevel.LOW,
    Severity.LOW: RiskLevel.LOW,
    Severity.MEDIUM: RiskLevel.LOW,
    Severity.HIGH: RiskLevel.MEDIUM,
    Severity.CRITICAL: RiskLevel.MEDIUM,
}

#: Rules that are weak evidence on their own. Credential-lure wording appears
#: on countless legitimate sites, so a keyword match must not, by itself,
#: produce a ``suspicious`` verdict - it needs corroboration from an
#: independent, stronger signal.
WEAK_SIGNAL_RULE_IDS = frozenset({"suspicious_keywords"})


def _is_weak_signal(finding: Finding) -> bool:
    """True when a finding is, on its own, only weak evidence."""
    if finding.rule_id in WEAK_SIGNAL_RULE_IDS:
        return True
    # Info-level findings carry no weight and are treated as weak.
    return finding.severity == Severity.INFO


def _severity_floor(findings: List[Finding]) -> RiskLevel:
    """Highest risk level implied by any single finding's severity."""
    floor = RiskLevel.LOW
    for finding in findings:
        candidate = _SEVERITY_RISK_FLOOR.get(finding.severity, RiskLevel.LOW)
        if _RISK_ORDER[candidate] > _RISK_ORDER[floor]:
            floor = candidate
    return floor


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

    level = RiskLevel.LOW
    if score >= _HIGH_RISK_SCORE:
        level = RiskLevel.HIGH
    elif score >= _MEDIUM_RISK_SCORE:
        level = RiskLevel.MEDIUM

    # Never let the reported risk contradict the strongest finding.
    floor = _severity_floor(findings)
    if _RISK_ORDER[floor] > _RISK_ORDER[level]:
        level = floor
    return level


def compute_verdict(
    findings: List[Finding],
    reputation: ReputationResult,
    detection_ok: bool = True,
) -> Verdict:
    """Map the evidence to one of the four explicit verdicts.

    Order of evidence (strongest first):
    1. Provider-confirmed threat match -> CONFIRMED_MALICIOUS (the only status
       that claims confirmed malice; only reliable external evidence may
       produce it).
    2. At least one *strong* finding (anything but a lone weak signal) ->
       SUSPICIOUS (something must be reviewed).
    3. Everything else -> UNKNOWN. This covers weak-signal-only results, no
       findings with an unavailable lookup, detection that could not run, and
       a completed lookup with no known threat. Absence of evidence is not
       evidence of safety, so ``VERIFIED_SAFE`` is never emitted by the
       current implementation (it is reserved for an explicit, documented
       positive-verification step that does not exist yet).
    """
    if reputation.status == ReputationStatus.THREAT_DETECTED:
        return Verdict.CONFIRMED_MALICIOUS
    if any(not _is_weak_signal(f) for f in findings):
        return Verdict.SUSPICIOUS
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
            "No known threats found; safety is not guaranteed. Google Safe "
            "Browsing returned no match for this URL."
        )

    if findings:
        titles = "; ".join(f.title for f in findings)
        parts.append(f"Detection engine(s) flagged: {titles}.")

    if not detection_ok:
        parts.append(
            "One or more detection engines failed during this analysis, so "
            "the URL could not be fully inspected - verification is needed."
        )

    if verdict == Verdict.UNKNOWN and findings:
        parts.append(
            "Only weak signals were observed and no independent signal "
            "corroborates them, so this result is unverified - verify manually "
            "before trusting this URL."
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
