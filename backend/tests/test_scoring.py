from app.models import Confidence, Finding, ReputationStatus, RiskLevel, Severity, Verdict
from app.scoring import build_response, compute_risk_level, compute_score, compute_verdict
from app.threat_intel.base import ReputationResult


def _finding(severity: Severity) -> Finding:
    return Finding(
        engine="test", title="test finding", severity=severity, confidence=Confidence.MEDIUM
    )


def test_confirmed_threat_is_high_risk():
    rep = ReputationResult.threat_detected("gsb", [])
    score = compute_score([], rep)
    assert score >= 75
    assert compute_risk_level(score, [], rep) == RiskLevel.HIGH


def test_unavailable_with_no_findings_is_unknown():
    rep = ReputationResult.unavailable("gsb", "timeout")
    score = compute_score([], rep)
    assert score == 0
    assert compute_risk_level(score, [], rep) == RiskLevel.UNKNOWN


def test_unavailable_with_findings_computes_from_findings():
    rep = ReputationResult.unavailable("gsb", "timeout")
    findings = [_finding(Severity.HIGH), _finding(Severity.HIGH)]
    score = compute_score(findings, rep)
    # 30 + 30 = 60, but the findings contribution is capped at 50.
    assert score == 50
    assert compute_risk_level(score, findings, rep) == RiskLevel.MEDIUM


def test_no_threat_no_findings_is_low_score_zero():
    rep = ReputationResult.no_known_threat("gsb")
    score = compute_score([], rep)
    assert score == 0
    assert compute_risk_level(score, [], rep) == RiskLevel.LOW


def test_findings_increase_score():
    rep = ReputationResult.no_known_threat("gsb")
    low = compute_score([_finding(Severity.LOW)], rep)
    crit = compute_score([_finding(Severity.CRITICAL)], rep)
    assert crit > low


def test_findings_capped():
    rep = ReputationResult.no_known_threat("gsb")
    many = [_finding(Severity.CRITICAL) for _ in range(10)]
    assert compute_score(many, rep) == 50


def test_build_response_shape():
    rep = ReputationResult.unavailable("gsb", "quota_exceeded")
    resp = build_response("https://example.com", [], rep)
    payload = resp.model_dump()
    for key in ("risk_level", "verdict", "score", "findings", "reputation_status", "advice"):
        assert key in payload
    assert resp.reputation_status == ReputationStatus.UNAVAILABLE
    assert "quota_exceeded" in resp.advice


# --- Verdicts: confirmed malicious / suspicious / unknown / verified safe ---


def test_verdict_confirmed_malicious_requires_threat_match():
    rep = ReputationResult.threat_detected("gsb", [])
    assert compute_verdict([], rep) == Verdict.CONFIRMED_MALICIOUS
    # Findings alone never confirm malice - only the provider match does.
    rep_clean = ReputationResult.no_known_threat("gsb")
    assert compute_verdict([_finding(Severity.CRITICAL)], rep_clean) != Verdict.CONFIRMED_MALICIOUS


def test_verdict_suspicious_when_findings_present():
    rep = ReputationResult.no_known_threat("gsb")
    assert compute_verdict([_finding(Severity.LOW)], rep) == Verdict.SUSPICIOUS
    # ...even when reputation is unavailable.
    rep_down = ReputationResult.unavailable("gsb", "timeout")
    assert compute_verdict([_finding(Severity.MEDIUM)], rep_down) == Verdict.SUSPICIOUS


def test_verdict_unknown_when_evidence_insufficient():
    # No findings + reputation unavailable: nothing matched, but nothing was
    # verified either -> UNKNOWN, never safe.
    rep = ReputationResult.unavailable("gsb", "timeout")
    assert compute_verdict([], rep) == Verdict.UNKNOWN


def test_verdict_verified_safe_requires_completed_lookup_and_clean_detection():
    rep = ReputationResult.no_known_threat("gsb")
    assert compute_verdict([], rep) == Verdict.VERIFIED_SAFE
    # Same clean findings but detection could NOT run -> not verified_safe.
    assert compute_verdict([], rep, detection_ok=False) == Verdict.UNKNOWN
    # Same clean detection but reputation unavailable -> not verified_safe.
    rep_down = ReputationResult.unavailable("gsb", "timeout")
    assert compute_verdict([], rep_down) == Verdict.UNKNOWN


def test_failed_detection_forces_unknown_risk_when_no_findings():
    rep = ReputationResult.no_known_threat("gsb")
    assert compute_risk_level(0, [], rep, detection_ok=False) == RiskLevel.UNKNOWN
    # ...but a completed clean run with no findings stays low.
    assert compute_risk_level(0, [], rep, detection_ok=True) == RiskLevel.LOW


def test_failed_detection_with_findings_stays_suspicious():
    rep = ReputationResult.unavailable("gsb", "timeout")
    findings = [_finding(Severity.HIGH)]
    verdict = compute_verdict(findings, rep, detection_ok=False)
    assert verdict == Verdict.SUSPICIOUS


def test_verdict_never_says_safe_from_missing_data():
    for rep in (
        ReputationResult.unavailable("gsb", "timeout"),
        ReputationResult.unavailable("gsb", "missing_api_key"),
    ):
        for detection_ok in (True, False):
            verdict = compute_verdict([], rep, detection_ok=detection_ok)
            assert verdict != Verdict.VERIFIED_SAFE
            assert verdict != Verdict.CONFIRMED_MALICIOUS
            assert verdict == Verdict.UNKNOWN


def test_build_response_verdicts():
    clean = build_response(
        "https://example.com", [], ReputationResult.no_known_threat("gsb")
    )
    assert clean.verdict == Verdict.VERIFIED_SAFE
    assert "not an absolute guarantee" in clean.advice

    crashed = build_response(
        "https://example.com", [], ReputationResult.no_known_threat("gsb"),
        detection_ok=False,
    )
    assert crashed.verdict == Verdict.UNKNOWN
    assert crashed.risk_level == RiskLevel.UNKNOWN
    assert "verification is needed" in crashed.advice
