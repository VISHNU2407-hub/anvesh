from app.models import Confidence, Finding, ReputationStatus, RiskLevel, Severity
from app.scoring import build_response, compute_risk_level, compute_score
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
    for key in ("risk_level", "score", "findings", "reputation_status", "advice"):
        assert key in payload
    assert resp.reputation_status == ReputationStatus.UNAVAILABLE
    assert "quota_exceeded" in resp.advice
