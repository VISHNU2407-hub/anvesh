from app.models import Confidence, Finding, ReputationStatus, RiskLevel, Severity, Verdict
from app.scoring import (
    THREAT_SCORE_FLOOR,
    build_response,
    compute_risk_level,
    compute_score,
    compute_verdict,
)
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


def test_verdict_never_verified_safe_without_explicit_verification():
    # A completed lookup with NO match is NOT proof of safety: the result is
    # unknown (needs verification), never verified_safe.
    rep = ReputationResult.no_known_threat("gsb")
    assert compute_verdict([], rep) == Verdict.UNKNOWN
    # Same when detection could NOT run.
    assert compute_verdict([], rep, detection_ok=False) == Verdict.UNKNOWN
    # Same when reputation was unavailable.
    rep_down = ReputationResult.unavailable("gsb", "timeout")
    assert compute_verdict([], rep_down) == Verdict.UNKNOWN


def test_verdict_verified_safe_is_never_emitted():
    """Regression: GSB "no match" must not be reported as verified_safe."""
    for reputation in (
        ReputationResult.no_known_threat("gsb"),
        ReputationResult.unavailable("gsb", "timeout"),
    ):
        for detection_ok in (True, False):
            for findings in ([], [_finding(Severity.LOW)]):
                assert compute_verdict(findings, reputation, detection_ok) != Verdict.VERIFIED_SAFE


# --- Risk-level / finding-severity consistency ------------------------------

HIGH_FINDING = Finding(
    engine="linkshield_rule_engine",
    rule_id="lookalike_domain",
    title="Possible lookalike domain",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
)


def _rule_finding(rule_id: str, severity: Severity, confidence=Confidence.MEDIUM) -> Finding:
    return Finding(
        engine="linkshield_rule_engine",
        rule_id=rule_id,
        title=rule_id,
        severity=severity,
        confidence=confidence,
    )


def test_high_severity_finding_never_reports_low_risk():
    """A single HIGH finding scores 30, but the risk level must not be 'low'."""
    rep = ReputationResult.no_known_threat("gsb")
    findings = [HIGH_FINDING]
    score = compute_score(findings, rep)
    assert score == 30
    assert compute_risk_level(score, findings, rep) == RiskLevel.MEDIUM
    assert compute_verdict(findings, rep) == Verdict.SUSPICIOUS


def test_userinfo_trick_high_confidence_is_medium_not_low():
    rep = ReputationResult.no_known_threat("gsb")
    findings = [
        _rule_finding("userinfo_trick", Severity.HIGH, Confidence.HIGH)
    ]
    score = compute_score(findings, rep)
    assert score == 30
    assert compute_risk_level(score, findings, rep) == RiskLevel.MEDIUM
    # ...and still only suspicious, never confirmed malicious.
    assert compute_verdict(findings, rep) == Verdict.SUSPICIOUS


def test_critical_finding_does_not_become_confirmed_malicious():
    rep = ReputationResult.no_known_threat("gsb")
    findings = [_rule_finding("redirect_to_dangerous_scheme", Severity.CRITICAL)]
    assert compute_verdict(findings, rep) == Verdict.SUSPICIOUS
    assert compute_risk_level(compute_score(findings, rep), findings, rep) in {
        RiskLevel.MEDIUM,
        RiskLevel.HIGH,
    }


def test_score_thresholds_are_clear_and_monotonic():
    rep = ReputationResult.no_known_threat("gsb")
    assert compute_risk_level(39, [], rep) == RiskLevel.LOW
    assert compute_risk_level(40, [], rep) == RiskLevel.MEDIUM
    assert compute_risk_level(69, [], rep) == RiskLevel.MEDIUM
    assert compute_risk_level(70, [], rep) == RiskLevel.HIGH


def test_confirmed_threat_dominates_any_findings():
    """A provider match is high risk + confirmed_malicious, whatever else fired."""
    rep = ReputationResult.threat_detected("gsb", [])
    findings = [_rule_finding("suspicious_keywords", Severity.MEDIUM)]
    score = compute_score(findings, rep)
    assert score == THREAT_SCORE_FLOOR == 75
    assert compute_risk_level(score, findings, rep) == RiskLevel.HIGH
    assert compute_verdict(findings, rep) == Verdict.CONFIRMED_MALICIOUS


def test_benign_url_is_low_risk_but_unknown_verdict():
    """A clean URL is low risk yet NOT verified safe (no proof of safety)."""
    rep = ReputationResult.no_known_threat("gsb")
    assert compute_score([], rep) == 0
    assert compute_risk_level(0, [], rep) == RiskLevel.LOW
    assert compute_verdict([], rep) == Verdict.UNKNOWN


# --- Weak signals (credential-lure keywords) --------------------------------


def test_keyword_only_finding_is_not_suspicious():
    """A lone keyword match is weak evidence -> unknown, not suspicious."""
    rep = ReputationResult.no_known_threat("gsb")
    findings = [_rule_finding("suspicious_keywords", Severity.MEDIUM)]
    assert compute_score(findings, rep) == 15
    assert compute_verdict(findings, rep) == Verdict.UNKNOWN
    # Weak evidence stays low risk (it never reaches medium/high).
    assert compute_risk_level(15, findings, rep) == RiskLevel.LOW


def test_keyword_plus_independent_signal_is_suspicious():
    """Keywords corroborated by an independent finding do count."""
    rep = ReputationResult.no_known_threat("gsb")
    findings = [
        _rule_finding("suspicious_keywords", Severity.MEDIUM),
        _rule_finding("plain_http_scheme", Severity.MEDIUM),
    ]
    assert compute_verdict(findings, rep) == Verdict.SUSPICIOUS


def test_two_weak_keyword_findings_still_unknown():
    rep = ReputationResult.no_known_threat("gsb")
    findings = [_rule_finding("suspicious_keywords", Severity.MEDIUM) for _ in range(2)]
    assert compute_verdict(findings, rep) == Verdict.UNKNOWN


def test_build_response_verdicts():
    clean = build_response(
        "https://example.com", [], ReputationResult.no_known_threat("gsb")
    )
    # No known threat is not proof of safety: unknown, clearly explained.
    assert clean.verdict == Verdict.UNKNOWN
    assert clean.risk_level == RiskLevel.LOW
    assert "No known threats found; safety is not guaranteed." in clean.advice

    crashed = build_response(
        "https://example.com", [], ReputationResult.no_known_threat("gsb"),
        detection_ok=False,
    )
    assert crashed.verdict == Verdict.UNKNOWN
    assert crashed.risk_level == RiskLevel.UNKNOWN
    assert "verification is needed" in crashed.advice


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
