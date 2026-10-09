"""Integration tests: the REAL rule-based engine behind POST /api/analyze.

These tests use the engine registered at application startup
(``LinkShieldDetectionEngine``) and verify, through the HTTP endpoint, that:

- the engine is registered under a unique name and honors the contract,
- valid / suspicious / malformed URLs behave as documented,
- engine errors are isolated and never fail the request,
- the expected JSON response shape is returned,
- detection performs no network I/O on the submitted URL.

No real API key and no internet access are required.
"""

from __future__ import annotations

import socket
from pathlib import Path

from app.detection import DetectionContext, get_engines
from app.detection import linkshield_engine as engine_module
from app.detection.engine import DetectionEngine
from app.detection.linkshield_engine import ENGINE_NAME, LinkShieldDetectionEngine
from app.models import Confidence, Finding, Severity

BENIGN_URL = "https://example.com/"
# Suspicious on several independent rules: raw IP host, plain http,
# open-redirect query parameter, credential-lure path wording.
SUSPICIOUS_URL = "http://192.168.10.5/login?redirect=http://evil.test/"
# New rule coverage: typosquat brand, obfuscated IP, offsite redirect target.
LOOKALIKE_URL = "https://paypa1.com/login"
OBFUSCATED_IP_URL = "http://2130706433/login"
OFFSITE_REDIRECT_URL = (
    "https://example.com/out?redirect=https%3A%2F%2Fevil.test/phish"
)

ALLOWED_SEVERITIES = {s.value for s in Severity}
ALLOWED_CONFIDENCE = {c.value for c in Confidence}
RESPONSE_KEYS = {
    "url",
    "risk_level",
    "verdict",
    "score",
    "findings",
    "reputation_status",
    "advice",
    "reputation",
}
FINDING_KEYS = {"engine", "rule_id", "title", "description", "severity", "confidence"}


def _context(url: str) -> DetectionContext:
    from urllib.parse import urlparse

    host = urlparse(url).hostname or ""
    return DetectionContext(url=url, normalized_url=url, host=host)


# --- Contract of the registered engine --------------------------------------


def test_real_engine_registered_with_unique_name():
    engines = get_engines()
    names = [e.name for e in engines]
    assert ENGINE_NAME in names, "real engine must be registered at startup"
    assert names.count(ENGINE_NAME) == 1, "engine name must be unique"
    # Unique against every other registered engine, not just itself.
    assert ENGINE_NAME != "placeholder"


def test_engine_implements_detection_engine_interface():
    engine = LinkShieldDetectionEngine()
    assert isinstance(engine, DetectionEngine)
    assert engine.name == ENGINE_NAME
    assert callable(engine.analyze)
    # analyze(context) -> List[Finding]
    findings = engine.analyze(_context(BENIGN_URL))
    assert isinstance(findings, list)
    assert all(isinstance(f, Finding) for f in findings)


def test_engine_uses_permitted_severity_and_confidence_values():
    engine = LinkShieldDetectionEngine()
    findings = engine.analyze(_context(SUSPICIOUS_URL))
    assert findings, "suspicious URL must produce findings from the real engine"
    for f in findings:
        assert isinstance(f, Finding)
        assert f.engine == ENGINE_NAME
        assert f.severity.value in ALLOWED_SEVERITIES
        assert f.confidence.value in ALLOWED_CONFIDENCE
        assert f.rule_id, "every finding must name the rule that fired"
        assert f.title


def test_engine_reports_malformed_and_dangerous_input_without_crashing():
    engine = LinkShieldDetectionEngine()
    for url, expected_rule in (
        ("not-a-url", "malformed_input"),
        ("javascript:alert(1)", "dangerous_scheme"),
    ):
        findings = engine.analyze(_context(url))
        assert findings, f"{url!r} must be reported, not silently accepted"
        assert {f.rule_id for f in findings} == {expected_rule}
        assert all(f.severity.value in ALLOWED_SEVERITIES for f in findings)


def test_engine_source_contains_no_network_access():
    """Static guard: the adapter never fetches or opens submitted URLs."""
    source = Path(engine_module.__file__).read_text(encoding="utf-8")
    for token in ("urlopen", "socket.", "requests.", "httpx.", "urllib.request"):
        assert token not in source, f"unexpected network API in adapter: {token}"


# --- Through the endpoint ----------------------------------------------------


def test_valid_url_returns_expected_json(client_safe):
    resp = client_safe.post("/api/analyze", json={"url": BENIGN_URL})
    assert resp.status_code == 200
    data = resp.json()
    assert set(data.keys()) == RESPONSE_KEYS
    assert data["url"] == BENIGN_URL
    assert data["reputation_status"] == "no_known_threat"
    assert isinstance(data["findings"], list)
    for f in data["findings"]:
        assert set(f.keys()) == FINDING_KEYS
        assert f["engine"] == ENGINE_NAME
        assert f["severity"] in ALLOWED_SEVERITIES
        assert f["confidence"] in ALLOWED_CONFIDENCE
    assert 0 <= data["score"] <= 100
    assert data["advice"]
    assert data["verdict"] in {
        "confirmed_malicious", "suspicious", "unknown", "verified_safe"
    }


def test_lookalike_domain_detected_through_endpoint(client_safe):
    resp = client_safe.post("/api/analyze", json={"url": LOOKALIKE_URL})
    assert resp.status_code == 200
    data = resp.json()
    rule_ids = {f["rule_id"] for f in data["findings"]}
    assert "lookalike_domain" in rule_ids
    assert data["verdict"] == "suspicious"
    assert data["risk_level"] in {"medium", "high"}
    assert any(f["confidence"] in ALLOWED_CONFIDENCE for f in data["findings"])


def test_obfuscated_ip_detected_through_endpoint(client_safe):
    resp = client_safe.post("/api/analyze", json={"url": OBFUSCATED_IP_URL})
    assert resp.status_code == 200
    data = resp.json()
    rule_ids = {f["rule_id"] for f in data["findings"]}
    assert "encoded_ip_host" in rule_ids
    assert data["verdict"] == "suspicious"


def test_offsite_redirect_detected_through_endpoint(client_safe):
    resp = client_safe.post("/api/analyze", json={"url": OFFSITE_REDIRECT_URL})
    assert resp.status_code == 200
    data = resp.json()
    rule_ids = {f["rule_id"] for f in data["findings"]}
    assert "redirect_parameter" in rule_ids
    assert "redirect_to_external_host" in rule_ids


def test_normal_url_with_clean_reputation_is_unknown_not_verified_safe(client_safe):
    """GSB 'no match' is not proof of safety -> unknown, clearly caveated."""
    resp = client_safe.post("/api/analyze", json={"url": BENIGN_URL})
    assert resp.status_code == 200
    data = resp.json()
    assert data["findings"] == []
    assert data["reputation_status"] == "no_known_threat"
    assert data["verdict"] == "unknown"
    assert data["risk_level"] == "low"
    # The user-facing explanation is explicit that this is not a guarantee.
    assert "No known threats found; safety is not guaranteed." in data["advice"]


# --- Regression: reported risk/verdict consistency cases ---------------------

LOOKALIKE_BARE_URL = "https://paypa1.com/"
USERINFO_TRICK_URL = "https://example.com@evil.test/"
LOGIN_KEYWORD_URL = "https://login.example.com/"
KEYWORD_LURE_URL = "https://secure-account-verify.example.com/login"


def test_paypa1_lookalike_is_suspicious_medium_not_low(client_safe):
    """A HIGH lookalike finding must not be reported under a LOW risk level."""
    resp = client_safe.post("/api/analyze", json={"url": LOOKALIKE_BARE_URL})
    assert resp.status_code == 200
    data = resp.json()
    lookalike = [f for f in data["findings"] if f["rule_id"] == "lookalike_domain"]
    assert lookalike and lookalike[0]["severity"] == "high"
    assert data["verdict"] == "suspicious"
    assert data["score"] == 30
    assert data["risk_level"] == "medium"


def test_userinfo_trick_is_suspicious_medium_not_low(client_safe):
    resp = client_safe.post("/api/analyze", json={"url": USERINFO_TRICK_URL})
    assert resp.status_code == 200
    data = resp.json()
    trick = [f for f in data["findings"] if f["rule_id"] == "userinfo_trick"]
    assert trick and trick[0]["severity"] == "high"
    assert trick[0]["confidence"] == "high"
    assert data["verdict"] == "suspicious"
    assert data["score"] == 30
    assert data["risk_level"] == "medium"


def test_keyword_only_login_is_unknown_not_suspicious(client_safe):
    """A lone keyword match is weak evidence: unknown, never suspicious."""
    resp = client_safe.post("/api/analyze", json={"url": LOGIN_KEYWORD_URL})
    assert resp.status_code == 200
    data = resp.json()
    assert [f["rule_id"] for f in data["findings"]] == ["suspicious_keywords"]
    assert data["verdict"] == "unknown"
    assert data["risk_level"] == "low"
    assert data["score"] == 15


def test_keyword_only_lure_is_unknown_with_score_15(client_safe):
    resp = client_safe.post("/api/analyze", json={"url": KEYWORD_LURE_URL})
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "unknown"
    assert data["score"] == 15


def test_keyword_plus_independent_signal_still_suspicious(client_safe):
    """Keyword wording corroborated by another signal stays suspicious."""
    # plain http + keyword wording + open-redirect parameter.
    url = "http://login.example.com/verify?redirect=http://evil.test/"
    resp = client_safe.post("/api/analyze", json={"url": url})
    assert resp.status_code == 200
    data = resp.json()
    rule_ids = {f["rule_id"] for f in data["findings"]}
    assert "suspicious_keywords" in rule_ids
    assert any(r in rule_ids for r in ("plain_http_scheme", "redirect_parameter"))
    assert data["verdict"] == "suspicious"


def test_engine_failure_yields_unknown_not_verified_safe(client_safe, monkeypatch):
    """False-negative guard: a crashed engine means MISSING evidence,
    so the result must be unknown/needs-verification, never verified_safe."""
    def boom(self, context):
        raise RuntimeError("engine blew up")

    monkeypatch.setattr(LinkShieldDetectionEngine, "analyze", boom)
    resp = client_safe.post("/api/analyze", json={"url": BENIGN_URL})
    assert resp.status_code == 200
    data = resp.json()
    assert data["findings"] == []
    assert data["verdict"] == "unknown"
    assert data["risk_level"] == "unknown"
    assert "verification" in data["advice"]


def test_real_engine_invoked_for_suspicious_url(client_safe):
    resp = client_safe.post("/api/analyze", json={"url": SUSPICIOUS_URL})
    assert resp.status_code == 200
    data = resp.json()

    # Findings prove the registered engine actually ran in the pipeline.
    assert data["findings"], "expected findings from the real engine"
    assert all(f["engine"] == ENGINE_NAME for f in data["findings"])
    rule_ids = {f["rule_id"] for f in data["findings"]}
    assert "ip_address_host" in rule_ids
    assert "plain_http_scheme" in rule_ids
    assert "redirect_parameter" in rule_ids

    assert data["score"] > 0
    assert data["risk_level"] in {"medium", "high"}
    assert "flagged" in data["advice"]
    assert data["reputation_status"] == "no_known_threat"


def test_malformed_urls_rejected_with_400(client_safe):
    for bad in (
        "not-a-url",
        "",
        "ftp://example.com",
        "javascript:alert(1)",
        "https://",
        "http://",
    ):
        resp = client_safe.post("/api/analyze", json={"url": bad})
        assert resp.status_code == 400, f"expected 400 for {bad!r}"
        assert resp.json()["detail"]


def test_engine_not_invoked_for_malformed_url(client_safe, monkeypatch):
    calls = []
    original = LinkShieldDetectionEngine.analyze

    def spy(self, context):
        calls.append(context)
        return original(self, context)

    monkeypatch.setattr(LinkShieldDetectionEngine, "analyze", spy)
    resp = client_safe.post("/api/analyze", json={"url": "not-a-url"})
    assert resp.status_code == 400
    assert calls == [], "invalid input must be rejected before detection runs"


def test_engine_error_is_isolated_and_request_still_succeeds(client_safe, monkeypatch):
    def boom(self, context):
        raise RuntimeError("engine blew up")

    monkeypatch.setattr(LinkShieldDetectionEngine, "analyze", boom)
    resp = client_safe.post("/api/analyze", json={"url": SUSPICIOUS_URL})
    assert resp.status_code == 200
    data = resp.json()
    # The crashed engine contributes nothing; the response stays honest.
    assert data["findings"] == []
    assert data["score"] == 0
    assert data["reputation_status"] == "no_known_threat"
    assert set(data.keys()) == RESPONSE_KEYS


def test_endpoint_performs_no_network_io(client_safe, monkeypatch):
    """Block outbound connections: detection must never fetch/open the URL."""

    _LOCAL = {"127.0.0.1", "::1", "localhost"}
    _orig_connect = socket.socket.connect
    _orig_connect_ex = socket.socket.connect_ex

    def _blocked(*args, **kwargs):
        raise AssertionError("network access attempted while analyzing a URL")

    def _guarded_connect(sock, address, *args, **kwargs):
        # The test harness's event loop uses a local socketpair self-pipe;
        # anything targeting a non-loopback host would be a real fetch.
        host = address[0] if isinstance(address, (tuple, list)) and address else address
        if isinstance(host, str) and host in _LOCAL:
            return _orig_connect(sock, address, *args, **kwargs)
        raise AssertionError(
            f"network access attempted while analyzing a URL: {address!r}"
        )

    def _guarded_connect_ex(sock, address, *args, **kwargs):
        host = address[0] if isinstance(address, (tuple, list)) and address else address
        if isinstance(host, str) and host in _LOCAL:
            return _orig_connect_ex(sock, address, *args, **kwargs)
        raise AssertionError(
            f"network access attempted while analyzing a URL: {address!r}"
        )

    # DNS resolution and outbound TCP are both blocked (loopback excepted).
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
    monkeypatch.setattr(socket, "gethostbyname", _blocked)
    monkeypatch.setattr(socket.socket, "connect", _guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", _guarded_connect_ex)

    resp = client_safe.post("/api/analyze", json={"url": SUSPICIOUS_URL})
    assert resp.status_code == 200
    data = resp.json()
    assert data["findings"], "detection must still work with sockets blocked"
