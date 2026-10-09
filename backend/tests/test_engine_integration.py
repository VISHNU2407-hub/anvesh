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

ALLOWED_SEVERITIES = {s.value for s in Severity}
ALLOWED_CONFIDENCE = {c.value for c in Confidence}
RESPONSE_KEYS = {
    "url",
    "risk_level",
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
