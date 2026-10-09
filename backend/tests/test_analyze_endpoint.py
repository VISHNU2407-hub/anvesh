import httpx

from app.detection import DetectionContext, DetectionEngine, get_engines, register_engine
from app.detection.registry import clear_engines
from app.main import app
from app.models import Finding, Severity
from app.threat_intel.base import ThreatIntelProvider
from app.threat_intel.google_safe_browsing import GoogleSafeBrowsingProvider

from .conftest import make_client

ALLOWED_VERDICTS = {"confirmed_malicious", "suspicious", "unknown", "verified_safe"}


class _FlagEngine(DetectionEngine):
    name = "flag_engine"

    def analyze(self, context: DetectionContext):
        return [Finding(engine=self.name, title="lookalike domain", severity=Severity.MEDIUM)]


class _CrashEngine(DetectionEngine):
    name = "crash_engine"

    def analyze(self, context: DetectionContext):
        raise RuntimeError("engine blew up")


class _ContextManager:
    """Yield a TestClient wired to the REAL provider, cleaning up overrides."""

    def __init__(self, provider):
        self._provider = provider

    def __enter__(self):
        return make_client(self._provider)

    def __exit__(self, *exc):
        app.dependency_overrides.clear()
        return False


def gsb_client(handler, api_key="test-key"):
    """Client wired to the real GoogleSafeBrowsingProvider (mocked transport)."""
    provider = GoogleSafeBrowsingProvider(
        api_key=api_key, transport=httpx.MockTransport(handler)
    )
    return _ContextManager(provider)


def _no_key_client():
    """Client wired to the real provider with NO API key configured."""
    return _ContextManager(GoogleSafeBrowsingProvider(api_key=None))


def test_invalid_url_returns_400(client_threat):
    resp = client_threat.post("/api/analyze", json={"url": "not-a-url"})
    assert resp.status_code == 400


def test_disallowed_scheme_returns_400(client_threat):
    resp = client_threat.post("/api/analyze", json={"url": "ftp://example.com"})
    assert resp.status_code == 400


def test_confirmed_threat_response(client_threat):
    resp = client_threat.post("/api/analyze", json={"url": "https://evil.example.com/"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["reputation_status"] == "threat_detected"
    assert data["verdict"] == "confirmed_malicious"  # reliable external evidence
    assert data["risk_level"] == "high"
    assert data["score"] >= 75
    assert isinstance(data["findings"], list)
    assert data["advice"]


def test_no_known_threat_response(client_safe):
    resp = client_safe.post("/api/analyze", json={"url": "https://example.com/"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["reputation_status"] == "no_known_threat"
    assert data["risk_level"] == "low"
    assert data["score"] == 0
    # Clean reputation + clean detection = the only path to verified_safe.
    assert data["verdict"] == "verified_safe"


def test_unavailable_response(client_unavailable):
    resp = client_unavailable.post("/api/analyze", json={"url": "https://example.com/"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["reputation_status"] == "unavailable"
    assert data["risk_level"] == "unknown"
    # No findings + unavailable reputation = insufficient evidence.
    assert data["verdict"] == "unknown"
    assert data["reputation"]["error_reason"] == "quota_exceeded"


def test_required_fields_always_present(client_safe):
    resp = client_safe.post("/api/analyze", json={"url": "https://example.com/"})
    data = resp.json()
    for key in ("risk_level", "score", "findings", "reputation_status", "advice"):
        assert key in data


def test_no_api_key_leak(client_threat):
    resp = client_threat.post("/api/analyze", json={"url": "https://evil.example.com/"})
    body = resp.text
    assert "GOOGLE_SAFE_BROWSING_API_KEY" not in body
    # The provider name may appear, but never a key-looking secret.
    assert "key=" not in body


def test_detection_engine_findings_included(client_safe):
    original = get_engines()
    clear_engines()
    try:
        register_engine(_FlagEngine())
        resp = client_safe.post("/api/analyze", json={"url": "https://example.com/"})
        data = resp.json()
        assert any(f["engine"] == "flag_engine" for f in data["findings"])
        # A medium finding should raise the score above 0 and risk above low.
        assert data["score"] > 0
    finally:
        clear_engines()
        for e in original:
            register_engine(e)


def test_url_is_normalized_in_response(client_safe):
    resp = client_safe.post("/api/analyze", json={"url": "  https://Example.com/path  "})
    data = resp.json()
    assert data["url"] == "https://Example.com/path"


# --- End-to-end tests through the REAL GoogleSafeBrowsingProvider -----------
# These exercise the full pipeline (validate -> detect -> GSB lookup -> score)
# with all network calls mocked. No real API key or internet is required.


def test_e2e_successful_analysis_real_provider():
    def handler(request):
        return httpx.Response(200, json={})  # GSB: no known threat

    with gsb_client(handler) as client:
        original = get_engines()
        clear_engines()
        try:
            register_engine(_FlagEngine())
            resp = client.post("/api/analyze", json={"url": "https://example.com/"})
        finally:
            clear_engines()
            for e in original:
                register_engine(e)

    assert resp.status_code == 200
    data = resp.json()
    # Detection findings are present and reputation is no_known_threat.
    assert any(f["engine"] == "flag_engine" for f in data["findings"])
    assert data["reputation_status"] == "no_known_threat"
    assert data["score"] > 0  # the medium finding adds score
    assert data["advice"]


def test_e2e_confirmed_threat_real_provider():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "matches": [
                    {
                        "threatType": "MALWARE",
                        "platformType": "ANY_PLATFORM",
                        "threatEntryType": "URL",
                        "threat": {"url": "https://evil.example.com/"},
                    }
                ]
            },
        )

    with gsb_client(handler) as client:
        resp = client.post("/api/analyze", json={"url": "https://evil.example.com/"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["reputation_status"] == "threat_detected"
    assert data["risk_level"] == "high"
    assert data["score"] >= 75
    assert data["reputation"]["matches"][0]["threat_type"] == "MALWARE"
    assert "MALWARE" in data["advice"]


def test_e2e_no_known_match_real_provider():
    def handler(request):
        return httpx.Response(200, json={})

    with gsb_client(handler) as client:
        resp = client.post("/api/analyze", json={"url": "https://example.com/"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["reputation_status"] == "no_known_threat"
    assert data["risk_level"] == "low"
    assert data["score"] == 0
    assert data["findings"] == []


def test_e2e_unavailable_timeout_real_provider():
    def handler(request):
        raise httpx.TimeoutException("timed out")

    with gsb_client(handler) as client:
        resp = client.post("/api/analyze", json={"url": "https://example.com/"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["reputation_status"] == "unavailable"
    assert data["risk_level"] == "unknown"  # we never claim it is safe
    assert data["reputation"]["error_reason"] == "timeout"


def test_e2e_unavailable_quota_real_provider():
    def handler(request):
        return httpx.Response(429, json={"error": {"status": "RESOURCE_EXHAUSTED"}})

    with gsb_client(handler) as client:
        resp = client.post("/api/analyze", json={"url": "https://example.com/"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["reputation_status"] == "unavailable"
    assert data["reputation"]["error_reason"] == "quota_exceeded"


def test_e2e_missing_api_key_endpoint():
    """No key configured -> honest 'unavailable/missing_api_key', never a crash."""
    with _no_key_client() as client:
        resp = client.post("/api/analyze", json={"url": "https://example.com/"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["reputation_status"] == "unavailable"
    assert data["risk_level"] == "unknown"
    # Missing evidence must never be labelled safe or verified_safe.
    assert data["verdict"] == "unknown"
    assert data["reputation"]["error_reason"] == "missing_api_key"
    # The advice explicitly declines to draw a conclusion.
    assert "No conclusion about known threats can be drawn" in data["advice"]


class _BoomProvider(ThreatIntelProvider):
    """A provider that violates the never-raise contract."""

    name = "boom_provider"

    async def check(self, url: str):
        raise RuntimeError("provider exploded with key=super-secret-key inside")


def test_provider_exception_degrades_gracefully():
    """A provider bug must degrade to 'unavailable', never a 500."""
    with _ContextManager(_BoomProvider()) as client:
        resp = client.post("/api/analyze", json={"url": "https://example.com/"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["reputation_status"] == "unavailable"
    assert data["reputation"]["error_reason"] == "provider_error"
    assert data["risk_level"] == "unknown"
    assert data["verdict"] == "unknown"
    # Raw exception text (which may embed secrets) never reaches the client.
    assert "super-secret-key" not in resp.text


def test_e2e_detection_engine_failure_isolated():
    """A crashing detection engine must not fail the request."""
    def handler(request):
        return httpx.Response(200, json={})

    with gsb_client(handler) as client:
        original = get_engines()
        clear_engines()
        try:
            register_engine(_CrashEngine())
            register_engine(_FlagEngine())  # a healthy engine still runs
            resp = client.post("/api/analyze", json={"url": "https://example.com/"})
        finally:
            clear_engines()
            for e in original:
                register_engine(e)

    assert resp.status_code == 200
    data = resp.json()
    # The crashing engine is skipped; the healthy engine's finding survives.
    assert any(f["engine"] == "flag_engine" for f in data["findings"])
    assert not any(f["engine"] == "crash_engine" for f in data["findings"])
    assert data["reputation_status"] == "no_known_threat"


def test_e2e_response_matches_frontend_contract():
    """Assert the exact shape the frontend consumes."""
    def handler(request):
        return httpx.Response(
            200,
            json={"matches": [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": "https://phish.example/"}}]},
        )

    with gsb_client(handler) as client:
        resp = client.post("/api/analyze", json={"url": "https://phish.example/"})

    data = resp.json()
    assert set(data.keys()) == {
        "url", "risk_level", "verdict", "score", "findings",
        "reputation_status", "advice", "reputation",
    }
    assert data["risk_level"] in {"unknown", "low", "medium", "high"}
    assert data["verdict"] in ALLOWED_VERDICTS
    assert 0 <= data["score"] <= 100
    assert data["reputation_status"] in {"threat_detected", "no_known_threat", "unavailable"}
    assert set(data["reputation"].keys()) == {"provider", "status", "matches", "error_reason"}
