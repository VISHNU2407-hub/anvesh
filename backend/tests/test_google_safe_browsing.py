import re
from pathlib import Path

import httpx
import pytest

from app.models import ReputationStatus
from app.threat_intel.google_safe_browsing import GoogleSafeBrowsingProvider


def provider_with(handler, api_key="test-key") -> GoogleSafeBrowsingProvider:
    return GoogleSafeBrowsingProvider(api_key=api_key, transport=httpx.MockTransport(handler))


async def test_missing_api_key_is_unavailable():
    provider = GoogleSafeBrowsingProvider(api_key=None)
    result = await provider.check("https://example.com")
    assert result.status == ReputationStatus.UNAVAILABLE
    assert result.error_reason == "missing_api_key"


async def test_empty_api_key_is_unavailable():
    provider = GoogleSafeBrowsingProvider(api_key="   ")
    result = await provider.check("https://example.com")
    assert result.status == ReputationStatus.UNAVAILABLE
    assert result.error_reason == "missing_api_key"


async def test_timeout_is_unavailable():
    def handler(request):
        raise httpx.TimeoutException("timed out")

    result = await provider_with(handler).check("https://example.com")
    assert result.status == ReputationStatus.UNAVAILABLE
    assert result.error_reason == "timeout"


async def test_connection_error_is_unavailable():
    def handler(request):
        raise httpx.ConnectError("boom")

    result = await provider_with(handler).check("https://example.com")
    assert result.status == ReputationStatus.UNAVAILABLE
    assert result.error_reason == "connection_error"


async def test_quota_exceeded():
    def handler(request):
        return httpx.Response(429, json={"error": {"status": "RESOURCE_EXHAUSTED"}})

    result = await provider_with(handler).check("https://example.com")
    assert result.status == ReputationStatus.UNAVAILABLE
    assert result.error_reason == "quota_exceeded"


async def test_auth_error():
    def handler(request):
        return httpx.Response(403, json={})

    result = await provider_with(handler).check("https://example.com")
    assert result.status == ReputationStatus.UNAVAILABLE
    assert result.error_reason == "auth_error"


async def test_bad_request():
    def handler(request):
        return httpx.Response(400, json={})

    result = await provider_with(handler).check("https://example.com")
    assert result.status == ReputationStatus.UNAVAILABLE
    assert result.error_reason == "bad_request"


async def test_server_error():
    def handler(request):
        return httpx.Response(500, json={})

    result = await provider_with(handler).check("https://example.com")
    assert result.status == ReputationStatus.UNAVAILABLE
    assert result.error_reason == "api_error"


async def test_no_matches_is_no_known_threat():
    def handler(request):
        return httpx.Response(200, json={})

    result = await provider_with(handler).check("https://example.com")
    assert result.status == ReputationStatus.NO_KNOWN_THREAT
    assert result.matches == []


async def test_matches_is_threat_detected():
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
                        "cacheDuration": "300.000s",
                    }
                ]
            },
        )

    result = await provider_with(handler).check("https://evil.example.com/")
    assert result.status == ReputationStatus.THREAT_DETECTED
    assert len(result.matches) == 1
    assert result.matches[0].threat_type == "MALWARE"


async def test_api_key_not_in_result():
    """Ensure the secret never leaks into the result object."""

    def handler(request):
        return httpx.Response(200, json={})

    provider = provider_with(handler, api_key="super-secret-key")
    result = await provider.check("https://example.com")
    assert "super-secret-key" not in repr(result)


async def test_request_body_shape():
    """Verify we send the documented threatMatches.find payload."""
    captured = {}

    def handler(request):
        captured["url"] = str(request.url)
        captured["json"] = request.read()
        return httpx.Response(200, json={})

    await provider_with(handler).check("https://example.com")
    assert captured["url"].startswith("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=test-key")
    body = captured["json"].decode()
    assert "threatInfo" in body
    assert "threatEntries" in body
    assert "MALWARE" in body


# --- Robustness: check() must NEVER raise, whatever goes wrong --------------


async def test_unexpected_exception_is_provider_error():
    """A non-httpx bug inside the provider degrades to 'provider_error'."""
    def handler(request):
        raise RuntimeError("boom")

    result = await provider_with(handler).check("https://example.com")
    assert result.status == ReputationStatus.UNAVAILABLE
    assert result.error_reason == "provider_error"


async def test_exception_text_never_leaks_api_key():
    """httpx exceptions embed the request URL (which carries ?key=...);
    the result must contain only a fixed, machine-readable reason."""
    secret = "super-secret-key"

    def handler(request):
        raise httpx.ConnectError(
            f"failed to connect: {request.url}"  # URL contains ?key=secret
        )

    result = await provider_with(handler, api_key=secret).check("https://example.com")
    assert result.status == ReputationStatus.UNAVAILABLE
    assert result.error_reason == "connection_error"
    assert secret not in repr(result)
    assert "key=" not in repr(result)


@pytest.mark.parametrize("body", [[], "ok", 42, None])
async def test_non_dict_response_is_invalid_response(body):
    """A malformed success body is NOT evidence of safety."""
    def handler(request):
        return httpx.Response(200, json=body)

    result = await provider_with(handler).check("https://example.com")
    assert result.status == ReputationStatus.UNAVAILABLE
    assert result.error_reason == "invalid_response"


# --- API key handling: environment-only, never hardcoded --------------------


def test_settings_read_key_from_environment(monkeypatch):
    from app.config import get_settings

    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "env-only-key-123")
    get_settings.cache_clear()
    try:
        assert get_settings().google_safe_browsing_api_key == "env-only-key-123"
    finally:
        get_settings.cache_clear()  # never leak the fixture value


def test_settings_missing_key_is_none(monkeypatch):
    from app.config import get_settings

    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_API_KEY", raising=False)
    get_settings.cache_clear()
    try:
        assert get_settings().google_safe_browsing_api_key is None
    finally:
        get_settings.cache_clear()


def test_no_hardcoded_api_key_in_source():
    """Static guard: no Google-API-key-looking literal anywhere in app/."""
    app_dir = Path(__file__).resolve().parents[1] / "app"
    sources = sorted(app_dir.rglob("*.py"))
    assert sources, "expected backend source files"
    key_literal = re.compile(r"AIza[0-9A-Za-z_\-]{20,}")
    assigned = re.compile(
        r"GOOGLE_SAFE_BROWSING_API_KEY[\"']?\s*=\s*[\"'][^\"']+"
    )
    for path in sources:
        text = path.read_text(encoding="utf-8")
        assert not key_literal.search(text), f"hardcoded key in {path}"
        assert not assigned.search(text), f"hardcoded value in {path}"


def test_env_files_are_gitignored_not_tracked():
    """Secrets live in environment files that git must ignore."""
    backend_dir = Path(__file__).resolve().parents[1]
    root_dir = backend_dir.parent
    assert ".env" in (backend_dir / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in (root_dir / ".gitignore").read_text(encoding="utf-8")
    # The template ships with an EMPTY key on purpose.
    template = (backend_dir / ".env.example").read_text(encoding="utf-8")
    assert "GOOGLE_SAFE_BROWSING_API_KEY=" in template
    assert "GOOGLE_SAFE_BROWSING_API_KEY=\"" not in template
