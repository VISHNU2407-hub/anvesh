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
