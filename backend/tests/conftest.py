"""Shared test fixtures."""

from __future__ import annotations

from typing import List

import pytest
from fastapi.testclient import TestClient

from app.main import app, get_reputation_provider
from app.models import ReputationMatch
from app.threat_intel.base import ReputationResult, ThreatIntelProvider


class FakeProvider(ThreatIntelProvider):
    """A reputation provider stub that returns a canned result."""

    name = "fake_provider"

    def __init__(self, result: ReputationResult) -> None:
        self._result = result
        self.seen_urls: List[str] = []

    async def check(self, url: str) -> ReputationResult:
        self.seen_urls.append(url)
        return self._result


def make_client(provider: ThreatIntelProvider) -> TestClient:
    app.dependency_overrides[get_reputation_provider] = lambda: provider
    return TestClient(app)


@pytest.fixture
def client_threat() -> TestClient:
    provider = FakeProvider(
        ReputationResult.threat_detected(
            "google_safe_browsing",
            [ReputationMatch(threat_type="MALWARE", platform_type="ANY_PLATFORM")],
        )
    )
    client = make_client(provider)
    yield client
    app.dependency_overrides.clear()


@pytest.fixture
def client_safe() -> TestClient:
    provider = FakeProvider(ReputationResult.no_known_threat("google_safe_browsing"))
    client = make_client(provider)
    yield client
    app.dependency_overrides.clear()


@pytest.fixture
def client_unavailable() -> TestClient:
    provider = FakeProvider(
        ReputationResult.unavailable("google_safe_browsing", "quota_exceeded")
    )
    client = make_client(provider)
    yield client
    app.dependency_overrides.clear()
