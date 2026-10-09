"""Google Safe Browsing integration (Lookup API v4, threatMatches.find).

Verified against current Google docs (developers.google.com/safe-browsing):
- Endpoint: POST https://safebrowsing.googleapis.com/v4/threatMatches:find?key=API_KEY
- Request body: client.{clientId,clientVersion} + threatInfo{threatTypes,
  platformTypes, threatEntryTypes, threatEntries[].url}
- Response: {} (empty) means NO match; {matches:[...]} means a confirmed match.
- Terms: Safe Browsing APIs are for NON-COMMERCIAL use only. Commercial users
  should use the Web Risk API instead.

Security notes:
- The API key is only used server-side and is never returned to the client.
- We send the URL string to Google for lookup; we NEVER fetch/open the URL here.
- All failures (missing key, timeout, quota, auth, API errors) map to an
  UNAVAILABLE result with a machine-readable reason instead of raising.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import httpx

from ..models import ReputationMatch
from .base import ReputationResult, ThreatIntelProvider

GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# Threat/platform types requested from Google. Combining with entry type URL
# names valid Safe Browsing lists.
THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]
PLATFORM_TYPES = ["ANY_PLATFORM"]
THREAT_ENTRY_TYPES = ["URL"]


class GoogleSafeBrowsingProvider(ThreatIntelProvider):
    name = "google_safe_browsing"

    def __init__(
        self,
        api_key: Optional[str],
        client_id: str = "linkshield-ai",
        client_version: str = "0.3.0",
        timeout: float = 5.0,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        self._api_key = (api_key or "").strip() or None
        self._client_id = client_id
        self._client_version = client_version
        self._timeout = timeout
        # Injectable transport for tests (httpx.MockTransport).
        self._transport = transport

    def _build_payload(self, url: str) -> Dict[str, Any]:
        return {
            "client": {
                "clientId": self._client_id,
                "clientVersion": self._client_version,
            },
            "threatInfo": {
                "threatTypes": THREAT_TYPES,
                "platformTypes": PLATFORM_TYPES,
                "threatEntryTypes": THREAT_ENTRY_TYPES,
                "threatEntries": [{"url": url}],
            },
        }

    @staticmethod
    def _parse_matches(data: Dict[str, Any]) -> List[ReputationMatch]:
        matches: List[ReputationMatch] = []
        for m in data.get("matches", []) or []:
            threat = m.get("threat", {}) or {}
            matches.append(
                ReputationMatch(
                    threat_type=m.get("threatType", "UNKNOWN"),
                    platform_type=m.get("platformType"),
                    threat_entry_type=m.get("threatEntryType"),
                )
            )
            # Keep a reference so linters don't flag the unused local.
            _ = threat.get("url")
        return matches

    async def check(self, url: str) -> ReputationResult:
        if not self._api_key:
            return ReputationResult.unavailable(self.name, "missing_api_key")

        request_url = f"{GSB_ENDPOINT}?key={self._api_key}"
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout, transport=self._transport
            ) as client:
                resp = await client.post(request_url, json=self._build_payload(url))
        except httpx.TimeoutException:
            return ReputationResult.unavailable(self.name, "timeout")
        except httpx.HTTPError:
            return ReputationResult.unavailable(self.name, "connection_error")

        if resp.status_code == 200:
            try:
                data = resp.json()
            except ValueError:
                return ReputationResult.unavailable(self.name, "invalid_response")
            matches = self._parse_matches(data or {})
            if not matches:
                return ReputationResult.no_known_threat(self.name)
            return ReputationResult.threat_detected(self.name, matches)

        # Map HTTP error codes to honest "unavailable" reasons.
        if resp.status_code == 429:
            reason = "quota_exceeded"
        elif resp.status_code == 400:
            reason = "bad_request"
        elif resp.status_code in (401, 403):
            reason = "auth_error"
        else:
            reason = "api_error"
        return ReputationResult.unavailable(self.name, reason)
