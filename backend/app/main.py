"""LinkShield AI backend - FastAPI application.

Exposes POST /api/analyze. Security invariants:
- The Google API key stays server-side and is never returned in a response.
- Submitted URLs are NEVER fetched or opened by this service; they are only
  validated and sent (as a string) to Google Safe Browsing for lookup.
"""

from __future__ import annotations

from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException
from starlette.concurrency import run_in_threadpool

from .config import get_settings
from .detection import DetectionContext, register_engine, run_detection
from .detection.linkshield_engine import LinkShieldDetectionEngine
from .models import AnalyzeRequest, AnalyzeResponse
from .scoring import build_response
from .threat_intel.base import ThreatIntelProvider
from .threat_intel.google_safe_browsing import GoogleSafeBrowsingProvider
from .url_validator import InvalidURLError, validate_and_normalize_url

app = FastAPI(
    title="LinkShield AI Backend",
    version="0.3.0",
    description="Part 3: Backend + Threat Intelligence Integration",
)

# Register the real rule-based detection engine at application startup using
# the existing registry mechanism (this module is imported when the app
# starts, e.g. `uvicorn app.main:app`). The no-op placeholder stays
# registered as the pipeline's baseline engine; findings come from
# LinkShieldDetectionEngine.
register_engine(LinkShieldDetectionEngine())


def get_reputation_provider() -> ThreatIntelProvider:
    """Build the reputation provider from settings (overridable in tests)."""
    s = get_settings()
    return GoogleSafeBrowsingProvider(
        api_key=s.google_safe_browsing_api_key,
        client_id=s.gsb_client_id,
        client_version=s.gsb_client_version,
        timeout=s.gsb_timeout_seconds,
    )


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze(
    request: AnalyzeRequest,
    provider: ThreatIntelProvider = Depends(get_reputation_provider),
) -> AnalyzeResponse:
    # 1. Validate the URL (rejects bad input before any external call).
    try:
        normalized = validate_and_normalize_url(request.url)
    except InvalidURLError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    host = urlparse(normalized).hostname or ""
    context = DetectionContext(
        url=request.url, normalized_url=normalized, host=host
    )

    # 2. Run modular detection engines (in a thread to avoid blocking the loop).
    try:
        findings = await run_in_threadpool(run_detection, context)
    except Exception:
        findings = []

    # 3. Reputation lookup (never fetches the URL; failures -> UNAVAILABLE).
    reputation = await provider.check(normalized)

    # 4. Combine into a consistent response.
    return build_response(normalized, findings, reputation)
