"""Application configuration loaded from environment variables.

The Google Safe Browsing API key is read from the environment and MUST stay
server-side. It is never returned in any API response.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

from dotenv import load_dotenv

# Load .env (if present) into the process environment. Safe to call repeatedly.
load_dotenv()


def _get_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    # Primary secret. Never expose this to the frontend / any response.
    google_safe_browsing_api_key: str | None
    gsb_timeout_seconds: float
    gsb_client_id: str
    gsb_client_version: str
    cors_allowed_origins: tuple[str, ...]


def _get_cors_origins() -> tuple[str, ...]:
    # Safe defaults for local development (Vite on :5173 and preview on :4173).
    defaults = (
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    )
    raw = os.getenv("CORS_ALLOWED_ORIGINS") or os.getenv("FRONTEND_ORIGINS")
    if not raw or not raw.strip():
        return defaults
    # Comma-separated list, e.g. "https://example.com,https://app.example.com"
    parts = [p.strip().rstrip("/") for p in raw.split(",") if p.strip()]
    # Filter: only allow http/https origins, no wildcards.
    allowed = [
        p for p in parts if p.startswith("http://") or p.startswith("https://")
    ]
    return tuple(allowed) if allowed else defaults


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings(
        google_safe_browsing_api_key=os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or None,
        gsb_timeout_seconds=_get_float("GSB_TIMEOUT_SECONDS", 5.0),
        gsb_client_id=os.getenv("GSB_CLIENT_ID", "linkshield-ai"),
        gsb_client_version=os.getenv("GSB_CLIENT_VERSION", "0.3.0"),
        cors_allowed_origins=_get_cors_origins(),
    )
