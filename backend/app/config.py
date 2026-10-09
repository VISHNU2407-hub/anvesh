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


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings(
        google_safe_browsing_api_key=os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or None,
        gsb_timeout_seconds=_get_float("GSB_TIMEOUT_SECONDS", 5.0),
        gsb_client_id=os.getenv("GSB_CLIENT_ID", "linkshield-ai"),
        gsb_client_version=os.getenv("GSB_CLIENT_VERSION", "0.3.0"),
    )
