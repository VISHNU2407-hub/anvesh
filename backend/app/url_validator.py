"""URL validation and safe input handling.

Security notes:
- We NEVER fetch or open the submitted URL. Validation here is purely
  syntactic; the normalized string is only sent to the reputation provider
  (Google Safe Browsing) as data to look up.
- We reject anything that is not an http(s) URL to avoid scheme-based abuse.
"""

from __future__ import annotations

from urllib.parse import urlparse

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = {"http", "https"}
# Characters that must never appear in a well-formed single-line URL.
_FORBIDDEN_CHARS = ("\r", "\n", "\x00", "\t", " ", "\"", "'", "<", ">")


class InvalidURLError(ValueError):
    """Raised when a submitted URL is malformed or disallowed."""


def validate_and_normalize_url(raw: str) -> str:
    """Validate a user-submitted URL and return a normalized copy.

    Raises InvalidURLError for anything that is not a clean http(s) URL.
    """
    if not isinstance(raw, str):
        raise InvalidURLError("URL must be a string.")

    url = raw.strip()

    if not url:
        raise InvalidURLError("URL must not be empty.")

    if len(url) > MAX_URL_LENGTH:
        raise InvalidURLError(f"URL exceeds maximum length of {MAX_URL_LENGTH}.")

    if any(ch in url for ch in _FORBIDDEN_CHARS):
        raise InvalidURLError("URL contains disallowed control or whitespace characters.")

    parsed = urlparse(url)

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise InvalidURLError("Only http:// and https:// URLs are supported.")

    host = parsed.hostname
    if not parsed.netloc or not host:
        raise InvalidURLError("URL must include a valid host.")

    # Rebuild a normalized, canonical-ish URL (scheme lowercased, safe chars kept).
    # We keep the original path/query; we only tidy scheme/host casing.
    normalized = parsed._replace(scheme=scheme, netloc=parsed.netloc)
    return normalized.geturl()
