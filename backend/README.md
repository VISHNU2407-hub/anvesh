# LinkShield AI — Part 3: Backend + Threat Intelligence Integration

A Python/FastAPI service that analyzes a submitted URL and returns a consistent
risk verdict by combining an external **reputation check** (Google Safe Browsing)
with **pluggable detection engines**.

## Endpoints

| Method | Path            | Description                          |
|--------|-----------------|--------------------------------------|
| GET    | `/health`       | Liveness check.                      |
| POST   | `/api/analyze`  | Analyze a URL. Body: `{"url": "..."}` |

Interactive API docs (auto-generated): http://127.0.0.1:8000/docs

### `POST /api/analyze` response

```json
{
  "url": "https://example.com/path",
  "risk_level": "unknown",          // unknown | low | medium | high
  "score": 0,                        // 0–100
  "findings": [],                    // from detection engines
  "reputation_status": "unavailable",// threat_detected | no_known_threat | unavailable
  "advice": "…",                     // human-readable guidance
  "reputation": {
    "provider": "google_safe_browsing",
    "status": "unavailable",
    "matches": [],
    "error_reason": "missing_api_key"
  }
}
```

`risk_level`, `score`, `findings`, `reputation_status`, and `advice` are always
present and consistently shaped.

## Setup

```bash
cd backend

# 1. Create and activate a virtual environment
python -m venv .venv
# macOS/Linux:  source .venv/bin/activate
# Windows:      .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure secrets
cp .env.example .env
#    then edit .env and set GOOGLE_SAFE_BROWSING_API_KEY

# 4. Run the server
uvicorn app.main:app --reload
```

### Getting a Google Safe Browsing API key

1. Go to https://console.cloud.google.com/ and create/select a project.
2. Enable the **Safe Browsing API**.
3. Create an API key under *Credentials* and paste it into `.env`.

> **Terms of use:** Google's Safe Browsing APIs are licensed for
> **non-commercial use only**. If you need malicious-URL detection for a
> commercial (for-sale / revenue-generating) product, Google directs you to the
> **Web Risk API** instead. See https://developers.google.com/safe-browsing/

### API version used

This backend uses the **Safe Browsing Lookup API v4** —
`POST https://safebrowsing.googleapis.com/v4/threatMatches:find?key=API_KEY`.
An empty response (`{}`) means **no known threat**; a `matches` array means a
**confirmed threat**. This distinction is surfaced honestly in
`reputation_status`.

## Security guarantees

- **API keys never reach the frontend.** The key is read server-side from the
  environment and is never included in any response.
- **Submitted URLs are never fetched or opened.** The service only validates the
  URL syntactically and sends the *string* to Google for lookup. There is no
  outbound request to the user-supplied host.
- **No invented results.** A confirmed match, a "no known match", and an
  "unavailable" check are three distinct, explicit outcomes. When the check
  fails (missing key, timeout, quota, auth, API error) the response reports
  `reputation_status: "unavailable"` with a machine-readable `error_reason` and
  `risk_level: "unknown"` — it never claims a URL is safe.
- **Safe input handling.** Only `http`/`https` URLs are accepted; control
  characters, whitespace injection, and over-long inputs are rejected with a
  `400` before any external call.

## Error handling

| Condition                         | Behavior                                        |
|-----------------------------------|-------------------------------------------------|
| Invalid / malformed URL           | HTTP `400` with a clear message                  |
| Missing API key                   | `reputation_status: "unavailable"`, reason `missing_api_key` |
| Request timeout                   | `unavailable`, reason `timeout`                  |
| Quota exceeded (HTTP 429)         | `unavailable`, reason `quota_exceeded`           |
| Auth failure (HTTP 401/403)       | `unavailable`, reason `auth_error`               |
| Other API/network failure         | `unavailable`, reason `api_error` / `connection_error` |

The endpoint never crashes on provider failures — it degrades to an honest
"unavailable" result.

## Plugging in your teammate's detection module

Detection is modular. Define a class that subclasses `DetectionEngine`,
implement `analyze`, and register it at startup. It will automatically have its
findings merged into the `/api/analyze` response.

```python
# my_team_module.py
from app.detection import register_engine
from app.detection.engine import DetectionContext, DetectionEngine
from app.models import Confidence, Finding, Severity


class MyTeamEngine(DetectionEngine):
    name = "my_team_engine"

    def analyze(self, context: DetectionContext) -> list[Finding]:
        # Inspect context.normalized_url / context.host and return findings.
        # Do NOT fetch/open the URL or any external resource.
        return [
            Finding(
                engine=self.name,
                rule_id="LOOKALIKE_001",
                title="Possible lookalike domain",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
            )
        ]


register_engine(MyTeamEngine())
```

Then import your module once at startup (e.g. at the top of `app/main.py` or via
a startup hook). Engines run in a worker thread and a crashing engine is
isolated so it can never take down the request. A no-op `PlaceholderDetectionEngine`
is registered by default and can be replaced.

## Running tests

```bash
cd backend
pytest
```

Tests mock all network calls (no real API key or internet required) and cover
URL validation, scoring, every Google Safe Browsing failure mode, the detection
registry, and the `/api/analyze` contract.

## Project structure

```
backend/
├── app/
│   ├── main.py                     # FastAPI app + /api/analyze
│   ├── config.py                   # env/dotenv settings
│   ├── models.py                   # Pydantic models + enums
│   ├── url_validator.py            # URL validation & safe input handling
│   ├── scoring.py                  # reputation + findings → verdict
│   ├── threat_intel/
│   │   ├── base.py                 # ThreatIntelProvider interface
│   │   └── google_safe_browsing.py # GSB v4 Lookup API
│   └── detection/
│       ├── engine.py               # DetectionEngine interface + placeholder
│       └── registry.py             # engine registry
├── tests/                          # pytest suite
├── requirements.txt
├── pytest.ini
├── .env.example
└── .gitignore
```
