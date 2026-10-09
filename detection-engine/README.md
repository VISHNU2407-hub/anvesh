# detection-engine

A dependency-free, rule-based URL analysis module for the Cybersecurity
Hackathon. It validates and parses URLs, detects suspicious patterns,
generates structured findings, assigns a heuristic risk score and risk
category, and returns everything through one function: `analyze_url(url)`.

**Important framing**

- The risk score (0-100) is a *deterministic sum of rule weights*. It is
  **not** a probability of phishing or compromise.
- An empty findings list only means no configured rule matched. It is
  **never** reported as proof that a URL is safe or benign.
- The module performs **no network I/O**: it never resolves, fetches, or
  visits a submitted URL. Only Python's standard library is used.

## Files

| File | Purpose |
| --- | --- |
| `detection_engine.py` | The module: validation, detection rules, scoring, `analyze_url(url)`. Also runnable as a small CLI. |
| `test_detection_engine.py` | `unittest` suite: valid/invalid URLs, suspicious patterns, risk categories, edge cases, output contract. |
| `README.md` | This document. |

## Usage

```python
from detection_engine import analyze_url

result = analyze_url("http://192.168.10.5/login?redirect=http://evil.test")
print(result["risk_score"])     # e.g. 50
print(result["risk_category"])  # e.g. "elevated_observed_risk"
for finding in result["findings"]:
    print(finding["rule_id"], finding["severity"], finding["evidence"])
```

Command-line (prints JSON):

```bash
python detection_engine.py "https://example.com/login"
```

`analyze_url` never raises: malformed, empty, or non-string input is
returned as a structured result with `is_valid=False` and
`risk_category="indeterminate"`.

## Output format

Every result contains the same keys:

| Key | Type | Meaning |
| --- | --- | --- |
| `input_url` | `str` | The submitted input (repr for non-strings, truncated). |
| `is_valid` | `bool` | Whether the input passed URL validation. |
| `parse_error` | `str \| None` | Why validation failed; `None` when valid. |
| `scheme` | `str \| None` | Lowercased scheme (`http`, `https`, ...). |
| `hostname` | `str \| None` | Lowercased host, trailing dot stripped. |
| `port` | `int \| None` | Explicit port, if any. |
| `path` | `str \| None` | Path component. |
| `query` | `str \| None` | Raw query string (without `?`). |
| `fragment` | `str \| None` | Fragment (without `#`). |
| `risk_score` | `int \| None` | Heuristic score 0-100; `None` when not scannable. |
| `risk_category` | `str` | See risk categories below. |
| `findings` | `list[dict]` | Structured findings, sorted by descending score. |
| `findings_count` | `int` | `len(findings)`. |
| `disclaimer` | `str` | Always-present limits-of-analysis statement. |

Each finding contains: `rule_id`, `title`, `severity`, `score`,
`description` (why the rule exists), and `evidence` (what matched).

### Example (suspicious URL)

```json
{
  "input_url": "http://192.168.10.5/login?redirect=http://evil.test",
  "is_valid": true,
  "parse_error": null,
  "scheme": "http",
  "hostname": "192.168.10.5",
  "port": null,
  "path": "/login",
  "query": "redirect=http://evil.test",
  "fragment": "",
  "risk_score": 50,
  "risk_category": "elevated_observed_risk",
  "findings": [
    {"rule_id": "ip_address_host", "severity": "high", "score": 20,
     "title": "Raw IP address as host", "evidence": "hostname='192.168.10.5'", "...": "..."},
    {"rule_id": "plain_http_scheme", "severity": "medium", "score": 10, "...": "..."},
    {"rule_id": "redirect_parameter", "severity": "medium", "score": 10, "...": "..."},
    {"rule_id": "suspicious_keywords", "severity": "medium", "score": 10,
     "evidence": "matched=login", "...": "..."}
  ],
  "findings_count": 4,
  "disclaimer": "Heuristic rule-based triage only; ..."
}
```

### Example (input that cannot be validated)

```json
{
  "input_url": "javascript:alert(1)",
  "is_valid": false,
  "parse_error": "missing host component (netloc)",
  "scheme": null, "hostname": null, "port": null,
  "path": null, "query": null, "fragment": null,
  "risk_score": null,
  "risk_category": "indeterminate",
  "findings": [
    {"rule_id": "dangerous_scheme", "severity": "critical", "score": 30,
     "title": "Dangerous URL scheme", "evidence": "scheme='javascript'", "...": "..."}
  ],
  "findings_count": 1,
  "disclaimer": "Heuristic rule-based triage only; ..."
}
```

## Validation rules

An input is **valid** only if all of the following hold; otherwise
`is_valid=False`, `risk_score=None`, `risk_category="indeterminate"`, and a
`malformed_input` (or `dangerous_scheme`) finding explains the failure:

1. Input is a `str` (non-strings are rejected, never crashed on).
2. After trimming, non-empty and at most 10,000 characters.
3. No raw whitespace or control characters inside the URL.
4. Parses with `urllib.parse.urlparse` without error.
5. Has a scheme and a host component (`netloc`).
6. Has a non-empty hostname.
7. Has a well-formed, in-range port (when a port is present).

Dangerous schemes that cannot be parsed as a web link (`javascript:`,
`data:`, `vbscript:`, `file:`, `blob:`) are rejected with an explicit
`dangerous_scheme` finding rather than a generic parse error.

## Detection rules

All rules are static and explainable; each fired rule adds its severity
weight to the score (`low=5`, `medium=10`, `high=20`, `critical=30`),
capped at 100.

| Rule ID | Fires when | Severity | Points |
| --- | --- | --- | --- |
| `unsupported_scheme` | Scheme is not `http`/`https` (e.g. `ftp:`, `ws:`) | critical | 30 |
| `dangerous_scheme` | Unparseable input uses `javascript:`/`data:`/`file:`/... (not scored) | critical | 30 |
| `malformed_input` | Input failed validation (not scored) | high | 20 |
| `ip_address_host` | Hostname is a raw IPv4/IPv6 literal | high | 20 |
| `userinfo_trick` | `@` in the authority (e.g. `trusted.com@evil.com`) | high | 20 |
| `punycode_hostname` | Host contains `xn--` (IDN homograph risk) | high | 20 |
| `non_ascii_hostname` | Host contains non-ASCII characters | medium | 10 |
| `plain_http_scheme` | URL uses unencrypted `http://` | medium | 10 |
| `suspicious_tld` | TLD is on the static abuse-prone list (`xyz`, `tk`, `top`, ...) | medium | 10 |
| `url_shortener` | Host is a known shortener (`bit.ly`, `t.co`, ...) | medium | 10 |
| `excessive_subdomains` | 5+ labels in the hostname | medium | 10 |
| `digit_heavy_hostname` | 40%+ digits in a non-IP hostname (6+ chars) | medium | 10 |
| `suspicious_keywords` | Lure wording (`login`, `verify`, `password`, ...) in host/path, word-boundary matched | medium | 10 |
| `non_standard_port` | Port is set and not 80/443 | medium | 10 |
| `double_slash_path` | `//` appears inside the path | medium | 10 |
| `redirect_parameter` | Query has an open-redirect-style parameter (`redirect`, `next`, `url`, ...) | medium | 10 |
| `excessive_url_encoding` | 8+ `%XX` sequences in the URL | medium | 10 |
| `unqualified_hostname` | Hostname has no dot (localhost / intranet name) | low | 5 |
| `many_hyphens` | 4+ hyphens in the hostname | low | 5 |
| `deep_path` | 6+ path segments | low | 5 |
| `many_query_parameters` | 8+ distinct query parameters | low | 5 |
| `excessive_length` | URL is 200+ characters | low | 5 |
| `analysis_error` | Defensive catch-all; result must not be read as a verdict (not scored) | high | 20 |

Static lists (`SUSPICIOUS_TLDS`, `URL_SHORTENERS`, `SUSPICIOUS_KEYWORDS`,
`REDIRECT_PARAM_NAMES`) are module-level constants and easy to extend.

## Risk categories

| Score | Category |
| --- | --- |
| 0 - 19 | `low_observed_risk` |
| 20 - 39 | `moderate_observed_risk` |
| 40 - 69 | `elevated_observed_risk` |
| 70 - 100 | `high_observed_risk` |
| not scannable (invalid input) | `indeterminate` |

Category names deliberately say *observed risk*: they describe what these
rules saw, not a verdict on the URL.

## Running the tests

From this folder (`detection-engine/`):

```bash
python -m unittest discover -p "test_*.py" -v
```

Equivalents:

```bash
python -m unittest -v          # discovery from the current directory
python test_detection_engine.py
```

Expected result: `Ran 49 tests ... OK`. If `python` is not on your PATH,
use the `py` launcher (`py -m unittest discover -p "test_*.py" -v`) or the
full path to your interpreter.

Test coverage: valid URLs, invalid/malformed URLs (including non-string
input and a fuzz list), each major suspicious pattern, risk-band
boundaries and score capping, edge cases (IDN hosts, localhost, trailing
dots, very long URLs), the exact output contract, determinism, and a
static check that the module contains no network calls.

## Known limitations

- **Heuristic only.** Scores are rule weights, not probabilities; no
  machine learning, no reputation feeds, no live DNS/WHOIS/HTTP.
- **No safety guarantee.** Zero findings means "no configured rule
  matched", not "safe". Phishing pages on popular domains with clean
  URLs will score low.
- **Static lists** go stale; new abuse TLDs, shorteners, or lure wording
  require updating the constants.
- **Plain strings only.** IDN homographs are flagged when punycode or
  non-ASCII appears, but no visual-similarity (confusables) comparison is
  performed; decimal/octal IP encodings are not recognized as IPs.
- **No redirect resolution.** Shorteners and redirect parameters are
  flagged but never followed, so the final destination is unknown by
  design (no live requests).
- Keyword rules can produce false positives on legitimate paths (e.g.
  `/login` on a real site) - findings explain themselves so a human can
  judge.
