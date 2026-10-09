"""Rule-based URL detection engine for the Cybersecurity Hackathon.

Entry point
-----------
``analyze_url(url)`` validates and parses the submitted URL, applies a fixed
catalogue of explainable, rule-based checks, and returns one structured dict
containing URL validity, hostname, a heuristic risk score (0-100), a risk
category, and the list of findings that produced the score.

Safety properties
-----------------
* Standard library only; no third-party dependencies.
* No network I/O: the module never resolves, fetches, or visits URLs.
* Malformed or non-string input never raises; it is reported with
  ``is_valid=False`` and ``risk_category="indeterminate"``.
* Every finding names the rule that fired, its severity, and its evidence.
* The score is a deterministic triage heuristic, NOT a probability of
  phishing. An empty findings list only means no configured rule matched;
  it is never reported as a guarantee that the URL is safe.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qs, urlparse

__all__ = [
    "analyze_url",
    "validate_and_parse",
    "detect_findings",
    "score_findings",
    "categorize_risk",
    "DISCLAIMER",
    "RISK_BANDS",
    "SEVERITY_SCORES",
    "MAX_RISK_SCORE",
    "INDETERMINATE_CATEGORY",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DISCLAIMER = (
    "Heuristic rule-based triage only; no network requests were made and the "
    "URL was not visited. The risk score is a deterministic sum of rule "
    "weights, not a probability of phishing or compromise. An empty findings "
    "list means only that no configured rule matched -- it does not mean the "
    "URL is safe or benign."
)

MAX_INPUT_LENGTH = 10000
MAX_RISK_SCORE = 100
SUPPORTED_SCHEMES = frozenset({"http", "https"})
DANGEROUS_SCHEMES = frozenset({"javascript", "data", "vbscript", "file", "blob"})

# Severity -> points contributed when a rule fires.
SEVERITY_SCORES = {"low": 5, "medium": 10, "high": 20, "critical": 30}

# (category name, inclusive lower bound of the risk score)
RISK_BANDS = (
    ("low_observed_risk", 0),
    ("moderate_observed_risk", 20),
    ("elevated_observed_risk", 40),
    ("high_observed_risk", 70),
)
INDETERMINATE_CATEGORY = "indeterminate"

# TLDs frequently abused in bulk / low-reputation registrations. Static
# list: the module never performs DNS or WHOIS lookups.
SUSPICIOUS_TLDS = frozenset(
    {
        "zip", "mov", "xyz", "top", "click", "link", "tk", "ml", "cf", "gq",
        "work", "loan", "country", "win", "review", "stream", "date",
        "racing", "download", "accountants", "rest", "quest", "monster",
        "icu", "cam", "beauty", "hair", "makeup", "sbs", "cfd",
        "bond", "enom",
    }
)

URL_SHORTENERS = frozenset(
    {
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
        "buff.ly", "tiny.cc", "cutt.ly", "rebrand.ly", "shorturl.at",
        "t.ly", "rb.gy", "s.id", "v.gd", "trib.al", "soo.gd", "bl.ink",
    }
)

# Credential-theft / lure wording. Matched on the hostname and path with
# word-ish boundaries. Deliberately weak: legitimate sites can contain the
# same words, so this rule never carries a high severity by itself.
SUSPICIOUS_KEYWORDS = (
    "account", "authenticate", "banking", "bonus", "confirm", "credential",
    "gift", "invoice", "login", "otp", "passwd", "password", "paypal",
    "prize", "reward", "signin", "sign-in", "suspend", "unlock", "update",
    "urgent", "validate", "verification", "verify", "wallet", "winner",
    "free",
)

# Query parameters commonly used for open-redirect / tainted-navigation
# chains.
REDIRECT_PARAM_NAMES = frozenset(
    {
        "callback", "continue", "dest", "destination", "forward", "goto",
        "link", "next", "redir", "redirect", "redirect_uri", "redirect_url",
        "refresh", "reload", "return", "return_to", "returnto", "site",
        "target", "u", "uri", "url",
    }
)

_WHITESPACE_OR_CONTROL_RE = re.compile(r"[\x00-\x20\x7f]")
_SCHEME_GUESS_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*):")
_PERCENT_ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}")
_KEYWORD_PATTERNS = {
    kw: re.compile(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])")
    for kw in SUSPICIOUS_KEYWORDS
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(rule_id, title, severity, description, evidence):
    """Build one structured finding dict."""
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "score": SEVERITY_SCORES[severity],
        "description": description,
        "evidence": evidence,
    }


def _short_repr(value, limit=160):
    """A repr() safe to embed in evidence strings."""
    try:
        text = repr(value)
    except Exception:  # pragma: no cover - defensive
        text = "<unrepresentable>"
    if len(text) > limit:
        text = text[:limit] + "...<truncated>"
    return text


def _is_ip_address(host):
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    except TypeError:  # pragma: no cover - defensive
        return False
    return True


def _matches_shortener(host, domains):
    for domain in domains:
        if host == domain or host.endswith("." + domain):
            return True
    return False


# ---------------------------------------------------------------------------
# Validation / parsing
# ---------------------------------------------------------------------------


def validate_and_parse(url):
    """Validate and parse ``url``.

    Returns ``(components, None)`` on success or ``(None, error_message)``
    when the input cannot be treated as a URL. Never raises.
    """
    if not isinstance(url, str):
        return None, "input is not a string (got %s)" % type(url).__name__

    candidate = url.strip()
    if not candidate:
        return None, "input is empty"
    if len(candidate) > MAX_INPUT_LENGTH:
        return None, "input exceeds maximum length of %d characters" % MAX_INPUT_LENGTH
    if _WHITESPACE_OR_CONTROL_RE.search(candidate):
        return None, "URL contains raw whitespace or control characters"

    try:
        parsed = urlparse(candidate)
    except ValueError as exc:
        return None, "URL could not be parsed: %s" % exc

    if not parsed.scheme:
        return None, "missing URL scheme (expected http:// or https://)"
    if not parsed.netloc:
        return None, "missing host component (netloc)"

    try:
        hostname = parsed.hostname
    except ValueError as exc:
        return None, "malformed hostname: %s" % exc
    try:
        port = parsed.port
    except ValueError:
        return None, "malformed or out-of-range port number"

    host = (hostname or "").lower().rstrip(".")
    if not host:
        return None, "missing hostname"

    components = {
        "url": candidate,
        "netloc": parsed.netloc,
        "scheme": parsed.scheme.lower(),
        "hostname": host,
        "port": port,
        "path": parsed.path or "",
        "query": parsed.query or "",
        "fragment": parsed.fragment or "",
    }

    try:
        components["query_params"] = parse_qs(
            components["query"], keep_blank_values=True
        )
    except (ValueError, TypeError):
        components["query_params"] = {}

    return components, None


# ---------------------------------------------------------------------------
# Detection rules (all pure functions of the parsed components)
# ---------------------------------------------------------------------------


def detect_findings(components):
    """Run every rule against parsed ``components`` and return findings.

    Findings are sorted by descending score, then rule id, so output is
    deterministic. Each finding explains which rule fired and why.
    """
    findings = []
    url = components["url"]
    scheme = components["scheme"]
    host = components["hostname"]
    netloc = components["netloc"]
    path = components["path"]
    port = components["port"]

    # --- Scheme ---------------------------------------------------------
    if scheme not in SUPPORTED_SCHEMES:
        findings.append(
            _finding(
                "unsupported_scheme",
                "Non-HTTP(S) URL scheme",
                "critical",
                "Only http/https links are expected here; schemes such as "
                "ftp:, ws: or javascript: are common in abuse and are not "
                "handled by normal web navigation.",
                "scheme=%r" % scheme,
            )
        )
    elif scheme == "http":
        findings.append(
            _finding(
                "plain_http_scheme",
                "Unencrypted HTTP scheme",
                "medium",
                "The URL uses plain http://, so anything sent to this host "
                "(credentials, tokens) can be observed or modified in transit.",
                "scheme=http",
            )
        )

    # --- Hostname -------------------------------------------------------
    is_ip = _is_ip_address(host)
    if is_ip:
        findings.append(
            _finding(
                "ip_address_host",
                "Raw IP address as host",
                "high",
                "The hostname is a bare IP address rather than a domain "
                "name; legitimate sites usually use a registered domain, "
                "and IP hosts are common in phishing and malware infrastructure.",
                "hostname=%r" % host,
            )
        )

    if "@" in netloc:
        findings.append(
            _finding(
                "userinfo_trick",
                "Userinfo text before the host",
                "high",
                "The URL embeds text before an '@' (for example "
                "http://trusted.com@evil.com). Browsers navigate to the part "
                "after the '@', while humans and filters often read the part "
                "before it.",
                "netloc=%r" % netloc,
            )
        )

    if "xn--" in host:
        findings.append(
            _finding(
                "punycode_hostname",
                "Punycode (IDN) hostname",
                "high",
                "The host contains punycode (xn--), which can render as a "
                "visual look-alike of an unrelated domain (homograph attack).",
                "hostname=%r" % host,
            )
        )
    elif any(ord(ch) > 127 for ch in host):
        findings.append(
            _finding(
                "non_ascii_hostname",
                "Non-ASCII characters in hostname",
                "medium",
                "The host contains non-ASCII characters; different scripts "
                "and fonts can make look-alike domains hard to distinguish.",
                "hostname=%r" % host,
            )
        )

    if "." in host:
        tld = host.rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS:
            findings.append(
                _finding(
                    "suspicious_tld",
                    "Frequently abused top-level domain",
                    "medium",
                    "This TLD appears often in bulk registrations and abuse "
                    "reports; it is a weak signal on its own.",
                    "tld=%r" % tld,
                )
            )
    else:
        findings.append(
            _finding(
                "unqualified_hostname",
                "Hostname without a public domain",
                "low",
                "The hostname has no dot (for example localhost or an "
                "intranet name), so it cannot be checked against normal "
                "Internet naming.",
                "hostname=%r" % host,
            )
        )

    if _matches_shortener(host, URL_SHORTENERS):
        findings.append(
            _finding(
                "url_shortener",
                "Known URL shortener",
                "medium",
                "Shorteners hide the final destination until the link is "
                "opened, so the target cannot be judged from the link text.",
                "hostname=%r" % host,
            )
        )

    labels = host.split(".")
    if len(labels) >= 5:
        findings.append(
            _finding(
                "excessive_subdomains",
                "Deeply nested subdomains",
                "medium",
                "Many subdomain levels make the real registered domain hard "
                "to spot and are common in look-alike hosting.",
                "label_count=%d hostname=%r" % (len(labels), host),
            )
        )

    hyphens = host.count("-")
    if hyphens >= 4:
        findings.append(
            _finding(
                "many_hyphens",
                "Hyphen-heavy hostname",
                "low",
                "Many hyphens in the host can indicate machine-generated "
                "look-alike domains.",
                "hyphen_count=%d hostname=%r" % (hyphens, host),
            )
        )

    if not is_ip and len(host) >= 6:
        digit_ratio = sum(1 for ch in host if ch.isdigit()) / float(len(host))
        if digit_ratio >= 0.4:
            findings.append(
                _finding(
                    "digit_heavy_hostname",
                    "Digit-heavy hostname",
                    "medium",
                    "A large share of digits in the host is typical of "
                    "auto-generated or algorithmically registered domains.",
                    "digit_ratio=%.2f hostname=%r" % (digit_ratio, host),
                )
            )

    # --- Host + path wording -------------------------------------------
    keyword_haystack = "%s %s %s" % (
        host,
        netloc.rsplit("@", 1)[0].lower() if "@" in netloc else "",
        path.replace("/", " "),
    )
    matched_keywords = sorted(
        kw for kw, pattern in _KEYWORD_PATTERNS.items()
        if pattern.search(keyword_haystack)
    )
    if matched_keywords:
        findings.append(
            _finding(
                "suspicious_keywords",
                "Credential-lure wording in host or path",
                "medium",
                "Words commonly used on credential-harvesting pages appear "
                "in the URL. This is a weak signal: legitimate sites can "
                "contain the same words.",
                "matched=%s" % ", ".join(matched_keywords),
            )
        )

    # --- Port -----------------------------------------------------------
    if port is not None and port not in (80, 443):
        findings.append(
            _finding(
                "non_standard_port",
                "Non-standard port",
                "medium",
                "The link targets a port other than 80/443, which is often "
                "used to reach unofficial services behind a firewall.",
                "port=%d" % port,
            )
        )

    # --- Path -----------------------------------------------------------
    segments = [seg for seg in path.split("/") if seg]
    if len(segments) >= 6:
        findings.append(
            _finding(
                "deep_path",
                "Unusually deep path",
                "low",
                "Many path segments can be used to bury the interesting part "
                "of a URL from a quick glance.",
                "segment_count=%d" % len(segments),
            )
        )

    if "//" in path:
        findings.append(
            _finding(
                "double_slash_path",
                "Double slash inside the path",
                "medium",
                "A '//' inside the path resembles a protocol-relative "
                "redirect and is a common obfuscation trick.",
                "path=%r" % path,
            )
        )

    # --- Query ----------------------------------------------------------
    param_names = sorted({key.lower() for key in components["query_params"]})
    matched_params = [key for key in param_names if key in REDIRECT_PARAM_NAMES]
    if matched_params:
        findings.append(
            _finding(
                "redirect_parameter",
                "Open-redirect style query parameter",
                "medium",
                "The query contains a parameter frequently used to redirect "
                "browsers to an attacker-chosen destination.",
                "params=%s" % ", ".join(matched_params),
            )
        )

    if len(param_names) >= 8:
        findings.append(
            _finding(
                "many_query_parameters",
                "Large number of query parameters",
                "low",
                "Unusually many parameters are common in crafted or "
                "tracker-heavy links.",
                "param_count=%d" % len(param_names),
            )
        )

    encoded = _PERCENT_ENCODED_RE.findall(url)
    if len(encoded) >= 8:
        findings.append(
            _finding(
                "excessive_url_encoding",
                "Heavy percent-encoding",
                "medium",
                "Many %XX sequences hide the readable content of the URL "
                "from both humans and simple filters.",
                "encoded_sequence_count=%d" % len(encoded),
            )
        )

    # --- Whole URL ------------------------------------------------------
    if len(url) >= 200:
        findings.append(
            _finding(
                "excessive_length",
                "Very long URL",
                "low",
                "Long URLs are used to push the suspicious part past where "
                "most people or UIs will read.",
                "length=%d" % len(url),
            )
        )

    findings.sort(key=lambda item: (-item["score"], item["rule_id"]))
    return findings


# ---------------------------------------------------------------------------
# Scoring / categorisation
# ---------------------------------------------------------------------------


def score_findings(findings):
    """Sum rule scores, capped at ``MAX_RISK_SCORE``."""
    total = 0
    for item in findings:
        try:
            total += int(item.get("score", 0))
        except (TypeError, ValueError):
            continue
    return min(total, MAX_RISK_SCORE)


def categorize_risk(score):
    """Map a risk score (0-100) to a category name; ``None`` -> indeterminate."""
    if score is None:
        return INDETERMINATE_CATEGORY
    category = RISK_BANDS[0][0]
    for name, floor in RISK_BANDS:
        if score >= floor:
            category = name
        else:
            break
    return category


# ---------------------------------------------------------------------------
# Result assembly
# ---------------------------------------------------------------------------


def _build_result(input_value, is_valid, components, findings, score, category, error):
    components = components or {}
    if isinstance(input_value, str):
        display_input = input_value
    else:
        display_input = _short_repr(input_value)
    return {
        "input_url": display_input,
        "is_valid": bool(is_valid),
        "parse_error": error,
        "scheme": components.get("scheme"),
        "hostname": components.get("hostname"),
        "port": components.get("port"),
        "path": components.get("path"),
        "query": components.get("query"),
        "fragment": components.get("fragment"),
        "risk_score": score,
        "risk_category": category,
        "findings": findings,
        "findings_count": len(findings),
        "disclaimer": DISCLAIMER,
    }


def _analyze(url):
    components, error = validate_and_parse(url)

    if components is None:
        # Input could not be parsed: report it, but do not score it. A
        # dangerous scheme is worth calling out explicitly.
        if isinstance(url, str):
            match = _SCHEME_GUESS_RE.match(url.strip())
            scheme_guess = match.group(1).lower() if match else None
        else:
            scheme_guess = None
        if scheme_guess in DANGEROUS_SCHEMES:
            findings = [
                _finding(
                    "dangerous_scheme",
                    "Dangerous URL scheme",
                    "critical",
                    "Schemes such as javascript:, data: or file: can execute "
                    "script or read local files and are never expected in a "
                    "normal web link.",
                    "scheme=%r" % scheme_guess,
                )
            ]
        else:
            findings = [
                _finding(
                    "malformed_input",
                    "Input could not be validated as a URL",
                    "high",
                    "The input failed URL validation, so it was not analyzed "
                    "further. An unparseable link is not evidence of safety; "
                    "it simply could not be assessed by these rules.",
                    "%s (input=%s)" % (error, _short_repr(url)),
                )
            ]
        # Not summed: there is nothing to score for an unparseable input.
        return _build_result(
            url, False, None, findings, None, INDETERMINATE_CATEGORY, error
        )

    findings = detect_findings(components)
    score = score_findings(findings)
    category = categorize_risk(score)
    return _build_result(url, True, components, findings, score, category, None)


def analyze_url(url):
    """Analyze ``url`` and return a structured result dict.

    The result always contains: ``input_url``, ``is_valid``, ``parse_error``,
    ``scheme``, ``hostname``, ``port``, ``path``, ``query``, ``fragment``,
    ``risk_score``, ``risk_category``, ``findings``, ``findings_count`` and
    ``disclaimer``.

    Never raises: malformed or non-string input is returned with
    ``is_valid=False`` and ``risk_category="indeterminate"``.
    """
    try:
        return _analyze(url)
    except Exception as exc:  # pragma: no cover - defensive safety net
        findings = [
            _finding(
                "analysis_error",
                "Unexpected error while analyzing input",
                "high",
                "The analyzer hit an unexpected error and stopped; the "
                "result must not be read as a verdict on this URL.",
                _short_repr(exc),
            )
        ]
        return _build_result(
            url,
            False,
            None,
            findings,
            None,
            INDETERMINATE_CATEGORY,
            "unexpected error while analyzing input: %s" % exc,
        )


if __name__ == "__main__":
    # Small convenience CLI: python detection_engine.py <url>
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(json.dumps(analyze_url(target), indent=2, sort_keys=True))
