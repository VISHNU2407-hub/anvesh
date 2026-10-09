"""Rule-based URL detection engine for the Cybersecurity Hackathon.

Entry point
-----------
``analyze_url(url)`` validates and parses the submitted URL, applies a fixed
catalogue of explainable, rule-based checks, and returns one structured dict
containing URL validity, hostname, a heuristic risk score (0-100), a risk
category, a verification status (``suspicious`` / ``needs_verification`` --
never "safe"), and the list of findings that produced the score.

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
from difflib import SequenceMatcher
from urllib.parse import parse_qs, unquote, urlparse

__all__ = [
    "analyze_url",
    "validate_and_parse",
    "detect_findings",
    "score_findings",
    "categorize_risk",
    "compute_verification_status",
    "DISCLAIMER",
    "RISK_BANDS",
    "SEVERITY_SCORES",
    "MAX_RISK_SCORE",
    "INDETERMINATE_CATEGORY",
    "VERIFICATION_STATUSES",
    "VERIFICATION_SUSPICIOUS",
    "VERIFICATION_NEEDS",
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

# Verification status of a result. This engine has no threat-intelligence
# feed, so it can only ever say "a rule fired" or "evidence was
# insufficient". It NEVER reports a URL as safe or verified: an empty
# findings list is reported as VERIFICATION_NEEDS, not as a pass.
VERIFICATION_SUSPICIOUS = "suspicious"
VERIFICATION_NEEDS = "needs_verification"
VERIFICATION_STATUSES = (VERIFICATION_SUSPICIOUS, VERIFICATION_NEEDS)

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

# Well-known brands that are commonly impersonated, mapped to their official
# domains. A hostname that IS one of the official domains (or is a subdomain
# of one) is exempt from lookalike matching for that brand, so paypal.com and
# accounts.google.com are never reported as lookalikes of themselves.
BRAND_OFFICIAL_DOMAINS = {
    "paypal": {"paypal.com", "paypal.me", "paypalobjects.com"},
    "google": {
        "google.com", "g.co", "gmail.com", "youtube.com",
        "googleapis.com", "googleusercontent.com", "gstatic.com",
    },
    "microsoft": {
        "microsoft.com", "microsoftonline.com", "live.com",
        "office.com", "office365.com", "msn.com",
    },
    "apple": {"apple.com", "icloud.com", "itunes.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amzn.to",
               "ssl-images-amazon.com"},
    "facebook": {"facebook.com", "fb.com", "fbcdn.net"},
    "instagram": {"instagram.com", "cdninstagram.com"},
    "netflix": {"netflix.com", "nflx.net", "nflximg.net", "nflxvideo.net"},
    "whatsapp": {"whatsapp.com", "wa.me"},
    "outlook": {"outlook.com", "outlook.live.com"},
    "yahoo": {"yahoo.com", "yimg.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "spotify": {"spotify.com", "scdn.co"},
    "dropbox": {"dropbox.com", "dropboxusercontent.com"},
    "linkedin": {"linkedin.com", "lnkd.in"},
    "tiktok": {"tiktok.com"},
    "twitter": {"twitter.com", "twimg.com", "x.com"},
    "steam": {"steampowered.com", "steamcommunity.com", "steam.tv",
              "steamstatic.com"},
}

# Lure-style words that, when prefixed to or appended around a brand inside a
# hostname, form the classic typosquat shape: paypal-login.example.com.
BRAND_AFFIX_WORDS = frozenset(
    {
        "login", "signin", "secure", "security", "verify", "verification",
        "validate", "validation", "account", "accounts", "auth", "official",
        "support", "update", "confirm", "credential", "wallet", "bonus",
        "reward", "prize", "unlock", "suspend", "community", "service",
        "center", "centre", "hub", "online", "app", "my", "best", "free",
        "top", "real", "site", "page", "id",
    }
)

# Common leetspeak substitutions, applied before brand matching so that
# paypa1.example.com and g00gle.example.com are recognised as paypal / google.
_LEET_TABLE = str.maketrans(
    {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
     "@": "a", "$": "s"}
)

# Ordinary English words that sit exactly one edit away from a brand and must
# never be reported as typosquats (stream vs steam, apply vs apple, ...).
BRAND_TYPO_DENYLIST = frozenset(
    {"stream", "streams", "streaming", "steamy", "goggle", "goggles",
     "apples", "dapple", "grapple"}
)

_WHITESPACE_OR_CONTROL_RE = re.compile(r"[\x00-\x20\x7f]")
_SCHEME_GUESS_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*):")
_PERCENT_ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}")
# A '%' followed by two hex digits twice in a row: '%252f' is '%2f' encoded
# a second time.
_DOUBLE_ENCODING_RE = re.compile(r"%25[0-9a-fA-F]{2}")
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


def _levenshtein(a, b):
    """Classic edit distance between two short strings."""
    if a == b:
        return 0
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(
                min(previous[j] + 1, current[j - 1] + 1,
                    previous[j - 1] + (ca != cb))
            )
        previous = current
    return previous[-1]


def _brand_match_reason(label, brand):
    """Why ``label`` (already leet-normalised) looks like a fake ``brand``.

    Returns a short human-readable reason, or ``None`` when the label is not
    close enough to the brand. Designed to avoid obvious false positives:
    "pineapple", "upstream" and "applegate" do NOT match "apple"/"steam",
    while "paypa1-login", "microsft-support" and a bare "paypal" on a
    non-official domain all do.
    """
    if brand in label:
        remainder = label.replace(brand, "")
        if not remainder:
            # Bare brand label on a domain the brand does not own
            # (paypal.example.com, g00gle.example.com).
            return "bare brand label on a non-official domain"
        if any(ch.isdigit() or ch in "-_." for ch in remainder):
            return "brand label with lure-style affix"
        tokens = [tok for tok in re.split(r"[^a-z]+", remainder) if tok]
        if any(tok in BRAND_AFFIX_WORDS for tok in tokens):
            return "brand label with lure-style affix"
        if SequenceMatcher(None, label, brand).ratio() >= 0.85:
            # Near-identical spelling, e.g. paypalxyz.example.com.
            return "near-identical spelling of the brand"
        return None
    # Typo-squatted spelling without the brand as a substring. Checked per
    # word-like token so that affixed typos count too: the token "microsft"
    # in "microsft-support.example" is one edit from "microsoft".
    for token in re.split(r"[^a-z0-9]+", label):
        if len(token) < 6 or abs(len(token) - len(brand)) > 2:
            continue
        if token in BRAND_TYPO_DENYLIST:
            continue
        if _levenshtein(token, brand) <= 1:
            return "typo-squatted spelling of the brand"
    return None


def _lookalike_findings(host):
    """Detect brand impersonation in ``host`` (pure string analysis)."""
    findings = []
    if not host or _is_ip_address(host):
        return findings
    labels = [part for part in host.split(".") if part]
    for brand, officials in sorted(BRAND_OFFICIAL_DOMAINS.items()):
        if any(host == dom or host.endswith("." + dom) for dom in officials):
            continue
        for label in labels:
            reason = _brand_match_reason(label.translate(_LEET_TABLE), brand)
            if reason:
                findings.append(
                    _finding(
                        "lookalike_domain",
                        "Possible lookalike domain impersonating a known brand",
                        "high",
                        "The hostname closely resembles the '%s' brand while "
                        "not being hosted on that brand's official domain -- "
                        "the classic shape of a typosquat or "
                        "brand-impersonation landing page. Heuristic only: "
                        "judge the surrounding context." % brand,
                        "brand=%r hostname=%r (%s)" % (brand, host, reason),
                    )
                )
                break  # one finding per brand is enough
    return findings


def _encoded_numeric_host_finding(host):
    """Single-label hosts that are really obfuscated IPv4 literals.

    Browsers accept decimal (2130706433) and hexadecimal (0x7f000001)
    spellings of IPv4 addresses, which hide the destination from readers and
    from filters that only recognise dotted quads. Returns a finding or None.
    """
    if not host or _is_ip_address(host) or "." in host:
        return None
    value = None
    kind = None
    if host.isdigit():
        # 6..10 digits: inside uint32 range and not a trivial number.
        if 6 <= len(host) <= 10:
            value = int(host)
            kind = "decimal"
    elif re.fullmatch(r"0x[0-9a-f]{1,8}", host):
        value = int(host, 16)
        kind = "hexadecimal"
    if value is None or value > 0xFFFFFFFF:
        return None
    return _finding(
        "encoded_ip_host",
        "Obfuscated numeric IP host",
        "high",
        "The hostname is a single number in %s notation instead of a "
        "domain or a dotted-quad IP. Browsers can navigate to these "
        "directly, which keeps the real destination out of sight." % kind,
        "hostname=%r numeric_value=%d" % (host, value),
    )


def _decode_redirect_value(value):
    """Percent-decode a query value up to 3 times (single/double encoding)."""
    current = value
    for _ in range(3):
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded
    return current


def _redirect_target_findings(components):
    """Analyse where open-redirect style parameters point (string only).

    The target is decoded as text and parsed -- it is NEVER fetched, opened
    or resolved. Only absolute http(s)/protocol-relative targets that point
    at a *different* host than the URL itself produce findings, which keeps
    same-site redirect parameters free of noise.
    """
    findings = []
    emitted = set()
    host = components.get("hostname") or ""
    params = components.get("query_params") or {}

    for name in sorted(params):
        if name.lower() not in REDIRECT_PARAM_NAMES:
            continue
        values = params.get(name) or []
        if isinstance(values, str):
            values = [values]
        for raw_value in values:
            if not isinstance(raw_value, str):
                continue
            target = _decode_redirect_value(raw_value.strip())
            if not target:
                continue
            lower = target.lower()
            if lower.startswith(("javascript:", "data:", "vbscript:")):
                if "redirect_to_dangerous_scheme" not in emitted:
                    emitted.add("redirect_to_dangerous_scheme")
                    findings.append(
                        _finding(
                            "redirect_to_dangerous_scheme",
                            "Redirect target uses a script/data scheme",
                            "critical",
                            "A redirect parameter points at a javascript:, "
                            "data: or vbscript: target, which can execute "
                            "script instead of navigating to a page.",
                            "param=%r target=%s" % (name, _short_repr(target)),
                        )
                    )
                continue
            candidate = target
            if candidate.startswith("//"):
                candidate = "http:" + candidate  # protocol-relative target
            if not re.match(r"^https?://", candidate, re.IGNORECASE):
                continue  # relative target: not a cross-host claim
            try:
                parsed = urlparse(candidate)
                target_host = (parsed.hostname or "").lower().rstrip(".")
            except ValueError:
                target_host = ""
            if not target_host or target_host == host:
                continue  # same-host redirect: nothing to report
            if (
                "redirect_to_shortener" not in emitted
                and _matches_shortener(target_host, URL_SHORTENERS)
            ):
                emitted.add("redirect_to_shortener")
                findings.append(
                    _finding(
                        "redirect_to_shortener",
                        "Redirect target hidden behind a URL shortener",
                        "medium",
                        "The redirect parameter points at a known shortener, "
                        "so the final destination cannot be judged without "
                        "opening the link (which this module never does).",
                        "param=%r target_host=%r" % (name, target_host),
                    )
                )
            if "redirect_to_external_host" not in emitted:
                emitted.add("redirect_to_external_host")
                findings.append(
                    _finding(
                        "redirect_to_external_host",
                        "Redirect target points to a different host",
                        "medium",
                        "An open-redirect style parameter carries an absolute "
                        "URL whose host differs from this URL's host, so "
                        "following the link could leave the expected site.",
                        "param=%r target_host=%r" % (name, target_host),
                    )
                )
    return findings


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

    # --- Lookalike domains & obfuscated hosts ---------------------------
    findings.extend(_lookalike_findings(host))

    encoded_host = _encoded_numeric_host_finding(host)
    if encoded_host is not None:
        findings.append(encoded_host)

    if "%" in host:
        findings.append(
            _finding(
                "encoded_hostname",
                "Percent-encoded characters in the hostname",
                "high",
                "Browsers decode %XX sequences inside the hostname before "
                "resolving it, so an encoded host can display as one domain "
                "while actually navigating to another.",
                "hostname=%r" % host,
            )
        )

    if "\\" in url:
        findings.append(
            _finding(
                "backslash_obfuscation",
                "Backslash in the URL",
                "medium",
                "Browsers treat a backslash as a forward slash in URLs, but "
                "most readers and simple filters do not, so backslashes can "
                "visually split or hide the real host and path.",
                "backslash_count=%d" % url.count("\\"),
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

    # Where do those redirect parameters actually point? (Parsed as text;
    # the target is never fetched or opened.)
    findings.extend(_redirect_target_findings(components))

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

    double_encoded = _DOUBLE_ENCODING_RE.findall(url)
    if len(double_encoded) >= 2:
        findings.append(
            _finding(
                "double_encoding",
                "Double percent-encoding",
                "medium",
                "%25XX sequences mean the URL was percent-encoded twice, "
                "which defeats filters that decode only once and hides the "
                "real target from plain-text inspection.",
                "double_encoded_count=%d" % len(double_encoded),
            )
        )

    lowered_path = path.lower()
    if "%2e%2e" in lowered_path or "%2e%2f" in lowered_path:
        findings.append(
            _finding(
                "encoded_dot_segments",
                "Encoded dot segments in the path",
                "medium",
                "%2e%2e / %2e%2f spell '../' in encoded form, a common way "
                "to disguise path traversal or to slip past naive filters.",
                "path=%r" % path,
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


def compute_verification_status(is_valid, findings):
    """Classify how much the evidence in ``findings`` actually proves.

    Returns one of ``VERIFICATION_STATUSES``:

    * ``suspicious``    - at least one rule fired (or the input uses a
      dangerous scheme such as javascript:): there is concrete evidence for
      a human to review.
    * ``needs_verification`` - the input could not be parsed, OR a valid URL
      produced no findings. This is deliberately NOT called "safe": an
      empty findings list only means no configured rule matched, never that
      the URL is benign.

    This module performs no network I/O and consults no reputation feed, so
    it can neither confirm a threat nor verify a URL as safe.
    """
    if is_valid:
        return VERIFICATION_SUSPICIOUS if findings else VERIFICATION_NEEDS
    # Unparseable input: only an explicit dangerous-scheme finding is direct
    # evidence of malice; a generic parse failure simply could not be
    # assessed and therefore needs verification.
    if any(item.get("rule_id") == "dangerous_scheme" for item in findings):
        return VERIFICATION_SUSPICIOUS
    return VERIFICATION_NEEDS


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
        "verification_status": compute_verification_status(
            bool(is_valid), findings
        ),
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
    ``risk_score``, ``risk_category``, ``verification_status``, ``findings``,
    ``findings_count`` and ``disclaimer``.

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
