"""LinkShield rule-based detection engine (Part 2 engine -> Part 3 backend).

This module adapts the standalone Part 2 engine
(``detection-engine/detection_engine.py``) to the backend's
``DetectionEngine`` interface:

* loads the rule module once at import time (standard library only),
* analyzes ``DetectionContext.normalized_url`` (never the network),
* maps each rule finding to the backend ``Finding`` model using only the
  permitted ``Severity`` (info/low/medium/high/critical) and ``Confidence``
  (low/medium/high) values.

Safety: the engine is a pure function of the URL string. It never resolves,
fetches, or opens the submitted URL (or any other resource).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import List

from ..models import Confidence, Finding, Severity
from .engine import DetectionContext, DetectionEngine

#: Unique registry name for this engine (must not collide with other engines).
ENGINE_NAME = "linkshield_rule_engine"

# Rules whose firing condition is directly observable from the URL string
# (scheme, host shape, port, encoding...): the match itself is certain.
_HIGH_CONFIDENCE_RULES = frozenset(
    {
        "unsupported_scheme",
        "dangerous_scheme",
        "malformed_input",
        "plain_http_scheme",
        "ip_address_host",
        "userinfo_trick",
        "punycode_hostname",
        "non_ascii_hostname",
        "unqualified_hostname",
        "non_standard_port",
        "double_slash_path",
        "excessive_url_encoding",
        "excessive_length",
        "deep_path",
    }
)

# Defensive catch-all: we know analysis failed, not what it would have found.
_LOW_CONFIDENCE_RULES = frozenset({"analysis_error"})


def _load_rule_module():
    """Locate and load ``detection-engine/detection_engine.py`` from the repo.

    The file lives outside the ``backend`` package, so it is loaded by path
    (searching upward from this file) instead of mutating ``sys.path``.
    Failing loudly here means a missing engine is caught at startup rather
    than silently producing no detections.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "detection-engine" / "detection_engine.py"
        if candidate.is_file():
            break
    else:
        raise FileNotFoundError(
            "detection-engine/detection_engine.py not found above "
            f"{here}; is the repository checkout complete?"
        )

    spec = importlib.util.spec_from_file_location(
        "linkshield_rule_engine_module", candidate
    )
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"could not load detection engine module from {candidate}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_RULES = _load_rule_module()


class LinkShieldDetectionEngine(DetectionEngine):
    """Rule-based URL analyzer backed by the Part 2 detection engine.

    Pure analysis: inspects the URL string only; never fetches or opens it.
    """

    name = ENGINE_NAME

    def analyze(self, context: DetectionContext) -> List[Finding]:
        url = context.normalized_url or context.url
        result = _RULES.analyze_url(url)
        return [
            self._to_finding(raw)
            for raw in result.get("findings", [])
            if isinstance(raw, dict)
        ]

    @staticmethod
    def _to_finding(raw: dict) -> Finding:
        rule_id = raw.get("rule_id") or ""
        # Severity(raw) raises on anything outside the permitted enum values;
        # the registry isolates the engine rather than emitting bad data.
        severity = Severity(raw["severity"])
        if rule_id in _LOW_CONFIDENCE_RULES:
            confidence = Confidence.LOW
        elif rule_id in _HIGH_CONFIDENCE_RULES:
            confidence = Confidence.HIGH
        else:
            confidence = Confidence.MEDIUM

        description = raw.get("description") or ""
        evidence = raw.get("evidence")
        if evidence:
            description = f"{description} Evidence: {evidence}".strip()

        return Finding(
            engine=ENGINE_NAME,
            rule_id=rule_id or None,
            title=raw["title"],
            description=description or None,
            severity=severity,
            confidence=confidence,
        )
