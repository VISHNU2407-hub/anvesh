/**
 * Backend response validation + the risk-tier decision policy.
 *
 * Pure module: no Chrome APIs, no network. Imported by the background service
 * worker, the popup, and the Node test suite.
 *
 * ---------------------------------------------------------------------------
 * NAVIGATION POLICY (documented, deterministic)
 * ---------------------------------------------------------------------------
 * Inputs are the backend's `score`, `risk_level`, `verdict` and
 * `reputation_status` — never the score alone.
 *
 *   BLOCK (no bypass button):
 *     - verdict === "confirmed_malicious", OR
 *     - reputation_status === "threat_detected", OR
 *     - risk_level === "high", OR
 *     - score > 65
 *
 *   WARN (full-page interstitial; "Go Back" + "Continue Anyway"):
 *     - score in [30, 65] inclusive, OR
 *     - verdict === "suspicious" (verdict escalation: a strong detection
 *       finding is never silently waved through just because the score
 *       arithmetic landed low), OR
 *     - risk_level === "medium"
 *
 *   ALLOW (navigate normally):
 *     - everything else (score 0–29 with no escalation trigger)
 *
 * VERIFICATION POLICY (never fake safety):
 *   - `unknown` and `unavailable` results are NEVER treated as verified safe.
 *     Every decision carries `unverified: true` unless the backend explicitly
 *     emits verdict `verified_safe` (reserved by the backend and currently
 *     never emitted).
 *   - Unverified/failed scans still allow low-score navigation, because the
 *     backend reports `verdict: unknown` for essentially every benign URL
 *     (a completed "no known threat" lookup is *unknown*, not safe). Routing
 *     every unknown result through an interstitial would warn on nearly every
 *     click in the browser. Instead, unverified results are surfaced as a
 *     visible warning (toolbar badge "?", popup banner, and an in-page chip),
 *     and any interstitial that is shown includes the verification banner.
 *     Scans that fail (timeout / backend down / malformed response) follow the
 *     same path: fail open for navigation, but explicitly marked UNVERIFIED —
 *     never "safe".
 */

export const TIER = Object.freeze({
  ALLOW: "allow",
  WARN: "warn",
  BLOCK: "block",
});

const RISK_LEVELS = new Set(["unknown", "low", "medium", "high"]);
const VERDICTS = new Set([
  "confirmed_malicious",
  "suspicious",
  "unknown",
  "verified_safe",
]);
const REPUTATION_STATUSES = new Set([
  "threat_detected",
  "no_known_threat",
  "unavailable",
]);
const SEVERITIES = new Set(["info", "low", "medium", "high", "critical"]);
const CONFIDENCES = new Set(["low", "medium", "high"]);

const MEDIUM_SCORE_MIN = 30;
const BLOCK_SCORE_MIN = 66; // score > 65 → block; 30–65 inclusive → warn

/**
 * Validate a parsed JSON body against the backend's AnalyzeResponse schema.
 * Returns { ok: true, value } with a normalized copy, or
 * { ok: false, errors: [...] } describing every violated expectation.
 *
 * Extra unknown fields are allowed (the backend may add fields later);
 * missing/mistyped required fields are not.
 */
export function validateAnalysis(data) {
  const errors = [];
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    return { ok: false, errors: ["response is not a JSON object"] };
  }

  if (!RISK_LEVELS.has(data.risk_level)) {
    errors.push(`risk_level invalid: ${JSON.stringify(data.risk_level)}`);
  }
  if (!VERDICTS.has(data.verdict)) {
    errors.push(`verdict invalid: ${JSON.stringify(data.verdict)}`);
  }
  if (!REPUTATION_STATUSES.has(data.reputation_status)) {
    errors.push(`reputation_status invalid: ${JSON.stringify(data.reputation_status)}`);
  }

  const { score } = data;
  if (typeof score !== "number" || !Number.isFinite(score) || score < 0 || score > 100) {
    errors.push(`score invalid: ${JSON.stringify(score)}`);
  }

  if (typeof data.advice !== "string") {
    errors.push(`advice invalid: ${JSON.stringify(data.advice)}`);
  }

  if (!Array.isArray(data.findings)) {
    errors.push("findings is not an array");
  } else {
    data.findings.forEach((f, i) => {
      if (f === null || typeof f !== "object" || Array.isArray(f)) {
        errors.push(`findings[${i}] is not an object`);
        return;
      }
      if (typeof f.title !== "string" || f.title.length === 0) {
        errors.push(`findings[${i}].title missing`);
      }
      if (f.severity !== undefined && !SEVERITIES.has(f.severity)) {
        errors.push(`findings[${i}].severity invalid: ${JSON.stringify(f.severity)}`);
      }
      if (f.confidence !== undefined && !CONFIDENCES.has(f.confidence)) {
        errors.push(`findings[${i}].confidence invalid`);
      }
      if (f.engine !== undefined && typeof f.engine !== "string") {
        errors.push(`findings[${i}].engine invalid`);
      }
      if (f.description !== undefined && f.description !== null && typeof f.description !== "string") {
        errors.push(`findings[${i}].description invalid`);
      }
    });
  }

  if (errors.length > 0) return { ok: false, errors };

  return {
    ok: true,
    value: {
      url: typeof data.url === "string" ? data.url : "",
      risk_level: data.risk_level,
      verdict: data.verdict,
      score: data.score,
      reputation_status: data.reputation_status,
      advice: data.advice,
      findings: data.findings.map((f) => ({
        engine: typeof f.engine === "string" ? f.engine : "",
        rule_id: typeof f.rule_id === "string" ? f.rule_id : null,
        title: f.title,
        description: typeof f.description === "string" ? f.description : null,
        severity: f.severity ?? "info",
        confidence: f.confidence ?? "medium",
      })),
      reputation:
        data.reputation && typeof data.reputation === "object"
          ? {
              provider:
                typeof data.reputation.provider === "string"
                  ? data.reputation.provider
                  : "",
              status: data.reputation.status,
              error_reason:
                typeof data.reputation.error_reason === "string"
                  ? data.reputation.error_reason
                  : null,
            }
          : null,
    },
  };
}

/**
 * Decide the navigation tier from a *validated* backend response.
 * Returns { tier, reasons, unverified, verified }.
 */
export function decide(analysis) {
  const reasons = [];
  const { score, verdict, risk_level, reputation_status } = analysis;

  // --- Verification state: never claim safety we don't have. ---------------
  const verified = verdict === "verified_safe";
  const unverified = !verified;    if (unverified) {
      const bits = [];
      if (verdict === "unknown") bits.push("verdict is unknown");
      if (reputation_status === "unavailable") bits.push("reputation check unavailable");
      if (reputation_status === "no_known_threat") {
        bits.push("no known threat found (not proof of safety)");
      }
      reasons.push(
        `Not verified${bits.length ? `: ${bits.join(", ")}` : ""}. Verify before trusting this link.`
      );
    }

  // --- Block tier (no bypass). Strongest evidence first. -------------------
  if (verdict === "confirmed_malicious") {
    reasons.push("Confirmed malicious — threat intelligence matched this URL.");
    return { tier: TIER.BLOCK, reasons, unverified, verified };
  }
  if (reputation_status === "threat_detected") {
    reasons.push("Threat intelligence match.");
    return { tier: TIER.BLOCK, reasons, unverified, verified };
  }
  if (risk_level === "high") {
    reasons.push("Risk level is HIGH.");
    return { tier: TIER.BLOCK, reasons, unverified, verified };
  }
  if (score > 65) {
    reasons.push(`Score ${score} — above block threshold (65).`);
    return { tier: TIER.BLOCK, reasons, unverified, verified };
  }

  // --- Warn tier (Continue available only here). ---------------------------
  if (score >= MEDIUM_SCORE_MIN) {
    reasons.push(`Score ${score} — warning range (30–65).`);
    if (verdict === "unknown") {
      reasons.push("Verdict: unknown (not verified).");
    }
    return { tier: TIER.WARN, reasons, unverified, verified };
  }
  if (verdict === "suspicious") {
    reasons.push("Detection engines flagged this URL (suspicious).");
    return { tier: TIER.WARN, reasons, unverified, verified };
  }
  if (risk_level === "medium") {
    reasons.push("Risk level is MEDIUM.");
    return { tier: TIER.WARN, reasons, unverified, verified };
  }

  // --- Allow tier. ---------------------------------------------------------
  if (!verified) {
    // already pushed above
  }
  return { tier: TIER.ALLOW, reasons, unverified, verified };
}

/** Human-facing explanation for each scan failure kind. */
export const ERROR_LABELS = Object.freeze({
  timeout: "The backend did not respond in time.",
  network: "The backend could not be reached.",
  bad_request: "The backend rejected this URL (HTTP 400).",
  server_error: "The backend returned a server error.",
  invalid_json: "The backend response is not JSON.",
  invalid_response: "The backend response has an unexpected shape.",
  aborted: "The scan was aborted.",
  invalid_url: "Not a valid http(s) URL.",
});

/**
 * Decision used when the scan itself failed (timeout, backend unavailable,
 * malformed response). Navigation is allowed to proceed (fail-open — see the
 * policy note at the top of this file) but the result is explicitly marked
 * UNVERIFIED and never "safe".
 */
export function errorDecision(url, error) {
  const label = ERROR_LABELS[error] || ERROR_LABELS.network;
  return {
    kind: "failed",
    url,
    tier: TIER.ALLOW,
    error,
    errorLabel: label,
    reasons: [`Scan failed — ${label} This link was NOT verified.`],
    unverified: true,
    verified: false,
    analysis: null,
    ts: 0,
  };
}
