/**
 * Tier policy + backend response validation.
 * Covers: low / medium / high / confirmed-malicious / unknown / unavailable,
 * boundary scores (29/30/65/66), verdict escalation, and malformed responses.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { TIER, decide, errorDecision, validateAnalysis } from "../lib/policy.js";
import { backendResponse, finding } from "./helpers.js";

// --------------------------------- validation --------------------------------

test("validateAnalysis accepts a real backend response", () => {
  const res = validateAnalysis(backendResponse());
  assert.equal(res.ok, true);
  assert.equal(res.value.verdict, "unknown");
  assert.equal(res.value.score, 0);
});

test("validateAnalysis accepts a full confirmed-threat response", () => {
  const res = validateAnalysis(
    backendResponse({
      url: "https://evil.example/",
      risk_level: "high",
      verdict: "confirmed_malicious",
      score: 75,
      findings: [finding({ severity: "critical" })],
      reputation_status: "threat_detected",
      advice: "Do not visit.",
      reputation: {
        provider: "google_safe_browsing",
        status: "threat_detected",
        matches: [{ threat_type: "MALWARE" }],
        error_reason: null,
      },
    })
  );
  assert.equal(res.ok, true);
  assert.equal(res.value.reputation.status, "threat_detected");
});

test("validateAnalysis rejects malformed payloads (table)", () => {
  const bad = [
    null,
    "just a string",
    [],
    {},
    backendResponse({ score: "high" }), // score must be a number
    backendResponse({ score: -1 }),
    backendResponse({ score: 101 }),
    backendResponse({ score: NaN }),
    backendResponse({ risk_level: "catastrophic" }),
    backendResponse({ verdict: "definitely_fine" }),
    backendResponse({ reputation_status: "probably_ok" }),
    backendResponse({ advice: 42 }),
    backendResponse({ findings: "none" }),
    backendResponse({ findings: [{}] }), // missing title
    backendResponse({ findings: [{ title: "x", severity: "apocalyptic" }] }),
    backendResponse({ findings: [{ title: "x", confidence: "certain" }] }),
  ];
  for (const payload of bad) {
    const res = validateAnalysis(payload);
    assert.equal(res.ok, false, `should reject: ${JSON.stringify(payload)?.slice(0, 80)}`);
    assert.ok(res.errors.length > 0);
  }
});

test("validateAnalysis tolerates missing optional finding fields", () => {
  const res = validateAnalysis(
    backendResponse({ findings: [{ engine: "e", title: "t" }] })
  );
  assert.equal(res.ok, true);
  assert.equal(res.value.findings[0].severity, "info");
  assert.equal(res.value.findings[0].confidence, "medium");
});

// --------------------------------- boundaries --------------------------------

function tierOf(overrides) {
  const res = validateAnalysis(backendResponse(overrides));
  assert.equal(res.ok, true, JSON.stringify(overrides));
  return decide(res.value).tier;
}

test("score 0–29 → allow", () => {
  assert.equal(tierOf({ score: 0 }), TIER.ALLOW);
  assert.equal(tierOf({ score: 15 }), TIER.ALLOW);
  assert.equal(tierOf({ score: 29 }), TIER.ALLOW);
});

test("score 30–65 inclusive → warn", () => {
  assert.equal(tierOf({ score: 30, risk_level: "low", verdict: "unknown" }), TIER.WARN);
  assert.equal(tierOf({ score: 50, risk_level: "medium" }), TIER.WARN);
  assert.equal(tierOf({ score: 65, risk_level: "medium" }), TIER.WARN);
});

test("score 66+ → block", () => {
  // risk_level medium: only the score itself can push this into block.
  assert.equal(tierOf({ score: 66, risk_level: "medium" }), TIER.BLOCK);
  assert.equal(tierOf({ score: 100, risk_level: "high" }), TIER.BLOCK);
});

test("confirmed_malicious blocks regardless of score", () => {
  assert.equal(
    tierOf({
      verdict: "confirmed_malicious",
      reputation_status: "threat_detected",
      risk_level: "high",
      score: 10, // even a low score must not downgrade it
    }),
    TIER.BLOCK
  );
});

test("reputation threat_detected blocks regardless of score", () => {
  assert.equal(
    tierOf({ verdict: "unknown", reputation_status: "threat_detected", score: 5 }),
    TIER.BLOCK
  );
});

test("risk_level high blocks regardless of score", () => {
  assert.equal(tierOf({ risk_level: "high", score: 10 }), TIER.BLOCK);
});

test("suspicious verdict escalates to warn even with a low score", () => {
  assert.equal(
    tierOf({ verdict: "suspicious", risk_level: "low", score: 5 }),
    TIER.WARN
  );
});

test("risk_level medium escalates to warn even with a low score", () => {
  assert.equal(tierOf({ risk_level: "medium", score: 10 }), TIER.WARN);
});

// ------------------------- unknown / unavailable ----------------------------

test("unknown verdict + no known threat → allow but NEVER verified", () => {
  const res = validateAnalysis(
    backendResponse({ verdict: "unknown", reputation_status: "no_known_threat", score: 0 })
  );
  const d = decide(res.value);
  assert.equal(d.tier, TIER.ALLOW);
  assert.equal(d.unverified, true);
  assert.equal(d.verified, false);
  assert.ok(d.reasons.some((r) => /Not verified/i.test(r)));
});

test("unavailable reputation → allow, unverified, with explicit reason", () => {
  const res = validateAnalysis(
    backendResponse({
      verdict: "unknown",
      risk_level: "unknown",
      reputation_status: "unavailable",
      advice: "The reputation check could not be completed (timeout).",
      reputation: {
        provider: "google_safe_browsing",
        status: "unavailable",
        matches: [],
        error_reason: "timeout",
      },
    })
  );
  const d = decide(res.value);
  assert.equal(d.tier, TIER.ALLOW);
  assert.equal(d.unverified, true);
  assert.ok(d.reasons.some((r) => /reputation check unavailable/i.test(r)));
});

test("unavailable + medium score → warn (verification banner present)", () => {
  const res = validateAnalysis(
    backendResponse({
      verdict: "unknown",
      risk_level: "medium",
      score: 45,
      reputation_status: "unavailable",
    })
  );
  const d = decide(res.value);
  assert.equal(d.tier, TIER.WARN);
  assert.equal(d.unverified, true);
});

test("verified_safe (reserved) would count as verified — never for unknown", () => {
  const verified = decide(
    validateAnalysis(backendResponse({ verdict: "verified_safe", score: 0 })).value
  );
  assert.equal(verified.verified, true);
  assert.equal(verified.unverified, false);

  const unknown = decide(
    validateAnalysis(backendResponse({ verdict: "unknown", score: 0 })).value
  );
  assert.equal(unknown.verified, false);
});

// ------------------------------ error decisions -----------------------------

test("errorDecision never claims safety and is always unverified + allow", () => {
  for (const kind of ["timeout", "network", "invalid_response", "invalid_json", "bad_request"]) {
    const d = errorDecision("https://x.example/", kind);
    assert.equal(d.tier, TIER.ALLOW);
    assert.equal(d.unverified, true);
    assert.equal(d.verified, false);
    assert.equal(d.kind, "failed");
    assert.equal(d.error, kind);
    assert.ok(d.errorLabel.length > 0);
    assert.ok(d.reasons.join(" ").includes("NOT verified"));
  }
});
