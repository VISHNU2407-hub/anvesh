/**
 * Warning interstitial: view model, button policy (Continue only for the
 * medium tier), text-only rendering (escaping), and back-navigation logic.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  backAction,
  buildWarningViewModel,
  renderWarning,
} from "../lib/warning-view.js";

// ---------------------------------------------------------------------------
// Fake DOM that throws on innerHTML usage — the renderer must be text-only.
// ---------------------------------------------------------------------------

function makeEl(tag) {
  const el = {
    tagName: tag,
    id: "",
    className: "",
    textContent: "",
    hidden: false,
    type: "",
    disabled: false,
    dataset: {},
    style: {},
    children: [],
    parentNode: null,
    appendChild(child) {
      child.parentNode = el;
      el.children.push(child);
      return child;
    },
    removeChild(child) {
      el.children = el.children.filter((c) => c !== child);
      child.parentNode = null;
    },
  };
  Object.defineProperty(el, "innerHTML", {
    get() {
      throw new Error("innerHTML must never be read by the renderer");
    },
    set() {
      throw new Error("innerHTML must never be written by the renderer");
    },
  });
  return el;
}

const REQUIRED_IDS = [
  "headline",
  "subline",
  "hostname",
  "url",
  "score-block",
  "score-label",
  "score-fill",
  "chips",
  "unverified-banner",
  "reasons-block",
  "reasons",
  "findings-block",
  "findings",
  "advice-block",
  "advice",
  "actions",
];

function makeDoc() {
  const byId = {};
  for (const id of REQUIRED_IDS) byId[id] = makeEl("div");
  return {
    byId,
    getElementById: (id) => byId[id] || null,
    createElement: (tag) => makeEl(tag),
  };
}

function caseFixture(overrides = {}) {
  return {
    id: "case-1",
    url: "https://evil.example/login?next=steal",
    tier: "warn",
    score: 45,
    riskLevel: "medium",
    verdict: "suspicious",
    reputationStatus: "no_known_threat",
    findings: [
      {
        title: "Credential-harvesting form",
        severity: "high",
        description: "Form posts credentials to a different host.",
        engine: "linkshield_rule_engine",
      },
      { title: "Minor note", severity: "info", description: "", engine: "e" },
    ],
    advice: "Do not enter credentials.",
    reasons: ["Risk score 45 is in the warning range (30–65)."],
    unverified: true,
    error: null,
    errorLabel: null,
    createdAt: 1,
    ...overrides,
  };
}

// --------------------------------- tiers -------------------------------------

test("warn tier shows Go Back + Continue Anyway", () => {
  const model = buildWarningViewModel(caseFixture());
  assert.equal(model.tier, "warn");
  assert.equal(model.showContinue, true);
  assert.deepEqual(
    model.buttons.map((b) => b.id),
    ["back", "continue"]
  );
  assert.equal(model.buttons[0].label, "Go Back");
  assert.equal(model.buttons[1].label, "Continue Anyway");
});

test("block tier has NO continue button — only 'Go Back to Safety'", () => {
  const model = buildWarningViewModel(
    caseFixture({
      tier: "block",
      score: 90,
      riskLevel: "high",
      verdict: "confirmed_malicious",
      reputationStatus: "threat_detected",
    })
  );
  assert.equal(model.tier, "block");
  assert.equal(model.showContinue, false);
  assert.deepEqual(
    model.buttons.map((b) => b.id),
    ["back"]
  );
  assert.equal(model.buttons[0].label, "Go Back to Safety");

  // Rendered DOM must not contain a continue button either.
  const doc = makeDoc();
  renderWarning(doc, model);
  const actions = doc.byId["actions"];
  assert.equal(actions.children.length, 1);
  assert.equal(actions.children[0].id, "btn-back");
  assert.ok(!actions.children.some((c) => c.id === "btn-continue"));
});

test("expired/missing case renders a safe state without continue", () => {
  const model = buildWarningViewModel(null);
  assert.equal(model.missing, true);
  assert.equal(model.showContinue, false);
  assert.equal(model.buttons.length, 1);
  const doc = makeDoc();
  renderWarning(doc, model);
  assert.ok(!doc.byId["actions"].children.some((c) => c.id === "btn-continue"));
});

test("renderer uses textContent only — hostile URL/finding text stays literal", () => {
  const hostile = `https://evil.example/<script>alert(1)</script>?q=<img src=x onerror=alert(2)>`;
  const model = buildWarningViewModel(
    caseFixture({
      url: hostile,
      findings: [{ title: `<b>bold finding</b>`, severity: "high", description: `<i>x</i>`, engine: "e" }],
      advice: `<style>*{display:none}</style>`,
      reasons: [`reason <svg onload=alert(1)>`],
    })
  );

  const doc = makeDoc();
  // Throws if the renderer ever touches innerHTML.
  renderWarning(doc, model);

  assert.ok(doc.byId["url"].textContent.includes("<script>alert(1)</script>"));
  assert.ok(doc.byId["url"].textContent.includes("<img src=x onerror=alert(2)>"));

  const findings = doc.byId["findings"].children;
  assert.ok(findings[0].children.some((c) => c.textContent.includes("<b>bold finding</b>")));
  assert.ok(doc.byId["advice"].textContent.includes("<style>"));

  const reasons = doc.byId["reasons"].children;
  assert.ok(reasons[0].textContent.includes("<svg onload=alert(1)>"));
});

test("score bar renders correct width and color class", () => {
  const doc = makeDoc();
  renderWarning(doc, buildWarningViewModel(caseFixture({ score: 45 })));
  assert.equal(doc.byId["score-fill"].style.width, "45%");
  assert.match(doc.byId["score-fill"].className, /medium/);
  assert.equal(doc.byId["score-label"].textContent, "Risk score 45/100");

  const doc2 = makeDoc();
  renderWarning(doc2, buildWarningViewModel(caseFixture({ score: 80, tier: "block" })));
  assert.match(doc2.byId["score-fill"].className, /high/);
});

test("hostname and display URL come from the flagged destination", () => {
  const doc = makeDoc();
  renderWarning(doc, buildWarningViewModel(caseFixture()));
  assert.equal(doc.byId["hostname"].textContent, "evil.example");
  assert.equal(doc.byId["url"].textContent, "https://evil.example/login?next=steal");
});

test("unverified banner is shown exactly when the case is unverified", () => {
  const doc = makeDoc();
  renderWarning(doc, buildWarningViewModel(caseFixture({ unverified: true })));
  assert.equal(doc.byId["unverified-banner"].hidden, false);
  assert.match(doc.byId["unverified-banner"].textContent, /not verified as safe/i);

  const doc2 = makeDoc();
  renderWarning(doc2, buildWarningViewModel(caseFixture({ unverified: false })));
  assert.equal(doc2.byId["unverified-banner"].hidden, true);
});

test("findings are sorted by severity (critical first)", () => {
  const model = buildWarningViewModel(
    caseFixture({
      findings: [
        { title: "low one", severity: "low", description: "", engine: "e" },
        { title: "critical one", severity: "critical", description: "", engine: "e" },
        { title: "medium one", severity: "medium", description: "", engine: "e" },
      ],
    })
  );
  assert.deepEqual(
    model.findings.map((f) => f.severity),
    ["critical", "medium", "low"]
  );
});

// ------------------------------ back navigation -----------------------------

test("back: history exists → go back in history", () => {
  assert.deepEqual(backAction(2), { type: "history-back" });
  assert.deepEqual(backAction(10), { type: "history-back" });
});

test("back: fresh tab (no history) → about:blank, never the flagged URL", () => {
  assert.deepEqual(backAction(1), { type: "navigate", url: "about:blank" });
  assert.deepEqual(backAction(0), { type: "navigate", url: "about:blank" });
  assert.deepEqual(backAction(undefined), { type: "navigate", url: "about:blank" });
});
