/**
 * Live integration: drives the real controller against the REAL FastAPI
 * backend when it is running on http://127.0.0.1:8000.
 *
 * Skips automatically (as a whole) when the backend is not reachable, so
 * `npm test` stays green offline. Run it with the backend up to validate the
 * extension's response validation + tier policy against the actual API
 * schema (backend/app/models.py).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { LinkShieldController } from "../lib/controller.js";
import { analyzeUrl } from "../lib/api.js";
import { TIER, validateAnalysis } from "../lib/policy.js";
import { makeDeps } from "./helpers.js";

const LIVE_BACKEND = process.env.LINKSHIELD_BACKEND || "http://127.0.0.1:8000";

async function backendUp() {
  try {
    const res = await fetch(`${LIVE_BACKEND}/health`, {
      signal: AbortSignal.timeout(1500),
    });
    return res.ok;
  } catch {
    return false;
  }
}

const up = await backendUp();

test(
  "live backend: response validates against the extension schema",
  { skip: up ? false : `backend not reachable at ${LIVE_BACKEND}` },
  async () => {
    const res = await analyzeUrl({
      fetchImpl: fetch,
      baseUrl: LIVE_BACKEND,
      url: "https://example.com/",
      timeoutMs: 10000,
    });
    assert.equal(res.ok, true, JSON.stringify(res));
    const validated = validateAnalysis(res.data);
    assert.equal(validated.ok, true, JSON.stringify(validated.errors));
    assert.ok(typeof res.data.advice === "string" && res.data.advice.length > 0);
    // The backend never claims safety on a completed lookup.
    assert.notEqual(res.data.verdict, "verified_safe");
  }
);

test(
  "live backend: numeric-IP URL lands in the warn tier end-to-end",
  { skip: up ? false : `backend not reachable at ${LIVE_BACKEND}` },
  async () => {
    const deps = makeDeps({ fetchImpl: fetch });
    deps.sync.data.settings = {
      backendUrl: LIVE_BACKEND,
      timeoutMs: 10000,
      protectMode: "cross-origin",
    };
    const controller = new LinkShieldController(deps);

    const res = await controller.handleMessage(
      { type: "ls:analyze-click", url: "http://2130706433/", intent: { mode: "current" } },
      { tab: { id: 3 } }
    );

    assert.equal(res.action, "warning");
    assert.equal(res.record.kind, "analyzed");
    assert.equal(res.record.tier, TIER.WARN); // score 30–65 or suspicious
    assert.ok(res.record.analysis.score >= 30 || res.record.analysis.verdict === "suspicious");
    assert.match(deps.tabs.updates[0].url, /warning\.html\?case=/);

    // The stored interstitial case carries everything the page renders.
    const caseId = deps.tabs.updates[0].url.split("case=")[1];
    const caseRec = await controller.getCase(caseId);
    assert.ok(new URL(caseRec.url).hostname.length > 0);
    assert.ok(caseRec.findings.length > 0);
    assert.ok(caseRec.reasons.length > 0);
    assert.equal(caseRec.unverified, true); // suspicious/unknown = never "safe"
  }
);

test(
  "live backend: benign URL is allowed but marked unverified",
  { skip: up ? false : `backend not reachable at ${LIVE_BACKEND}` },
  async () => {
    const deps = makeDeps({ fetchImpl: fetch });
    deps.sync.data.settings = {
      backendUrl: LIVE_BACKEND,
      timeoutMs: 10000,
      protectMode: "cross-origin",
    };
    const controller = new LinkShieldController(deps);

    const res = await controller.handleMessage(
      { type: "ls:analyze-click", url: "https://example.com/", intent: { mode: "current" } },
      { tab: { id: 4 } }
    );
    assert.equal(res.action, "navigate");
    assert.equal(res.record.unverified, true); // unknown verdict ≠ verified safe
    assert.deepEqual(deps.tabs.updates[0], { tabId: 4, url: "https://example.com/" });
  }
);
