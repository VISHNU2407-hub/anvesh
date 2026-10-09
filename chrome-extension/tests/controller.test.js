/**
 * End-to-end behavior of the background controller with fake Chrome APIs:
 *
 *   - repeated clicks (in-flight dedupe + cache)
 *   - redirect chains + approval persistence (loop prevention)
 *   - Continue Anyway / block-tier refusal / back navigation
 *   - stale-navigation race guard
 *   - timeout / backend-unavailable / malformed-response fail-open policy
 *   - unknown / unavailable never treated as verified safe
 *   - MV3 service-worker restart (storage.session persistence)
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { LinkShieldController } from "../lib/controller.js";
import { ANALYZE_ENDPOINT, backendResponse, finding, makeDeps, makeFetch } from "./helpers.js";

const URL_A = "https://site-a.example/page";
const URL_EVIL = "https://evil.example/login";
const URL_SAFE = "https://safe.example/home";

function makeController(fetchImpl, overrides = {}) {
  const deps = makeDeps({ fetchImpl, ...overrides });
  return { controller: new LinkShieldController(deps), deps };
}

function byDest(handler) {
  // handler(destUrl) -> Response-like parts; the destination URL must only
  // ever travel in the request BODY to an /api/analyze endpoint.
  return makeFetch((url, init) => {
    assert.ok(String(url).endsWith("/api/analyze"), `unexpected fetch: ${url}`);
    assert.ok(!String(url).includes("evil.example"), "destination leaked into request URL");
    const dest = JSON.parse(init.body).url;
    return handler(dest);
  });
}

const ok = (body) => ({ status: 200, body });

// ---------------------------------------------------------------------------
// Click flow: tiers + navigation intents
// ---------------------------------------------------------------------------

test("low-score click → navigates the same tab and pre-approves the URL", async () => {
  const fetchImpl = byDest(() => ok(backendResponse({ score: 5 })));
  const { controller, deps } = makeController(fetchImpl);

  const res = await controller.handleMessage(
    { type: "ls:analyze-click", url: URL_A, intent: { mode: "current" } },
    { tab: { id: 7 } }
  );

  assert.equal(res.action, "navigate");
  assert.equal(res.record.tier, "allow");
  assert.deepEqual(deps.tabs.updates, [{ tabId: 7, url: URL_A }]);
  // Approved so the webNavigation observer won't re-scan our own navigation.
  assert.equal(await controller.isApproved(URL_A), true);
  assert.equal(fetchImpl.calls.length, 1);
});

test("medium-score click → warning page in the same tab; original stays in history", async () => {
  const fetchImpl = byDest(() => ok(backendResponse({ score: 45, risk_level: "medium" })));
  const { controller, deps } = makeController(fetchImpl);

  const res = await controller.handleMessage(
    { type: "ls:analyze-click", url: URL_EVIL, intent: { mode: "current" } },
    { tab: { id: 7 } }
  );

  assert.equal(res.action, "warning");
  assert.match(deps.tabs.updates[0].url, /^chrome-extension:\/\/test-id\/warning\/warning\.html\?case=/);
  const caseRec = await controller.getCase(res.caseId);
  assert.equal(caseRec.tier, "warn");
  assert.equal(caseRec.score, 45);
  assert.equal(caseRec.findings.length, 0);
});

test("high-score click → warning page; badge set to block marker", async () => {
  const fetchImpl = byDest(() => ok(backendResponse({ score: 90, risk_level: "high" })));
  const { controller, deps } = makeController(fetchImpl);

  const res = await controller.handleMessage(
    { type: "ls:analyze-click", url: URL_EVIL, intent: { mode: "current" } },
    { tab: { id: 7 } }
  );
  assert.equal(res.record.tier, "block");
  const badge = deps.action.badges.at(-1);
  assert.equal(badge.text, "✕");
  assert.equal(badge.tabId, 7);
});

test("confirmed malicious with LOW score still blocks", async () => {
  const fetchImpl = byDest(() =>
    ok(
      backendResponse({
        score: 10, // score alone would allow!
        verdict: "confirmed_malicious",
        reputation_status: "threat_detected",
        risk_level: "high",
        advice: "Do not visit.",
      })
    )
  );
  const { controller, deps } = makeController(fetchImpl);

  const res = await controller.handleMessage(
    { type: "ls:analyze-click", url: URL_EVIL, intent: { mode: "current" } },
    { tab: { id: 7 } }
  );
  assert.equal(res.record.tier, "block");
  assert.match(deps.tabs.updates[0].url, /warning\.html/);
});

test("ctrl/middle-click intent: allow opens a background tab; warn opens the warning there", async () => {
  const dests = ["https://x.example/", "https://y.example/"];
  let i = 0;
  const fetchImpl = byDest(() => ok(backendResponse({ score: i++ === 0 ? 5 : 50, risk_level: i === 2 ? "medium" : "low" })));
  const { controller, deps } = makeController(fetchImpl);

  const allow = await controller.handleMessage(
    { type: "ls:analyze-click", url: dests[0], intent: { mode: "tab", active: false } },
    { tab: { id: 7 } }
  );
  assert.equal(allow.action, "navigate");
  assert.deepEqual(deps.tabs.creates[0], { url: dests[0], active: false });

  const warn = await controller.handleMessage(
    { type: "ls:analyze-click", url: dests[1], intent: { mode: "tab", active: false } },
    { tab: { id: 7 } }
  );
  assert.equal(warn.action, "warning");
  assert.match(deps.tabs.creates[1].url, /warning\.html/);
});

test("shift-click intent opens a window", async () => {
  const fetchImpl = byDest(() => ok(backendResponse({ score: 45, risk_level: "medium" })));
  const { controller, deps } = makeController(fetchImpl);

  await controller.handleMessage(
    { type: "ls:analyze-click", url: URL_EVIL, intent: { mode: "window", active: true } },
    { tab: { id: 7 } }
  );
  assert.equal(deps.windows.creates.length, 1);
  assert.match(deps.windows.creates[0].url, /warning\.html/);
});

// ---------------------------------------------------------------------------
// Repeated clicks / repeated scans
// ---------------------------------------------------------------------------

test("concurrent clicks on the same URL share ONE backend call", async () => {
  let calls = 0;
  const fetchImpl = byDest(() => {
    calls += 1;
    return ok(backendResponse({ score: 45, risk_level: "medium" }));
  });
  const { controller } = makeController(fetchImpl);

  const [r1, r2] = await Promise.all([
    controller.handleMessage(
      { type: "ls:analyze-click", url: URL_EVIL, intent: { mode: "current" } },
      { tab: { id: 7 } }
    ),
    controller.handleMessage(
      { type: "ls:analyze-click", url: URL_EVIL, intent: { mode: "current" } },
      { tab: { id: 7 } }
    ),
  ]);

  assert.equal(calls, 1);
  assert.equal(r1.action, "warning");
  assert.equal(r2.action, "warning");
});

test("a later repeated click is served from cache — still one backend call", async () => {
  let calls = 0;
  const fetchImpl = byDest(() => {
    calls += 1;
    return ok(backendResponse({ score: 5 }));
  });
  const { controller, deps } = makeController(fetchImpl);

  for (let n = 0; n < 3; n++) {
    await controller.handleMessage(
      { type: "ls:analyze-click", url: URL_A, intent: { mode: "current" } },
      { tab: { id: 7 } }
    );
  }
  assert.equal(calls, 1);
  assert.equal(deps.tabs.updates.length, 3); // each click still navigates
});

test("popup scan (fresh) bypasses the cache; a second unforced scan uses it", async () => {
  let calls = 0;
  const fetchImpl = byDest(() => {
    calls += 1;
    return ok(backendResponse({ score: 12 }));
  });
  const { controller } = makeController(fetchImpl);

  const first = await controller.handleMessage({ type: "ls:scan", url: URL_A }, {});
  assert.equal(first.record.kind, "analyzed");
  const fresh = await controller.handleMessage({ type: "ls:scan", url: URL_A, fresh: true }, {});
  assert.equal(calls, 2);
  assert.equal(fresh.record.kind, "analyzed");

  // lastScan is retrievable for popup restore.
  const last = await controller.handleMessage({ type: "ls:last-scan" }, {});
  assert.equal(last.record.url, URL_A);
});

// ---------------------------------------------------------------------------
// Unknown / unavailable / failure policy
// ---------------------------------------------------------------------------

test("unknown + unavailable reputation → allow + UNVERIFIED badge, never 'safe'", async () => {
  const fetchImpl = byDest(() =>
    ok(
      backendResponse({
        verdict: "unknown",
        risk_level: "unknown",
        reputation_status: "unavailable",
        advice: "The reputation check could not be completed (missing_api_key).",
        reputation: {
          provider: "google_safe_browsing",
          status: "unavailable",
          matches: [],
          error_reason: "missing_api_key",
        },
      })
    )
  );
  const { controller, deps } = makeController(fetchImpl);

  const res = await controller.handleMessage(
    { type: "ls:analyze-click", url: URL_A, intent: { mode: "current" } },
    { tab: { id: 7 } }
  );

  assert.equal(res.record.tier, "allow");
  assert.equal(res.record.unverified, true);
  assert.equal(res.record.verified, false);
  assert.match(res.record.reasons.join(" "), /Not verified/i);
  assert.equal(deps.tabs.updates[0].url, URL_A); // navigation proceeds
  assert.equal(deps.action.badges.at(-1).text, "?"); // visible warning
});

test("timeout → fail-open navigation with an explicit timeout failure record", async () => {
  const fetchImpl = async (url) => {
    const err = new Error("The operation was aborted");
    err.name = "AbortError";
    throw err;
  };
  const { controller, deps } = makeController(fetchImpl);

  const res = await controller.handleMessage(
    { type: "ls:analyze-click", url: URL_A, intent: { mode: "current" } },
    { tab: { id: 7 } }
  );

  assert.equal(res.action, "navigate");
  assert.equal(res.record.kind, "failed");
  assert.equal(res.record.error, "timeout");
  assert.equal(res.record.unverified, true);
  assert.equal(deps.tabs.updates[0].url, URL_A);
  assert.equal(deps.action.badges.at(-1).text, "?");
});

test("backend unavailable (connection refused) → fail-open + unverified", async () => {
  const fetchImpl = async () => {
    throw new TypeError("fetch failed");
  };
  const { controller, deps } = makeController(fetchImpl);

  const res = await controller.handleMessage(
    { type: "ls:analyze-click", url: URL_A, intent: { mode: "current" } },
    { tab: { id: 7 } }
  );
  assert.equal(res.record.kind, "failed");
  assert.equal(res.record.error, "network");
  assert.equal(res.record.unverified, true);
  assert.deepEqual(deps.tabs.updates[0], { tabId: 7, url: URL_A });
});

test("malformed backend responses → invalid_response failure, not a crash", async () => {
  const bodies = [
    { unexpected: "shape" },
    backendResponse({ score: "high" }),
    backendResponse({ verdict: "totally-fine" }),
    backendResponse({ findings: "oops" }),
  ];
  for (const body of bodies) {
    const fetchImpl = byDest(() => ok(body));
    const { controller } = makeController(fetchImpl);
    const res = await controller.handleMessage(
      { type: "ls:analyze-click", url: URL_A, intent: { mode: "current" } },
      { tab: { id: 7 } }
    );
    assert.equal(res.record.kind, "failed", JSON.stringify(body).slice(0, 50));
    assert.equal(res.record.error, "invalid_response");
    assert.equal(res.record.unverified, true);
  }
});

test("non-JSON backend response → invalid_json failure", async () => {
  const fetchImpl = byDest(() => ({ status: 200, body: "<html>oops</html>" }));
  const { controller } = makeController(fetchImpl);
  const res = await controller.handleMessage(
    { type: "ls:analyze-click", url: URL_A, intent: { mode: "current" } },
    { tab: { id: 7 } }
  );
  assert.equal(res.record.error, "invalid_json");
  assert.equal(res.record.tier, "allow"); // fail-open, never "safe"
  assert.equal(res.record.unverified, true);
});

test("failed scans are cached so a dead backend is not hammered", async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    throw new TypeError("fetch failed");
  };
  const { controller } = makeController(fetchImpl);

  await controller.onBeforeNavigate({ tabId: 1, frameId: 0, url: URL_A });
  await controller.onBeforeNavigate({ tabId: 1, frameId: 0, url: URL_A });
  assert.equal(calls, 1);
});

// ---------------------------------------------------------------------------
// Redirects, approvals, loop prevention, restart persistence
// ---------------------------------------------------------------------------

test("redirect chain: allow A, warn B, continue B, then B never re-warns", async () => {
  const fetchImpl = byDest((dest) =>
    dest === URL_A
      ? ok(backendResponse({ score: 5 }))
      : ok(backendResponse({ score: 50, risk_level: "medium", url: dest }))
  );
  const { controller, deps } = makeController(fetchImpl);

  // 1) User (or server) navigates to A → allowed silently.
  await controller.onBeforeNavigate({ tabId: 1, frameId: 0, url: URL_A });
  assert.equal(deps.tabs.updates.length, 0);

  // 2) A server-redirects to B → warned.
  await controller.onBeforeNavigate({ tabId: 1, frameId: 0, url: URL_EVIL });
  assert.equal(deps.tabs.updates.length, 1);
  assert.match(deps.tabs.updates[0].url, /warning\.html/);
  const caseId = deps.tabs.updates[0].url.split("case=")[1];

  // 3) User clicks Continue Anyway (warn tier only). The page itself then
  //    location.replace()s to B, so the interstitial leaves the back history.
  const cont = await controller.handleMessage(
    { type: "warning:continue", caseId },
    { tab: { id: 1 } }
  );
  assert.equal(cont.ok, true);
  assert.equal(cont.url, URL_EVIL); // returned to the warning page to navigate
  assert.equal(await controller.isApproved(URL_EVIL), true);

  // 4) B redirects again (same URL) → approval prevents re-analysis & loops.
  await controller.onBeforeNavigate({ tabId: 1, frameId: 0, url: URL_EVIL });
  // Still exactly one navigation by the background (the warning swap): the
  // approval skips re-analysis, and Continue navigates via location.replace
  // on the warning page rather than a background tabs.update.
  assert.equal(deps.tabs.updates.length, 1);

  // 5) A fresh explicit CLICK on B still warns (continuation is per navigation).
  const reClick = await controller.handleMessage(
    { type: "ls:analyze-click", url: URL_EVIL, intent: { mode: "current" } },
    { tab: { id: 9 } }
  );
  assert.equal(reClick.action, "warning");
  assert.equal(fetchImpl.calls.length, 2); // A + B; the re-click hit the cache
});

test("block tier: background refuses warning:continue even if a page forges it", async () => {
  const fetchImpl = byDest(() =>
    ok(
      backendResponse({
        score: 95,
        risk_level: "high",
        verdict: "confirmed_malicious",
        reputation_status: "threat_detected",
      })
    )
  );
  const { controller, deps } = makeController(fetchImpl);

  await controller.onBeforeNavigate({ tabId: 1, frameId: 0, url: URL_EVIL });
  assert.equal(deps.tabs.updates.length, 1);
  const caseId = deps.tabs.updates[0].url.split("case=")[1];
  const caseRec = await controller.getCase(caseId);
  assert.equal(caseRec.tier, "block");

  const cont = await controller.handleMessage(
    { type: "warning:continue", caseId },
    { tab: { id: 1 } }
  );
  assert.equal(cont.ok, false);
  assert.equal(cont.reason, "not-allowed");
  // The flagged URL was never navigated to.
  assert.ok(!deps.tabs.updates.some((u) => u.url === URL_EVIL));
  assert.ok(!deps.tabs.creates.some((u) => u.url === URL_EVIL));

  // Unknown case ids are refused too.
  const bad = await controller.handleMessage(
    { type: "warning:continue", caseId: "case-does-not-exist" },
    { tab: { id: 1 } }
  );
  assert.equal(bad.ok, false);
});

test("warning:details returns stored case, or not-found", async () => {
  const fetchImpl = byDest(() => ok(backendResponse({ score: 70, risk_level: "high" })));
  const { controller } = makeController(fetchImpl);
  const res = await controller.handleMessage(
    { type: "ls:analyze-click", url: URL_EVIL, intent: { mode: "current" } },
    { tab: { id: 1 } }
  );
  const details = await controller.handleMessage(
    { type: "warning:details", caseId: res.caseId },
    {}
  );
  assert.equal(details.ok, true);
  assert.equal(details.record.tier, "block");

  const missing = await controller.handleMessage({ type: "warning:details", caseId: "nope" }, {});
  assert.equal(missing.ok, false);
});

test("stale navigation result does not yank the tab away", async () => {
  let resolveEvil;
  const fetchImpl = byDest((dest) => {
    if (dest === URL_EVIL) {
      return new Promise((resolve) => {
        resolveEvil = () => resolve(ok(backendResponse({ score: 95, risk_level: "high", url: dest })));
      });
    }
    return ok(backendResponse({ score: 0, url: dest }));
  });
  const { controller, deps } = makeController(fetchImpl);

  // Evil navigation starts, analysis in flight...
  const pending = controller.onBeforeNavigate({ tabId: 1, frameId: 0, url: URL_EVIL });
  // ...user navigates elsewhere before it resolves.
  await controller.onBeforeNavigate({ tabId: 1, frameId: 0, url: URL_SAFE });
  resolveEvil();
  await pending;

  // The slow evil result must NOT replace the tab the user moved to.
  assert.equal(deps.tabs.updates.length, 0);

  // But a fresh attempt at the evil URL (with it current again) still warns.
  await controller.onBeforeNavigate({ tabId: 1, frameId: 0, url: URL_EVIL });
  assert.equal(deps.tabs.updates.length, 1);
  assert.match(deps.tabs.updates[0].url, /warning\.html/);
  // evil (1st) + safe (2nd); the retry served evil from the cache.
  assert.equal(fetchImpl.calls.length, 2);
});

test("iframe navigations (frameId !== 0) are not intercepted by the observer", async () => {
  let calls = 0;
  const fetchImpl = byDest(() => {
    calls += 1;
    return ok(backendResponse({ score: 95, risk_level: "high" }));
  });
  const { controller, deps } = makeController(fetchImpl);

  await controller.onBeforeNavigate({ tabId: 1, frameId: 3, url: URL_EVIL });
  assert.equal(calls, 0);
  assert.equal(deps.tabs.updates.length, 0);
});

test("browser-internal URLs never reach the analysis API", async () => {
  let calls = 0;
  const fetchImpl = byDest(() => {
    calls += 1;
    return ok(backendResponse());
  });
  const { controller } = makeController(fetchImpl);

  for (const url of [
    "chrome://extensions",
    "chrome-extension://test-id/warning/warning.html?case=case-1",
    "about:blank",
    "chrome://newtab",
    "file:///etc/passwd",
    "view-source:https://x.example/",
  ]) {
    await controller.onBeforeNavigate({ tabId: 1, frameId: 0, url });
  }
  assert.equal(calls, 0);
});

test("approvals + cache survive an MV3 service-worker restart", async () => {
  let calls = 0;
  const fetchImpl = byDest(() => {
    calls += 1;
    return ok(backendResponse({ score: 50, risk_level: "medium", url: URL_EVIL }));
  });

  // First "worker lifetime".
  const first = makeController(fetchImpl);
  await first.controller.onBeforeNavigate({ tabId: 1, frameId: 0, url: URL_EVIL });
  assert.equal(first.deps.tabs.updates.length, 1);
  const caseId = first.deps.tabs.updates[0].url.split("case=")[1];
  await first.controller.handleMessage({ type: "warning:continue", caseId }, { tab: { id: 1 } });
  assert.equal(calls, 1);

  // New controller instance sharing the same storage.session = worker restart.
  const second = new LinkShieldController(
    makeDeps({ fetchImpl, session: first.deps.session, sync: first.deps.sync })
  );
  await second.onBeforeNavigate({ tabId: 1, frameId: 0, url: URL_EVIL });
  assert.equal(calls, 1); // approval persisted → no re-analysis, no loop
});

test("changing settings invalidates cached results", async () => {
  let calls = 0;
  const fetchImpl = byDest(() => {
    calls += 1;
    return ok(backendResponse({ score: 5 }));
  });
  const { controller } = makeController(fetchImpl);

  await controller.handleMessage({ type: "ls:scan", url: URL_A }, {});
  await controller.handleMessage({ type: "ls:scan", url: URL_A }, {});
  assert.equal(calls, 1);

  await controller.handleMessage(
    { type: "ls:settings:set", settings: { backendUrl: "http://localhost:9000" } },
    {}
  );
  await controller.handleMessage({ type: "ls:scan", url: URL_A }, {});
  assert.equal(calls, 2);
});

test("settings are validated and clamped", async () => {
  const fetchImpl = byDest(() => ok(backendResponse()));
  const { controller } = makeController(fetchImpl);

  const s1 = await controller.handleMessage(
    { type: "ls:settings:set", settings: { backendUrl: "javascript:alert(1)", timeoutMs: 999999 } },
    {}
  );
  assert.equal(s1.settings.backendUrl, "http://127.0.0.1:8000"); // rejected
  assert.equal(s1.settings.timeoutMs, 30000); // clamped

  const s2 = await controller.handleMessage(
    { type: "ls:settings:set", settings: { backendUrl: "http://localhost:9000/", timeoutMs: 500 } },
    {}
  );
  assert.equal(s2.settings.backendUrl, "http://localhost:9000"); // slash trimmed
  assert.equal(s2.settings.timeoutMs, 1000); // clamped
  assert.equal(s2.settings.protectMode, "cross-origin");
});

test("suspicious verdict with low score still reaches the warning page", async () => {
  const fetchImpl = byDest(() =>
    ok(
      backendResponse({
        score: 5,
        verdict: "suspicious",
        risk_level: "low",
        findings: [finding({ severity: "low" })],
        advice: "Detection engine(s) flagged: Lookalike domain.",
      })
    )
  );
  const { controller, deps } = makeController(fetchImpl);

  const res = await controller.handleMessage(
    { type: "ls:analyze-click", url: URL_EVIL, intent: { mode: "current" } },
    { tab: { id: 7 } }
  );
  assert.equal(res.action, "warning");
  assert.equal(res.record.tier, "warn");
  assert.match(deps.tabs.updates[0].url, /warning\.html/);
});
