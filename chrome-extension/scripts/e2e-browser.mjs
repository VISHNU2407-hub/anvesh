/**
 * Real-browser end-to-end test for the URL Lens extension.
 *
 * Loads the unpacked extension into installed Chrome the SUPPORTED way for
 * Chrome 137+ (where --load-extension was removed): launch Chrome with
 * --remote-debugging-pipe --enable-unsafe-extension-debugging and issue the
 * CDP `Extensions.loadUnpacked` command.
 *
 * Then drives actual page clicks through CDP and verifies in a real DOM:
 *   1. low-score link        → direct navigation (allowed) + one backend call
 *   2. non-protected link    → navigation proceeds without an interstitial
 *   3. medium link           → interstitial (hostname, score, reasons, banner,
 *                              Continue + Go Back); Continue navigates; Back
 *                              returns to the source page
 *   4. malicious link        → block interstitial, NO Continue button,
 *                              "Go Back to Safety" returns to the source page
 *   5. rapid double click    → exactly one backend scan
 *   6. malformed response    → fail-open navigation (documented), no crash
 *   7. backend down          → fail-open navigation (documented)
 *
 * A local fake backend serves deterministic schema-valid responses for all
 * tiers (the REAL backend is covered by tests/integration.live.test.js).
 *
 * Usage:  npm run test:e2e        (requires Chrome; CHROME_PATH to override)
 * Not part of `npm test`.
 */

import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const FAKE_PORT = 18199;
const PAGE_PORT = 18190;
const TEST_PAGE = `http://127.0.0.1:${PAGE_PORT}/`;

// One origin per destination tier so every link is cross-origin AND resolvable.
const DEST = {
  low: 18201,
  low2: 18202,
  medium: 18203,
  medium2: 18204,
  evil: 18205,
  garbage: 18206,
};
const destUrl = (tier) => `http://localhost:${DEST[tier]}/${tier}`;

const CHROME_CANDIDATES = [
  process.env.CHROME_PATH,
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
  join(process.env.LOCALAPPDATA || "", "Google\\Chrome\\Application\\chrome.exe"),
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
].filter(Boolean);

const CHROME = CHROME_CANDIDATES.find((p) => existsSync(p));
if (!CHROME) {
  console.error("Chrome not found. Set CHROME_PATH to a Chrome binary.");
  process.exit(2);
}

// ---------------------------------------------------------------------------
// Fake backend (schema-valid, deterministic, CORS-open: the extension reaches
// it WITHOUT a host permission, exercising the normal-CORS path).
// ---------------------------------------------------------------------------

const backendState = { calls: [] };

function tierOfDest(dest) {
  for (const [tier, port] of Object.entries(DEST)) {
    if (dest.includes(`:${port}/`)) return tier;
  }
  return "benign";
}

function analyzeResponse(dest) {
  const tier = tierOfDest(dest);
  const base = {
    url: dest,
    reputation: {
      provider: "fake_backend",
      status: "no_known_threat",
      matches: [],
      error_reason: null,
    },
  };

  if (tier === "evil") {
    return {
      ...base,
      risk_level: "high",
      verdict: "confirmed_malicious",
      score: 75,
      reputation_status: "threat_detected",
      advice: "Google Safe Browsing confirms this URL matches known threat list(s): MALWARE. Do not visit.",
      findings: [
        {
          engine: "linkshield_rule_engine",
          rule_id: "FAKE_001",
          title: "Known malware host",
          description: "Test fixture.",
          severity: "high",
          confidence: "high",
        },
      ],
      reputation: {
        provider: "fake_backend",
        status: "threat_detected",
        matches: [{ threat_type: "MALWARE" }],
        error_reason: null,
      },
    };
  }

  if (tier === "garbage") return "GARBAGE-NOT-SCHEMA";

  if (tier === "medium" || tier === "medium2") {
    return {
      ...base,
      risk_level: "medium",
      verdict: "suspicious",
      score: 50,
      reputation_status: "no_known_threat",
      advice: "Detection engine(s) flagged: Suspicious redirect parameter.",
      findings: [
        {
          engine: "linkshield_rule_engine",
          rule_id: "FAKE_002",
          title: "Suspicious redirect parameter",
          description: "Points at an off-site target.",
          severity: "medium",
          confidence: "high",
        },
      ],
    };
  }

  // Benign: exactly what the real backend emits for a clean lookup.
  return {
    ...base,
    risk_level: "low",
    verdict: "unknown",
    score: 0,
    reputation_status: "no_known_threat",
    advice: "No known threats found; safety is not guaranteed.",
    findings: [],
  };
}

const fakeBackend = createServer((req, res) => {
  const cors = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "content-type",
  };
  if (req.method === "OPTIONS") {
    res.writeHead(204, cors);
    res.end();
    return;
  }
  if (req.url === "/api/analyze" && req.method === "POST") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      let dest = "";
      try {
        dest = JSON.parse(body).url;
      } catch {
        /* ignore */
      }
      backendState.calls.push(dest);
      const payload = analyzeResponse(dest);
      res.writeHead(200, { "Content-Type": "application/json", ...cors });
      res.end(typeof payload === "string" ? JSON.stringify({ oops: payload }) : JSON.stringify(payload));
    });
    return;
  }
  res.writeHead(404, cors);
  res.end();
});

// Test page with one link per scenario (each cross-origin to the page).
const pageHtml = `<!DOCTYPE html><html><head><title>URL Lens E2E</title></head><body>
  <h1>E2E test page</h1>
  <nav>
    <a id="low" href="${destUrl("low")}">low</a>
    <a id="low2" href="${destUrl("low2")}">low2</a>
    <a id="medium" href="${destUrl("medium")}">medium</a>
    <a id="medium2" href="${destUrl("medium2")}">medium2</a>
    <a id="evil" href="${destUrl("evil")}">evil</a>
    <a id="garbage" href="${destUrl("garbage")}">garbage</a>
    <a id="same" href="http://127.0.0.1:${PAGE_PORT}/other">same-origin</a>
  </nav>
</body></html>`;

const pageServer = createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(pageHtml);
});

// Destination servers — pages actually load so navigation URLs are stable.
const destServers = [];
for (const tier of Object.keys(DEST)) {
  const srv = createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(`<!DOCTYPE html><html><body><h1>destination ${tier}</h1></body></html>`);
  });
  destServers.push({ tier, srv });
}

// ---------------------------------------------------------------------------
// CDP over --remote-debugging-pipe (NUL-terminated; Chrome reads fd 3,
// writes fd 4).
// ---------------------------------------------------------------------------

function launchChrome() {
  const profile = mkdtempSync(join(tmpdir(), "linkshield-e2e-"));
  const child = spawn(
    CHROME,
    [
      "--headless",
      "--remote-debugging-pipe",
      "--enable-unsafe-extension-debugging",
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-gpu",
      `--user-data-dir=${profile}`,
      "--window-size=1280,900",
      "about:blank",
    ],
    { stdio: ["ignore", "pipe", "pipe", "pipe", "pipe"] }
  );

  const toChrome = child.stdio[3];
  const fromChrome = child.stdio[4];
  let buffer = "";
  let nextId = 1;
  const pending = new Map();

  fromChrome.on("data", (chunk) => {
    buffer += chunk;
    let end;
    while ((end = buffer.indexOf("\0")) !== -1) {
      const raw = buffer.slice(0, end);
      buffer = buffer.slice(end + 1);
      if (!raw) continue;
      let msg;
      try {
        msg = JSON.parse(raw);
      } catch {
        continue;
      }
      if (msg.id && pending.has(msg.id)) {
        const { resolve: res, reject: rej } = pending.get(msg.id);
        pending.delete(msg.id);
        if (msg.error) rej(new Error(`${msg.error.message || ""} ${JSON.stringify(msg.error.data || "")}`));
        else res(msg.result);
      }
    }
  });

  const send = (method, params = {}, sessionId) =>
    new Promise((resolveP, reject) => {
      const id = nextId++;
      const payload = { id, method, params };
      if (sessionId) payload.sessionId = sessionId;
      pending.set(id, { resolve: resolveP, reject });
      toChrome.write(JSON.stringify(payload) + "\0");
      setTimeout(() => {
        if (pending.delete(id)) reject(new Error(`CDP timeout: ${method}`));
      }, 20000);
    });

  child.on("exit", (code) => {
    for (const { reject } of pending.values()) reject(new Error(`Chrome exited (${code})`));
    pending.clear();
  });

  return {
    send,
    close() {
      try {
        child.kill();
      } catch {
        /* already gone */
      }
      try {
        rmSync(profile, { recursive: true, force: true });
      } catch {
        /* best effort */
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const results = [];
function report(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "✅" : "❌"} ${name}${detail ? ` — ${detail}` : ""}`);
}

async function evaluate(session, expression) {
  const res = await chrome.send(
    "Runtime.evaluate",
    { expression, returnByValue: true, awaitPromise: true },
    session
  );
  if (res.exceptionDetails) {
    throw new Error(
      `evaluate failed: ${res.exceptionDetails.text} ${JSON.stringify(res.exceptionDetails.exception || {})}`
    );
  }
  return res.result ? res.result.value : undefined;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitFor(session, expression, predicate, label, timeoutMs = 12000) {
  const start = Date.now();
  let last;
  while (Date.now() - start < timeoutMs) {
    try {
      last = await evaluate(session, expression);
      if (predicate(last)) return last;
    } catch {
      /* context may be mid-navigation */
    }
    await sleep(250);
  }
  throw new Error(`timeout waiting for ${label} (last value: ${JSON.stringify(last)})`);
}

async function waitForTestPage(session) {
  await waitFor(session, "location.href", (v) => v === TEST_PAGE, `back to ${TEST_PAGE}`);
  await waitFor(session, "document.readyState", (v) => v === "complete", "page ready");
}

async function resetToTestPage(session) {
  await chrome.send("Page.navigate", { url: TEST_PAGE }, session).catch(() => {});
  await waitForTestPage(session).catch(() => {});
}

function callsFor(tier) {
  return backendState.calls.filter((u) => u.includes(`:${DEST[tier]}/`)).length;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

let chrome = null;
let exitCode = 1;

async function main() {
  await new Promise((r) => fakeBackend.listen(FAKE_PORT, "127.0.0.1", r));
  await new Promise((r) => pageServer.listen(PAGE_PORT, "127.0.0.1", r));
  for (const { tier, srv } of destServers) {
    await new Promise((r) => srv.listen(DEST[tier], "127.0.0.1", r));
  }
  console.log(`fake backend :${FAKE_PORT}, test page :${PAGE_PORT}, destinations :${Object.values(DEST).join(":,")}`);

  chrome = launchChrome();

  // 1. Load the unpacked extension (supported Chrome 137+ path).
  const loaded = await chrome.send("Extensions.loadUnpacked", { path: ROOT });
  const extId = loaded.id;
  if (!extId) throw new Error(`loadUnpacked returned no id: ${JSON.stringify(loaded)}`);
  console.log(`extension loaded: ${extId}`);

  // 2. Attach the background SW and configure the backend BEFORE first scan.
  let swTargetId = null;
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline && !swTargetId) {
    const { targetInfos } = await chrome.send("Target.getTargets");
    const sw = targetInfos.find(
      (t) => t.type === "service_worker" && t.url.startsWith(`chrome-extension://${extId}/`)
    );
    if (sw) swTargetId = sw.targetId;
    else await sleep(300);
  }
  if (!swTargetId) throw new Error("background service worker target never appeared");
  const swAttached = await chrome.send("Target.attachToTarget", { targetId: swTargetId, flatten: true });
  await evaluate(
    swAttached.sessionId,
    `chrome.storage.sync.set({ settings: { backendUrl: "http://127.0.0.1:${FAKE_PORT}", timeoutMs: 8000, protectMode: "cross-origin" } })`
  );
  console.log("service worker attached; backend pointed at fake server");

  // 3. Open the test page.
  const { targetId: pageTargetId } = await chrome.send("Target.createTarget", { url: "about:blank" });
  const attached = await chrome.send("Target.attachToTarget", { targetId: pageTargetId, flatten: true });
  const page = attached.sessionId;
  await chrome.send("Page.enable", {}, page);
  await chrome.send("Runtime.enable", {}, page);
  await chrome.send("Page.navigate", { url: TEST_PAGE }, page);
  await waitFor(page, "document.readyState", (v) => v === "complete", "test page load");

  // --- Scenario 1: low-score link allows direct navigation -----------------
  try {
    await evaluate(page, `document.getElementById("low").click()`);
    await waitFor(page, "location.href", (v) => v === destUrl("low"), "low navigation");
    report(
      "low-score link navigates directly after one scan",
      callsFor("low") === 1,
      `${callsFor("low")} backend call(s)`
    );
    await evaluate(page, "history.back()");
    await waitForTestPage(page);
  } catch (err) {
    report("low-score link navigates directly after one scan", false, err.message);
    await resetToTestPage(page);
  }

  // --- Scenario 2: non-protected link is never held for analysis -----------
  try {
    const before = backendState.calls.length;
    await evaluate(page, `document.getElementById("same").click()`);
    await waitFor(page, "location.href", (v) => String(v).includes(`:${PAGE_PORT}/other`), "same-origin navigation");
    await sleep(600);
    const after = backendState.calls.length;
    const stillThere = await evaluate(page, "location.href");
    report(
      "non-protected link navigates with no interstitial",
      String(stillThere).includes(`:${PAGE_PORT}/other`),
      `observer scans (best-effort): ${after - before} call(s) for this URL`
    );
    await evaluate(page, "history.back()");
    await waitForTestPage(page);
  } catch (err) {
    report("non-protected link navigates with no interstitial", false, err.message);
    await resetToTestPage(page);
  }

  // --- Scenario 3: medium link → interstitial, Continue, Back --------------
  try {
    await evaluate(page, `document.getElementById("medium").click()`);
    await waitFor(page, "location.href", (v) => String(v).includes("warning.html?case="), "interstitial (medium)");
    const info = JSON.parse(
      await evaluate(
        page,
        `JSON.stringify({
          hostname: document.getElementById("hostname").textContent,
          urlText: document.getElementById("url").textContent,
          hasContinue: Boolean(document.getElementById("btn-continue")),
          continueLabel: document.getElementById("btn-continue")?.textContent || null,
          backLabel: document.getElementById("btn-back")?.textContent || null,
          bannerShown: !document.getElementById("unverified-banner").hidden,
          reasons: document.getElementById("reasons").children.length,
          findings: document.getElementById("findings").children.length,
          body: document.body.innerText
        })`
      )
    );
    const okInfo =
      info.hostname === "localhost" &&
      info.urlText === destUrl("medium") &&
      info.hasContinue &&
      info.continueLabel === "Continue Anyway" &&
      info.backLabel === "Go Back" &&
      info.bannerShown &&
      info.reasons > 0 &&
      info.findings > 0 &&
      info.body.includes("50");
    report(
      "medium interstitial renders (hostname, score, reasons, Continue+Back)",
      okInfo,
      JSON.stringify(info).slice(0, 240)
    );

    await evaluate(page, `document.getElementById("btn-continue").click()`);
    await waitFor(page, "location.href", (v) => v === destUrl("medium"), "Continue navigation");
    await evaluate(page, "history.back()");
    await waitForTestPage(page);
    report("Continue Anyway navigates; Back returns to the source page", true);
  } catch (err) {
    report("medium interstitial + Continue/Back", false, err.message);
    await resetToTestPage(page);
  }

  // --- Scenario 4: malicious link → block tier, NO Continue ----------------
  try {
    await evaluate(page, `document.getElementById("evil").click()`);
    await waitFor(page, "location.href", (v) => String(v).includes("warning.html?case="), "interstitial (evil)");
    const info = JSON.parse(
      await evaluate(
        page,
        `JSON.stringify({
          hasContinue: Boolean(document.getElementById("btn-continue")),
          anyContinueText: document.body.innerText.includes("Continue Anyway"),
          backLabel: document.getElementById("btn-back")?.textContent || null,
          hostname: document.getElementById("hostname").textContent,
          urlText: document.getElementById("url").textContent,
          body: document.body.innerText
        })`
      )
    );
    const okInfo =
      info.hasContinue === false &&
      info.anyContinueText === false &&
      info.backLabel === "Go Back to Safety" &&
      info.hostname === "localhost" &&
      info.urlText === destUrl("evil") &&
      info.body.includes("MALWARE");
    report(
      "block interstitial has NO bypass (Go Back to Safety only)",
      okInfo,
      JSON.stringify(info).slice(0, 240)
    );

    // Forged message from the page must also be refused (defense in depth).
    const forged = await evaluate(
      page,
      `chrome.runtime.sendMessage({ type: "warning:continue", caseId: new URLSearchParams(location.search).get("case") }).then(r => JSON.stringify(r))`
    );
    report("forged warning:continue refused for block tier", forged.includes('"ok":false'), forged);

    await evaluate(page, `document.getElementById("btn-back").click()`);
    await waitForTestPage(page);
    report("Go Back to Safety returns to the source page", true);
  } catch (err) {
    report("block interstitial / back", false, err.message);
    await resetToTestPage(page);
  }

  // --- Scenario 5: rapid double click → ONE backend call -------------------
  try {
    const before = callsFor("medium2");
    await evaluate(
      page,
      `document.getElementById("medium2").click(); document.getElementById("medium2").click();`
    );
    await waitFor(page, "location.href", (v) => String(v).includes("warning.html?case="), "interstitial (medium2)");
    await sleep(700);
    const delta = callsFor("medium2") - before;
    report("rapid repeated clicks share one backend scan", delta === 1, `${delta} call(s)`);
    await evaluate(page, `document.getElementById("btn-back").click()`);
    await waitForTestPage(page);
  } catch (err) {
    report("rapid repeated clicks share one backend scan", false, err.message);
    await resetToTestPage(page);
  }

  // --- Scenario 6: malformed backend response → fail-open, unverified ------
  try {
    await evaluate(page, `document.getElementById("garbage").click()`);
    await waitFor(page, "location.href", (v) => v === destUrl("garbage"), "fail-open (malformed)");
    report(
      "malformed response → navigation fails open (documented policy)",
      callsFor("garbage") === 1,
      `${callsFor("garbage")} backend call(s)`
    );
    await evaluate(page, "history.back()");
    await waitForTestPage(page);
  } catch (err) {
    report("malformed response → navigation fails open", false, err.message);
    await resetToTestPage(page);
  }

  // --- Scenario 7: backend down → fail-open navigation ---------------------
  try {
    await new Promise((r) => {
      try {
        if (fakeBackend.closeAllConnections) fakeBackend.closeAllConnections();
      } catch {
        /* best effort */
      }
      fakeBackend.close(() => r());
      setTimeout(r, 1000); // never hang on keep-alive sockets
    });
    await sleep(300);
    await evaluate(page, `document.getElementById("low2").click()`);
    await waitFor(page, "location.href", (v) => v === destUrl("low2"), "fail-open (backend down)");
    report("backend unavailable → navigation fails open (documented policy)", true);
  } catch (err) {
    report("backend unavailable → navigation fails open", false, err.message);
  }

  const failed = results.filter((r) => !r.ok);
  exitCode = failed.length === 0 ? 0 : 1;
  console.log(`\nE2E result: ${results.length - failed.length}/${results.length} scenarios passed`);
}

main()
  .catch((err) => {
    console.error("E2E fatal error:", err);
    exitCode = 1;
  })
  .finally(() => {
    if (chrome) chrome.close();
    try {
      fakeBackend.close();
    } catch {
      /* already closed */
    }
    try {
      pageServer.close();
    } catch {
      /* best effort */
    }
    for (const { srv } of destServers) {
      try {
        srv.close();
      } catch {
        /* best effort */
      }
    }
    setTimeout(() => process.exit(exitCode), 500);
  });
