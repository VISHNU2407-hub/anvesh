/**
 * Popup controller.
 *
 * States handled explicitly:
 *   - loading            (scan in flight)
 *   - timeout            (backend did not answer in time)
 *   - backend-unavailable (network error / connection refused)
 *   - invalid-response   (malformed JSON or unexpected schema)
 *   - bad request / server error
 *   - result             (verdict, score, risk, findings, advice)
 *
 * The popup NEVER claims a URL is safe: unknown/unavailable results always
 * show the verification banner.
 */

const $ = (id) => document.getElementById(id);

const ERROR_TITLES = {
  timeout: "Scan timed out",
  network: "Backend unavailable",
  invalid_response: "Invalid response",
  invalid_json: "Invalid response",
  bad_request: "URL rejected by backend",
  server_error: "Backend error",
  invalid_url: "Invalid URL",
  aborted: "Scan aborted",
};

const VERDICT_LABELS = {
  confirmed_malicious: "Confirmed malicious",
  suspicious: "Suspicious",
  unknown: "Unverified",
  verified_safe: "Verified safe",
};

let pageUrl = null;
let busy = false;

function show(panelId) {
  for (const id of ["state-loading", "state-error", "state-result"]) {
    $(id).hidden = id !== panelId;
  }
}

function setBusy(value) {
  busy = value;
  $("btn-scan").disabled = value;
}

async function resolvePageUrl() {
  // 1) Ask the content script (works without the "tabs" permission).
  try {
    const info = await chrome.runtime.sendMessage({ type: "linkshield:page-info" });
    if (info && info.url) {
      pageUrl = info.url;
      $("page-url").textContent = info.url;
      return;
    }
  } catch (e) {
    /* no content script on this page — fall through */
  }

  // 2) Fallback: tab URL (available when host permissions cover the page).
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url && /^https?:/i.test(tab.url)) {
      pageUrl = tab.url;
      $("page-url").textContent = tab.url;
      return;
    }
  } catch (e) {
    /* ignore */
  }

  // 3) Extension/browser pages cannot be scanned.
  pageUrl = null;
  $("page-url").textContent = "This page can't be scanned.";
}

function renderError(record) {
  const title = ERROR_TITLES[record.error] || "Scan failed";
  $("error-title").textContent = title;
  $("error-detail").textContent = record.errorLabel || "Scan failed. URL not verified.";
  $("error-hint").textContent =
    record.error === "network"
      ? "Is the backend running? Check Settings (⚙)."
      : record.error === "timeout"
        ? "Too slow — raise the timeout in Settings (⚙)."
        : record.error === "invalid_response" || record.error === "invalid_json"
          ? "The backend sent an unexpected response."
          : "Check Settings (⚙).";
  show("state-error");
}

function renderResult(record) {
  const analysis = record.analysis;
  const verdict = analysis ? analysis.verdict : "unknown";
  const risk = analysis ? analysis.risk_level : "unknown";
  const score = analysis ? analysis.score : null;

  const chip = $("verdict-chip");
  chip.textContent = VERDICT_LABELS[verdict] || verdict;
  chip.className = `chip tier-${record.tier}`;

  const riskChip = $("risk-chip");
  riskChip.textContent =
    risk === "unknown" ? "Unknown risk" : `${risk.charAt(0).toUpperCase()}${risk.slice(1)} risk`;

  if (score === null) {
    document.querySelector(".score-block").hidden = true;
  } else {
    document.querySelector(".score-block").hidden = false;
    $("score-label").textContent = `Score ${score}/100`;
    const fill = $("score-fill");
    fill.style.width = `${score}%`;
    fill.className = `fill ${score > 65 ? "high" : score >= 30 ? "medium" : "low"}`;
  }

  $("result-url").textContent = record.url || "";

  // Verification banner — shown for unknown / unavailable / failed scans.
  const banner = $("unverified-banner");
  if (record.unverified) {
    banner.hidden = false;
    banner.textContent = "Not verified as safe — no known threats found isn't proof of safety.";
  } else {
    banner.hidden = true;
  }

  const reasons = record.reasons || [];
  $("reasons-block").hidden = reasons.length === 0;
  const reasonsList = $("reasons");
  reasonsList.textContent = "";
  for (const r of reasons) {
    const li = document.createElement("li");
    li.textContent = r;
    reasonsList.appendChild(li);
  }

  const findings = (analysis && analysis.findings) || [];
  $("findings-block").hidden = findings.length === 0;
  const findingsList = $("findings");
  findingsList.textContent = "";
  for (const f of findings) {
    const li = document.createElement("li");
    const title = document.createElement("strong");
    title.textContent = `${f.title} (${f.severity})`;
    li.appendChild(title);
    if (f.description) {
      const desc = document.createElement("span");
      desc.className = "finding-desc";
      desc.textContent = f.description;
      li.appendChild(desc);
    }
    findingsList.appendChild(li);
  }

  const advice = (analysis && analysis.advice) || "";
  $("advice-block").hidden = !advice;
  $("advice").textContent = advice;

  show("state-result");
}

async function scan(url, fresh) {
  if (busy || !url) return;
  setBusy(true);
  show("state-loading");
  try {
    const res = await chrome.runtime.sendMessage({
      type: "ls:scan",
      url,
      fresh: Boolean(fresh),
    });
    if (!res || !res.ok || !res.record) {
      renderError({
        kind: "failed",
        error: "network",
        errorLabel: "The extension could not reach its background worker.",
        unverified: true,
        reasons: [],
        analysis: null,
      });
      return;
    }
    const record = res.record;
    if (record.kind === "failed") {
      renderError(record);
    } else {
      renderResult(record);
    }
  } catch (err) {
    renderError({
      kind: "failed",
      error: "network",
      errorLabel: String(err && err.message ? err.message : err),
      unverified: true,
      reasons: [],
      analysis: null,
    });
  } finally {
    setBusy(false);
  }
}

async function restoreLastScan() {
  try {
    const res = await chrome.runtime.sendMessage({ type: "ls:last-scan" });
    if (res && res.ok && res.record && res.record.url === pageUrl) {
      if (res.record.kind === "failed") renderError(res.record);
      else renderResult(res.record);
      return true;
    }
  } catch (e) {
    /* ignore */
  }
  return false;
}

async function init() {
  $("btn-options").addEventListener("click", () => {
    void chrome.runtime.openOptionsPage();
  });
  $("btn-scan").addEventListener("click", () => scan(pageUrl, true));
  $("btn-rescan").addEventListener("click", () => scan(pageUrl, true));

  try {
    const res = await chrome.runtime.sendMessage({ type: "ls:settings:get" });
    if (res && res.ok) {
      $("backend-label").textContent = `Backend: ${res.settings.backendUrl}`;
    }
  } catch (e) {
    $("backend-label").textContent = "Backend: unreachable settings";
  }

  await resolvePageUrl();
  const restored = await restoreLastScan();
  if (!restored) show(null); // no panel — idle with the Scan button
  $("btn-rescan").hidden = !restored;
}

init();
