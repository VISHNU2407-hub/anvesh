/**
 * Background orchestration for LinkShield AI.
 *
 * Pure, dependency-injected core so the Node test suite can drive the entire
 * flow (clicks, redirects, approvals, warnings, failures) with fakes.
 *
 * Responsibilities:
 *   - Analyze destination URLs via the backend (with cache + in-flight dedupe
 *     so repeated clicks and redirect chains never re-hit the API needlessly).
 *   - Apply the risk-tier policy (see lib/policy.js).
 *   - Navigate the tab after an allowed click, or swap it to the local
 *     warning interstitial for warn/block tiers.
 *   - Best-effort protection for navigations the content script cannot
 *     intercept (address bar, server-side redirects) via webNavigation —
 *     documented as racing the page load, NOT pre-navigation blocking.
 *   - Session-scoped approvals so "Continue Anyway" survives service-worker
 *     restarts and can never ping-pong with the interceptor.
 *
 * Deps injected by background/service_worker.js (real Chrome APIs) or tests:
 *   fetchImpl, now, randomId, extensionBase,
 *   session  — { get(key), set(key, value) }   (chrome.storage.session)
 *   sync     — { get(key), set(key, value) }   (chrome.storage.sync)
 *   tabs     — { update(tabId, props), create(props) }
 *   windows  — { create(props) }
 *   action   — { setBadge(props), clearBadge(tabId) }
 *   log      — optional logger
 */

import { analyzeUrl } from "./api.js";
import {
  TIER,
  decide,
  errorDecision,
} from "./policy.js";
import { isHttpUrl, normalizeForCache } from "./util.js";

export const DEFAULT_SETTINGS = Object.freeze({
  backendUrl: "http://127.0.0.1:8000",
  timeoutMs: 8000,
  protectMode: "cross-origin", // "cross-origin" | "all"
});

const CACHE_TTL_MS = 5 * 60 * 1000;
const CACHE_MAX = 120;
const APPROVAL_TTL_MS = 30 * 60 * 1000;
const APPROVAL_MAX = 200;
const CASE_TTL_MS = 60 * 60 * 1000;
const CASE_MAX = 20;
const LAST_SCAN_KEY = "lastScan";

function newSettings(raw) {
  const s = { ...DEFAULT_SETTINGS, ...(raw && typeof raw === "object" ? raw : {}) };
  try {
    const u = new URL(String(s.backendUrl));
    if (u.protocol !== "http:" && u.protocol !== "https:") {
      s.backendUrl = DEFAULT_SETTINGS.backendUrl;
    } else {
      s.backendUrl = String(s.backendUrl).replace(/\/+$/, "");
    }
  } catch {
    s.backendUrl = DEFAULT_SETTINGS.backendUrl;
  }
  const t = Number(s.timeoutMs);
  s.timeoutMs = Number.isFinite(t) ? Math.min(Math.max(Math.round(t), 1000), 30000) : DEFAULT_SETTINGS.timeoutMs;
  s.protectMode = s.protectMode === "all" ? "all" : "cross-origin";
  return s;
}

export class LinkShieldController {
  constructor(deps) {
    this.deps = deps;
    this.inflight = new Map(); // cacheKey -> Promise<record>
    this.pendingNav = new Map(); // tabId -> url (latest observed navigation)
    this.cacheWriteChain = Promise.resolve();
    this.settingsPromise = null;
  }

  log(...args) {
    try {
      (this.deps.log || (() => {}))(...args);
    } catch {
      /* logging must never break protection */
    }
  }

  now() {
    return this.deps.now ? this.deps.now() : Date.now();
  }

  warningUrl(caseId) {
    return `${this.deps.extensionBase}warning/warning.html?case=${encodeURIComponent(caseId)}`;
  }

  // -------------------------------------------------------------------------
  // Settings
  // -------------------------------------------------------------------------

  async getSettings({ fresh = false } = {}) {
    if (fresh || !this.settingsPromise) {
      this.settingsPromise = (async () => {
        const raw = await this.deps.sync.get("settings");
        return newSettings(raw);
      })();
    }
    return this.settingsPromise;
  }

  async setSettings(partial) {
    const current = await this.getSettings({ fresh: true });
    const next = newSettings({ ...current, ...(partial || {}) });
    await this.deps.sync.set("settings", next);
    this.settingsPromise = Promise.resolve(next);
    // Backend changed → cached results were produced by a different config.
    await this.clearCaches();
    return next;
  }

  // -------------------------------------------------------------------------
  // Cache / approvals / cases (persisted in chrome.storage.session so an MV3
  // service-worker restart cannot cause re-scan storms or approval loss)
  // -------------------------------------------------------------------------

  async clearCaches() {
    this.inflight.clear();
    await this.deps.session.set("cache", {});
  }

  async cacheGet(key) {
    const cache = (await this.deps.session.get("cache")) || {};
    const entry = cache[key];
    if (!entry) return null;
    if (this.now() - entry.ts > CACHE_TTL_MS) return null;
    return entry.record;
  }

  async cachePut(key, record) {
    // Serialize read-modify-write to avoid losing parallel entries.
    this.cacheWriteChain = this.cacheWriteChain.then(async () => {
      try {
        const cache = (await this.deps.session.get("cache")) || {};
        const pruned = {};
        const entries = Object.entries(cache)
          .filter(([, v]) => this.now() - v.ts <= CACHE_TTL_MS)
          .sort((a, b) => b[1].ts - a[1].ts)
          .slice(0, CACHE_MAX - 1);
        for (const [k, v] of entries) pruned[k] = v;
        pruned[key] = { ts: this.now(), record };
        await this.deps.session.set("cache", pruned);
      } catch (err) {
        this.log("cachePut failed", err);
      }
    });
    await this.cacheWriteChain;
  }

  async isApproved(key) {
    const approvals = (await this.deps.session.get("approvals")) || {};
    const ts = approvals[key];
    if (!ts) return false;
    if (this.now() - ts > APPROVAL_TTL_MS) return false;
    return true;
  }

  async approve(key) {
    const approvals = (await this.deps.session.get("approvals")) || {};
    approvals[key] = this.now();
    const pruned = {};
    const entries = Object.entries(approvals)
      .filter(([, ts]) => this.now() - ts <= APPROVAL_TTL_MS)
      .sort((a, b) => b[1] - a[1])
      .slice(0, APPROVAL_MAX);
    for (const [k, ts] of entries) pruned[k] = ts;
    await this.deps.session.set("approvals", pruned);
  }

  async storeCase(record) {
    const id = this.deps.randomId
      ? this.deps.randomId()
      : `case-${this.now()}-${Math.random().toString(36).slice(2, 10)}`;
    const cases = (await this.deps.session.get("cases")) || {};
    cases[id] = {
      id,
      url: record.url,
      tier: record.tier,
      score: record.analysis ? record.analysis.score : null,
      riskLevel: record.analysis ? record.analysis.risk_level : null,
      verdict: record.analysis ? record.analysis.verdict : null,
      reputationStatus: record.analysis ? record.analysis.reputation_status : null,
      findings: record.analysis ? record.analysis.findings : [],
      advice: record.analysis ? record.analysis.advice : "",
      reasons: record.reasons || [],
      unverified: Boolean(record.unverified),
      error: record.error || null,
      errorLabel: record.errorLabel || null,
      createdAt: this.now(),
    };
    const pruned = {};
    const entries = Object.entries(cases)
      .filter(([, c]) => this.now() - c.createdAt <= CASE_TTL_MS)
      .sort((a, b) => b[1].createdAt - a[1].createdAt)
      .slice(0, CASE_MAX);
    for (const [k, v] of entries) pruned[k] = v;
    pruned[id] = cases[id];
    await this.deps.session.set("cases", pruned);
    return id;
  }

  async getCase(id) {
    const cases = (await this.deps.session.get("cases")) || {};
    const c = cases[id];
    if (!c) return null;
    if (this.now() - c.createdAt > CASE_TTL_MS) return null;
    return c;
  }

  // -------------------------------------------------------------------------
  // Analysis (cache + in-flight dedupe)
  // -------------------------------------------------------------------------

  /**
   * Get the decision record for a URL, reusing an in-flight scan or a cached
   * result when possible. `fresh: true` forces a new backend call (popup
   * manual rescan) but still shares an already-running scan.
   *
   * Records: kind "analyzed" (backend responded) or "failed" (scan error —
   * fail-open + unverified, never "safe").
   */
  async getDecision(url, { fresh = false } = {}) {
    const key = normalizeForCache(url);
    if (!isHttpUrl(key)) return errorDecision(url, "invalid_url");

    // Check in-flight FIRST and synchronously: concurrent clicks on the same
    // URL must share one backend call (see the re-check below for the
    // post-await race).
    const running = this.inflight.get(key);
    if (running) return running;

    if (!fresh) {
      const cached = await this.cacheGet(key);
      if (cached) return cached;
      // Another caller may have started a scan while we awaited the cache.
      const raced = this.inflight.get(key);
      if (raced) return raced;
    }

    const promise = this.#scan(key)
      .catch((err) => {
        this.log("scan failed", err);
        return errorDecision(key, "network");
      })
      .then(async (record) => {
        // Cache failures too: a dead backend must not be hammered on every
        // click/redirect (short TTL is inherited from the cache entry).
        await this.cachePut(key, record);
        return record;
      })
      .finally(() => {
        this.inflight.delete(key);
      });

    this.inflight.set(key, promise);
    return promise;
  }

  async #scan(key) {
    const settings = await this.getSettings();
    const res = await analyzeUrl({
      fetchImpl: this.deps.fetchImpl,
      baseUrl: settings.backendUrl,
      url: key,
      timeoutMs: settings.timeoutMs,
    });

    if (!res.ok) {
      return errorDecision(key, res.error);
    }

    const d = decide(res.data);
    return {
      kind: "analyzed",
      url: key,
      tier: d.tier,
      error: null,
      errorLabel: null,
      reasons: d.reasons,
      unverified: d.unverified,
      verified: d.verified,
      analysis: res.data,
      ts: this.now(),
    };
  }

  // -------------------------------------------------------------------------
  // Badge
  // -------------------------------------------------------------------------

  async setBadge(tabId, record) {
    try {
      if (!this.deps.action) return;
      if (record.tier === TIER.WARN) {
        await this.deps.action.setBadge({ tabId, text: "!", color: "#f59e0b" });
      } else if (record.tier === TIER.BLOCK) {
        await this.deps.action.setBadge({ tabId, text: "✕", color: "#dc2626" });
      } else if (record.unverified || record.kind === "failed") {
        await this.deps.action.setBadge({ tabId, text: "?", color: "#64748b" });
      } else {
        await this.deps.action.setBadge({ tabId, text: "", color: "#64748b" });
      }
    } catch (err) {
      this.log("badge failed", err);
    }
  }

  // -------------------------------------------------------------------------
  // Navigation helpers
  // -------------------------------------------------------------------------

  /**
   * intent: { mode: "current" | "tab" | "window", active?: boolean }
   */
  async openTarget(tabId, url, intent) {
    const mode = intent && intent.mode ? intent.mode : "current";
    if (mode === "tab") {
      await this.deps.tabs.create({ url, active: intent && intent.active === false ? false : true });
    } else if (mode === "window") {
      await this.deps.windows.create({ url });
    } else if (tabId !== null && tabId !== undefined) {
      await this.deps.tabs.update(tabId, { url });
    } else {
      await this.deps.tabs.create({ url, active: true });
    }
  }

  /**
   * A click was intercepted by the content script: analyze, then navigate to
   * the destination (allow) or to the local warning page (warn/block).
   */
  async handleClick(tabId, url, intent) {
    const record = await this.getDecision(url);
    await this.setBadge(tabId, record);

    if (record.tier === TIER.ALLOW) {
      // Pre-approve so the onBeforeNavigate observer does not re-analyze the
      // navigation we just performed (prevents redundant scans + loops).
      await this.approve(normalizeForCache(record.url));
      await this.openTarget(tabId, record.url, intent);
      return { ok: true, action: "navigate", record };
    }

    const caseId = await this.storeCase(record);
    await this.openTarget(tabId, this.warningUrl(caseId), intent);
    return { ok: true, action: "warning", caseId, record };
  }

  /**
   * Best-effort observer for navigations the content script cannot stop:
   * address-bar entries, server-side redirects, drag-and-drop, link clicks
   * inside iframes, etc. MV3 cannot cancel these before they start loading,
   * so we analyze concurrently and swap the tab to the interstitial when the
   * result comes back — a documented race, not pre-navigation blocking.
   */
  async onBeforeNavigate(details) {
    if (!details || details.frameId !== 0) return;
    const url = details.url;
    this.pendingNav.set(details.tabId, url);
    if (!isHttpUrl(url)) return; // chrome://, extension pages, data:, ...

    try {
      const key = normalizeForCache(url);
      if (await this.isApproved(key)) return; // user-approved (Continue / allow path)

      const record = await this.getDecision(key);
      await this.setBadge(details.tabId, record);
      if (record.tier === TIER.ALLOW) return;

      // Stale-result guard: the tab has moved on since this navigation
      // started (redirect chain or user navigation) — do not yank it.
      if (this.pendingNav.get(details.tabId) !== url) return;

      const caseId = await this.storeCase(record);
      await this.deps.tabs.update(details.tabId, { url: this.warningUrl(caseId) });
    } catch (err) {
      // Fail open: never break navigation when the observer itself errors.
      this.log("onBeforeNavigate failed", err);
    }
  }

  onTabRemoved(tabId) {
    this.pendingNav.delete(tabId);
  }

  // -------------------------------------------------------------------------
  // Message router
  // -------------------------------------------------------------------------

  /**
   * @returns {Promise<object|undefined>} undefined = "not my message"
   *   (content scripts also listen on runtime.onMessage).
   */
  async handleMessage(msg, sender) {
    if (!msg || typeof msg.type !== "string") return undefined;

    switch (msg.type) {
      case "ls:analyze-click": {
        const tabId = sender && sender.tab ? sender.tab.id : null;
        const result = await this.handleClick(tabId, msg.url, msg.intent);
        return result;
      }

      case "ls:scan": {
        const record = await this.getDecision(msg.url, { fresh: Boolean(msg.fresh) });
        await this.deps.session.set(LAST_SCAN_KEY, record);
        if (sender && sender.tab) await this.setBadge(sender.tab.id, record);
        return { ok: true, record };
      }

      case "ls:last-scan": {
        const record = await this.deps.session.get(LAST_SCAN_KEY);
        return { ok: true, record: record || null };
      }

      case "ls:settings:get": {
        return { ok: true, settings: await this.getSettings() };
      }

      case "ls:settings:set": {
        const settings = await this.setSettings(msg.settings);
        return { ok: true, settings };
      }

      case "warning:continue": {
        const record = await this.getCase(msg.caseId);
        // Defense in depth: the Continue button only ever exists for the
        // medium tier, and the background refuses block-tier continuations
        // even if a page forges the message.
        if (!record || record.tier !== TIER.WARN) {
          return { ok: false, reason: "not-allowed" };
        }
        // Approve BEFORE the warning page navigates (via location.replace),
        // so the webNavigation observer does not re-analyze — and never
        // re-warns — the URL the user explicitly continued to.
        await this.approve(normalizeForCache(record.url));
        await this.setBadge(sender && sender.tab ? sender.tab.id : null, await this.getDecision(record.url));
        // The page performs the navigation itself (location.replace), which
        // keeps the interstitial out of the back history.
        return { ok: true, url: record.url };
      }

      case "warning:details": {
        const record = await this.getCase(msg.caseId);
        return { ok: Boolean(record), record: record || null };
      }

      default:
        return undefined;
    }
  }
}
