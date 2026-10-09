/**
 * Shared test doubles: fake chrome.storage / tabs / windows / action, a
 * controllable fetch stub, and fixtures matching the backend's real
 * AnalyzeResponse schema (see backend/app/models.py).
 */

export const BACKEND_BASE = "http://127.0.0.1:8000";
export const ANALYZE_ENDPOINT = `${BACKEND_BASE}/api/analyze`;

/** A valid, benign-but-unverified response as the real backend emits it. */
export function backendResponse(overrides = {}) {
  return {
    url: "https://example.com/path",
    risk_level: "low",
    verdict: "unknown",
    score: 0,
    findings: [],
    reputation_status: "no_known_threat",
    advice: "No known threats found; safety is not guaranteed.",
    reputation: {
      provider: "google_safe_browsing",
      status: "no_known_threat",
      matches: [],
      error_reason: null,
    },
    ...overrides,
  };
}

export function finding(overrides = {}) {
  return {
    engine: "linkshield_rule_engine",
    rule_id: "RULE_001",
    title: "Lookalike domain",
    description: "Host resembles a well-known brand domain.",
    severity: "medium",
    confidence: "high",
    ...overrides,
  };
}

/** In-memory stand-in for chrome.storage.session / chrome.storage.sync. */
export function makeStorage(initial = {}) {
  const data = { ...initial };
  return {
    data,
    async get(key) {
      return data[key];
    },
    async set(key, value) {
      data[key] = value;
    },
  };
}

/**
 * fetch stub.
 * handler(url, init) may return a Response-like object
 *   ({ status, body }) or a promise resolving to one.
 */
export function makeFetch(handler) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    const result = await handler(url, init);
    const status = result.status ?? 200;
    const body = result.body;
    return {
      status,
      ok: status >= 200 && status < 300,
      async json() {
        if (body === undefined) throw new SyntaxError("Unexpected end of JSON input");
        if (typeof body === "string") return JSON.parse(body);
        return body;
      },
    };
  };
  fetchImpl.calls = calls;
  return fetchImpl;
}

/** fetch stub that never resolves until its abort signal fires (timeouts). */
export function hangingFetch() {
  const calls = [];
  const fetchImpl = (url, init) => {
    calls.push({ url, init });
    return new Promise((_resolve, reject) => {
      init.signal.addEventListener("abort", () => {
        const err = new Error("The operation was aborted");
        err.name = "AbortError";
        reject(err);
      });
    });
  };
  fetchImpl.calls = calls;
  return fetchImpl;
}

export function makeTabs() {
  const updates = [];
  const creates = [];
  return {
    updates,
    creates,
    async update(tabId, props) {
      updates.push({ tabId, ...props });
    },
    async create(props) {
      creates.push(props);
      return { id: 999, ...props };
    },
  };
}

export function makeWindows() {
  const creates = [];
  return {
    creates,
    async create(props) {
      creates.push(props);
      return { id: 1000 };
    },
  };
}

export function makeAction() {
  const badges = [];
  return {
    badges,
    async setBadge({ tabId, text, color }) {
      badges.push({ tabId, text, color });
    },
  };
}

/** Controllable clock. */
export function makeClock(start = 1_000_000) {
  let t = start;
  return {
    now: () => t,
    advance(ms) {
      t += ms;
    },
  };
}

export function makeIdGen(prefix = "case") {
  let n = 0;
  return () => `${prefix}-${++n}`;
}

/**
 * Assemble a full controller dep set with fakes.
 * overrides: { fetchImpl, now, ... }
 */
export function makeDeps(overrides = {}) {
  const clock = overrides.clock || makeClock();
  return {
    fetchImpl: overrides.fetchImpl || makeFetch(() => ({ status: 200, body: backendResponse() })),
    extensionBase: "chrome-extension://test-id/",
    session: overrides.session || makeStorage(),
    sync: overrides.sync || makeStorage(),
    tabs: overrides.tabs || makeTabs(),
    windows: overrides.windows || makeWindows(),
    action: overrides.action || makeAction(),
    now: overrides.now || clock.now,
    clock,
    randomId: overrides.randomId || makeIdGen(),
    log: () => {},
  };
}

/** The chrome.storage.session key names used by the controller. */
export const SESSION_KEYS = ["cache", "approvals", "cases", "lastScan"];
