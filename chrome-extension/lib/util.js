/**
 * Shared URL / string helpers. Pure functions only — no Chrome APIs.
 */

export const MAX_URL_LENGTH = 2048; // mirrors the backend's AnalyzeRequest limit

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001F\u007F]/g;
// Non-global copy for .test() — a /g regex is stateful across calls.
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS_TEST = /[\u0000-\u001F\u007F]/;

/** True when `str` parses as an absolute http(s) URL with a host. */
export function isHttpUrl(str) {
  if (typeof str !== "string" || str.length === 0 || str.length > MAX_URL_LENGTH) {
    return false;
  }
  if (CONTROL_CHARS_TEST.test(str)) {
    return false;
  }
  let parsed;
  try {
    parsed = new URL(str);
  } catch {
    return false;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return false;
  }
  return Boolean(parsed.hostname);
}

/**
 * Cache/dedup key for a URL: trimmed, fragment removed.
 * Two URLs that differ only in `#fragment` are the same analysis target.
 */
export function normalizeForCache(url) {
  if (typeof url !== "string") return "";
  let trimmed = url.trim();
  if (trimmed.length > MAX_URL_LENGTH) return trimmed.slice(0, MAX_URL_LENGTH);
  const hashIndex = trimmed.indexOf("#");
  if (hashIndex !== -1) trimmed = trimmed.slice(0, hashIndex);
  return trimmed;
}

/** Hostname of a URL for display, or "" when unparsable. */
export function hostnameOf(url) {
  try {
    return new URL(url).hostname || "";
  } catch {
    return "";
  }
}

/** Origin of a URL ("https://host:port"), or "" when unparsable. */
export function originOf(url) {
  try {
    return new URL(url).origin;
  } catch {
    return "";
  }
}

/** True when both URLs are valid http(s) URLs on the same origin. */
export function isSameOrigin(a, b) {
  const oa = originOf(a);
  const ob = originOf(b);
  return Boolean(oa) && oa === ob;
}

/** True when both URLs resolve to the same document (ignoring #fragment). */
export function isSameDocument(a, b) {
  const na = normalizeForCache(a);
  const nb = normalizeForCache(b);
  if (!na || !nb) return false;
  if (na === nb) return true;
  // Treat a trailing "/" root and the bare origin as the same document too.
  try {
    const pa = new URL(na);
    const pb = new URL(nb);
    return (
      pa.origin === pb.origin &&
      pa.pathname.replace(/\/$/, "") === pb.pathname.replace(/\/$/, "") &&
      pa.search === pb.search
    );
  } catch {
    return false;
  }
}

/**
 * Produce a safe, bounded display string from untrusted URL data.
 * Strips control characters; the renderer must still use textContent.
 */
export function safeDisplayUrl(url, max = 200) {
  if (typeof url !== "string") return "";
  const cleaned = url.replace(CONTROL_CHARS, "").trim();
  if (cleaned.length <= max) return cleaned;
  return `${cleaned.slice(0, max - 1)}…`;
}

/** Escape a string for safe interpolation into plain text contexts. */
export function escapeText(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Join a backend base URL with the analyze path (no double slashes). */
export function analyzeEndpoint(baseUrl) {
  const base = String(baseUrl || "").replace(/\/+$/, "");
  return `${base}/api/analyze`;
}
