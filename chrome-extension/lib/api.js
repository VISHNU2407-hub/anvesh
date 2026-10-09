/**
 * Thin client for `POST {backend}/api/analyze`.
 *
 * SAFETY INVARIANT (asserted by tests): this module only ever fetches the
 * configured backend endpoint. The destination URL being analyzed is sent as
 * a JSON string in the request body — the extension NEVER fetches, opens, or
 * visits the suspicious URL itself.
 *
 * Pure module: `fetchImpl` and `now` are injected for tests.
 */

import { analyzeEndpoint, isHttpUrl, MAX_URL_LENGTH } from "./util.js";
import { validateAnalysis } from "./policy.js";

/**
 * Perform one analysis request.
 *
 * @param {object} opts
 * @param {typeof fetch} opts.fetchImpl
 * @param {string} opts.baseUrl        Backend base URL, e.g. http://127.0.0.1:8000
 * @param {string} opts.url            Destination URL to analyze (body only).
 * @param {number} [opts.timeoutMs]
 * @returns {Promise<{ok: true, data: object} | {ok: false, error: string}>}
 */
export async function analyzeUrl({ fetchImpl, baseUrl, url, timeoutMs = 8000 }) {
  if (!isHttpUrl(url) || url.length > MAX_URL_LENGTH) {
    return { ok: false, error: "invalid_url" };
  }

  let endpoint;
  try {
    endpoint = analyzeEndpoint(baseUrl);
    const parsed = new URL(endpoint);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return { ok: false, error: "network" };
    }
  } catch {
    return { ok: false, error: "network" };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let response;
  try {
    response = await fetchImpl(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      // The destination URL goes in the BODY — never in the request URL.
      body: JSON.stringify({ url }),
      signal: controller.signal,
      cache: "no-store",
      redirect: "error", // never follow a redirect into the analyzed site
    });
  } catch (err) {
    clearTimeout(timer);
    if (err && (err.name === "AbortError" || err.code === 20)) {
      return { ok: false, error: "timeout" };
    }
    return { ok: false, error: "network" };
  }
  clearTimeout(timer);

  if (response.status === 400) return { ok: false, error: "bad_request" };
  if (response.status >= 500) return { ok: false, error: "server_error" };
  if (!response.ok) return { ok: false, error: "network" };

  let body;
  try {
    body = await response.json();
  } catch {
    return { ok: false, error: "invalid_json" };
  }

  const validated = validateAnalysis(body);
  if (!validated.ok) return { ok: false, error: "invalid_response" };

  return { ok: true, data: validated.value };
}
