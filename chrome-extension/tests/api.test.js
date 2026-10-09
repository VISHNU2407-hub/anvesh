/**
 * API client behavior: endpoints, timeouts, failure classification,
 * malformed payloads — and the hard rule that the extension never fetches
 * the destination URL itself.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { analyzeUrl } from "../lib/api.js";
import {
  ANALYZE_ENDPOINT,
  BACKEND_BASE,
  backendResponse,
  finding,
  hangingFetch,
  makeFetch,
} from "./helpers.js";

test("posts only to the backend /api/analyze endpoint, never the destination", async () => {
  const dest = "https://super-suspicious.example/login?user=a";
  const fetchImpl = makeFetch(() => ({ status: 200, body: backendResponse({ url: dest }) }));

  const res = await analyzeUrl({ fetchImpl, baseUrl: BACKEND_BASE, url: dest });
  assert.equal(res.ok, true);

  assert.equal(fetchImpl.calls.length, 1);
  const call = fetchImpl.calls[0];
  // The destination appears ONLY in the request body.
  assert.equal(call.url, ANALYZE_ENDPOINT);
  assert.ok(!call.url.includes("super-suspicious.example"));
  assert.deepEqual(JSON.parse(call.init.body), { url: dest });
  assert.equal(call.init.method, "POST");
  assert.equal(call.init.headers["Content-Type"], "application/json");
  // Never follow redirects into the analyzed site.
  assert.equal(call.init.redirect, "error");
});

test("accepts a valid response", async () => {
  const fetchImpl = makeFetch(() => ({
    status: 200,
    body: backendResponse({
      score: 55,
      risk_level: "medium",
      verdict: "suspicious",
      findings: [finding()],
    }),
  }));
  const res = await analyzeUrl({ fetchImpl, baseUrl: BACKEND_BASE, url: "https://a.example/" });
  assert.equal(res.ok, true);
  assert.equal(res.data.score, 55);
  assert.equal(res.data.findings[0].title, "Lookalike domain");
});

test("timeout → error 'timeout'", async () => {
  const fetchImpl = hangingFetch();
  const res = await analyzeUrl({
    fetchImpl,
    baseUrl: BACKEND_BASE,
    url: "https://slow.example/",
    timeoutMs: 25,
  });
  assert.deepEqual(res, { ok: false, error: "timeout" });
  assert.equal(fetchImpl.calls.length, 1);
});

test("network failure (connection refused) → error 'network'", async () => {
  const fetchImpl = async () => {
    throw new TypeError("fetch failed");
  };
  const res = await analyzeUrl({ fetchImpl, baseUrl: BACKEND_BASE, url: "https://a.example/" });
  assert.deepEqual(res, { ok: false, error: "network" });
});

test("HTTP 400 → 'bad_request'; HTTP 500 → 'server_error'", async () => {
  const f400 = makeFetch(() => ({ status: 400, body: { detail: "Invalid URL" } }));
  const r400 = await analyzeUrl({ fetchImpl: f400, baseUrl: BACKEND_BASE, url: "https://a.example/" });
  assert.deepEqual(r400, { ok: false, error: "bad_request" });

  const f500 = makeFetch(() => ({ status: 500, body: { detail: "boom" } }));
  const r500 = await analyzeUrl({ fetchImpl: f500, baseUrl: BACKEND_BASE, url: "https://a.example/" });
  assert.deepEqual(r500, { ok: false, error: "server_error" });
});

test("non-JSON body → 'invalid_json'", async () => {
  const fetchImpl = makeFetch(() => ({
    status: 200,
    body: "<html>not json</html>",
  }));
  const res = await analyzeUrl({ fetchImpl, baseUrl: BACKEND_BASE, url: "https://a.example/" });
  assert.deepEqual(res, { ok: false, error: "invalid_json" });
});

test("JSON with wrong schema → 'invalid_response'", async () => {
  const cases = [
    { hello: "world" },
    backendResponse({ score: "banana" }),
    backendResponse({ risk_level: "apocalyptic" }),
    backendResponse({ findings: "nope" }),
    backendResponse({ verdict: "safe-ish" }),
  ];
  for (const body of cases) {
    const fetchImpl = makeFetch(() => ({ status: 200, body }));
    const res = await analyzeUrl({ fetchImpl, baseUrl: BACKEND_BASE, url: "https://a.example/" });
    assert.deepEqual(res, { ok: false, error: "invalid_response" }, JSON.stringify(body).slice(0, 60));
  }
});

test("invalid destination URL → 'invalid_url' without any network call", async () => {
  const fetchImpl = makeFetch(() => ({ status: 200, body: backendResponse() }));
  for (const bad of ["not-a-url", "ftp://x.example/", "javascript:alert(1)", ""]) {
    const res = await analyzeUrl({ fetchImpl, baseUrl: BACKEND_BASE, url: bad });
    assert.deepEqual(res, { ok: false, error: "invalid_url" }, bad);
  }
  assert.equal(fetchImpl.calls.length, 0);
});

test("backend base URL with trailing slash still hits /api/analyze", async () => {
  const fetchImpl = makeFetch(() => ({ status: 200, body: backendResponse() }));
  const res = await analyzeUrl({
    fetchImpl,
    baseUrl: "http://localhost:8000/",
    url: "https://a.example/",
  });
  assert.equal(res.ok, true);
  assert.equal(fetchImpl.calls[0].url, "http://localhost:8000/api/analyze");
});
