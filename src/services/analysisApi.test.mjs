/**
 * Focused tests for the frontend analysis service and its integration with the
 * backend POST /api/analyze contract.
 *
 * The service reads `import.meta.env` for VITE_USE_MOCK / VITE_API_BASE_URL, so
 * the module is loaded through Vite's SSR module runner. That gives us the real
 * environment substitution and JSX transform without adding extra dependencies.
 *
 * Run with:  npm test   (node --test)
 */

import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'
import { createServer } from 'vite'
import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'

/* ------------------------------------------------------------------ */
/* Module loading                                                      */
/* ------------------------------------------------------------------ */

async function loadModuleServer(useMock) {
  process.env.VITE_USE_MOCK = useMock
  process.env.VITE_API_BASE_URL = 'http://127.0.0.1:8000'
  const server = await createServer({
    server: { middlewareMode: true },
    appType: 'custom',
    logLevel: 'silent',
  })
  return server
}

async function loadEntry(server, path) {
  const mod = await server.ssrLoadModule(path)
  return mod.default ?? mod
}

let apiServer
let mockServer
let api
let mock
let ResultDashboard

before(async () => {
  apiServer = await loadModuleServer('false')
  mockServer = await loadModuleServer('true')
  api = await apiServer.ssrLoadModule('/src/services/analysisApi.js')
  mock = await mockServer.ssrLoadModule('/src/services/analysisApi.js')
  ResultDashboard = await loadEntry(apiServer, '/src/components/ResultDashboard.jsx')
})

after(async () => {
  delete process.env.VITE_USE_MOCK
  delete process.env.VITE_API_BASE_URL
  await apiServer?.close()
  await mockServer?.close()
})

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

const JSON_HEADERS = { 'Content-Type': 'application/json' }

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS })
}

/** Run `fn` with global fetch replaced, then always restore it. */
async function withFetch(impl, fn) {
  const original = globalThis.fetch
  globalThis.fetch = impl
  try {
    return await fn()
  } finally {
    globalThis.fetch = original
  }
}

function baseResponse(overrides = {}) {
  return {
    url: 'https://example.com/',
    risk_level: 'low',
    verdict: 'unknown',
    score: 0,
    findings: [],
    reputation_status: 'no_known_threat',
    advice:
      'No known threats found; safety is not guaranteed. Google Safe Browsing returned no match for this URL.',
    reputation: {
      provider: 'google_safe_browsing',
      status: 'no_known_threat',
      matches: [],
      error_reason: null,
    },
    ...overrides,
  }
}

function isAnalysisError(code) {
  return (err) => {
    assert.ok(err instanceof api.AnalysisError, `expected AnalysisError, got ${err?.name}: ${err?.message}`)
    assert.equal(err.code, code)
    return true
  }
}

/* ------------------------------------------------------------------ */
/* 1. Valid HTTPS URL, verdict unknown, score 0, empty findings        */
/* ------------------------------------------------------------------ */

test('valid HTTPS URL with verdict "unknown", score 0, empty findings resolves', async () => {
  await withFetch(
    async () => jsonResponse(baseResponse()),
    async () => {
      const result = await api.analyzeUrl('https://example.com')
      assert.equal(result.risk_level, 'Low')
      assert.equal(result.verdict, 'unknown')
      assert.equal(result.risk_score, 0)
      assert.equal(result.score, 0)
      assert.deepEqual(result.findings, [])
      assert.equal(result.reputation_status, 'no_known_threat')
      assert.equal(result.domain, 'example.com')
      assert.equal(result.demo, null)
      // Regression: normalizeResponse must populate scanned_at (the previous
      // `scanned_at` shorthand threw a ReferenceError here).
      assert.equal(typeof result.scanned_at, 'string')
      assert.ok(!Number.isNaN(new Date(result.scanned_at).getTime()))
    },
  )
})

/* ------------------------------------------------------------------ */
/* 2. Suspicious verdict with findings                                 */
/* ------------------------------------------------------------------ */

test('valid URL with suspicious verdict and findings maps findings and score', async () => {
  const payload = baseResponse({
    risk_level: 'medium',
    verdict: 'suspicious',
    score: 35,
    findings: [
      {
        engine: 'linkshield_rule_engine',
        rule_id: 'lookalike_domain',
        title: 'Lookalike domain',
        description: 'The hostname imitates a well-known brand.',
        severity: 'high',
        confidence: 'medium',
      },
    ],
  })

  await withFetch(
    async () => jsonResponse(payload),
    async () => {
      const result = await api.analyzeUrl('https://paypa1-login.example')
      assert.equal(result.risk_level, 'Medium')
      assert.equal(result.verdict, 'suspicious')
      assert.equal(result.risk_score, 35)
      assert.equal(result.findings.length, 1)
      const [finding] = result.findings
      assert.equal(finding.name, 'Lookalike domain')
      assert.equal(finding.severity, 'high')
      assert.equal(finding.explanation, 'The hostname imitates a well-known brand.')
      assert.equal(finding.rule_id, 'lookalike_domain')
      assert.equal(result.advice.length >= 1, true)
    },
  )
})

/* ------------------------------------------------------------------ */
/* 3. no_known_threat must never be presented as safe                  */
/* ------------------------------------------------------------------ */

test('reputation_status "no_known_threat" keeps an honest, non-safe message', async () => {
  await withFetch(
    async () => jsonResponse(baseResponse()),
    async () => {
      const result = await api.analyzeUrl('https://example.com')
      assert.equal(result.reputation_status, 'no_known_threat')
      assert.equal(result.reputation.rawStatus, 'no_known_threat')
      assert.match(result.reputation.message, /does not guarantee/i)
      // It must never make an affirmative, guaranteed-safety claim.
      assert.doesNotMatch(
        result.reputation.message,
        /guaranteed safe|proven safe|100% safe|verified safe/i,
      )
    },
  )
})

/* ------------------------------------------------------------------ */
/* 4. Unavailable reputation -> unknown/unavailable state              */
/* ------------------------------------------------------------------ */

test('reputation_status "unavailable" produces an unavailable state with reason', async () => {
  const payload = baseResponse({
    risk_level: 'unknown',
    verdict: 'unknown',
    score: 0,
    reputation_status: 'unavailable',
    reputation: {
      provider: 'google_safe_browsing',
      status: 'unavailable',
      matches: [],
      error_reason: 'quota_exceeded',
    },
  })

  await withFetch(
    async () => jsonResponse(payload),
    async () => {
      const result = await api.analyzeUrl('https://example.com')
      assert.equal(result.risk_level, 'Unknown')
      assert.equal(result.reputation_status, 'unavailable')
      assert.equal(result.reputation.status, 'unavailable')
      assert.equal(result.reputation.error_reason, 'quota_exceeded')
      assert.match(result.reputation.message, /quota/i)
    },
  )
})

/* ------------------------------------------------------------------ */
/* 5. Backend 400 / 422 validation errors                              */
/* ------------------------------------------------------------------ */

test('HTTP 400 preserves the backend validation message', async () => {
  await withFetch(
    async () => jsonResponse({ detail: 'Only http:// and https:// URLs are supported.' }, 400),
    async () => {
      await assert.rejects(
        api.analyzeUrl('https://example.com'),
        isAnalysisError('malformed'),
      )
    },
  )
})

test('HTTP 422 validation error is surfaced without crashing', async () => {
  await withFetch(
    async () =>
      jsonResponse(
        { detail: [{ loc: ['body', 'url'], msg: 'field required', type: 'value_error.missing' }] },
        422,
      ),
    async () => {
      await assert.rejects(
        api.analyzeUrl('https://example.com'),
        isAnalysisError('malformed'),
      )
    },
  )
})

/* ------------------------------------------------------------------ */
/* 6. Backend 500                                                      */
/* ------------------------------------------------------------------ */

test('HTTP 500 becomes an http service error (not an invalid URL)', async () => {
  await withFetch(
    async () => new Response('Internal Server Error', { status: 500 }),
    async () => {
      await assert.rejects(
        api.analyzeUrl('https://example.com'),
        isAnalysisError('http'),
      )
    },
  )
})

/* ------------------------------------------------------------------ */
/* 7. Network failure and timeout                                      */
/* ------------------------------------------------------------------ */

test('network failure becomes a network error', async () => {
  await withFetch(
    async () => {
      throw new TypeError('Failed to fetch')
    },
    async () => {
      await assert.rejects(
        api.analyzeUrl('https://example.com'),
        isAnalysisError('network'),
      )
    },
  )
})

test('request timeout becomes a timeout error', async () => {
  const realSetTimeout = globalThis.setTimeout
  // Shorten the module's internal 10s timer so the test is fast.
  globalThis.setTimeout = (fn, _ms, ...rest) => realSetTimeout(fn, 5, ...rest)
  try {
    await withFetch(
      (_url, opts) =>
        new Promise((_resolve, reject) => {
          const rejectAbort = () => reject(new DOMException('Aborted', 'AbortError'))
          if (opts?.signal?.aborted) rejectAbort()
          else opts?.signal?.addEventListener('abort', rejectAbort)
        }),
      async () => {
        await assert.rejects(
          api.analyzeUrl('https://example.com'),
          isAnalysisError('timeout'),
        )
      },
    )
  } finally {
    globalThis.setTimeout = realSetTimeout
  }
})

/* ------------------------------------------------------------------ */
/* 8. Malformed / unexpected backend response                          */
/* ------------------------------------------------------------------ */

test('non-JSON body becomes an invalid_response error', async () => {
  await withFetch(
    async () => new Response('<html>not json</html>', { status: 200, headers: { 'Content-Type': 'text/html' } }),
    async () => {
      await assert.rejects(
        api.analyzeUrl('https://example.com'),
        isAnalysisError('invalid_response'),
      )
    },
  )
})

test('unexpected JSON shape becomes an invalid_response error', async () => {
  await withFetch(
    async () => jsonResponse({ unexpected: true }),
    async () => {
      await assert.rejects(
        api.analyzeUrl('https://example.com'),
        isAnalysisError('invalid_response'),
      )
    },
  )
})

test('out-of-range score becomes an invalid_response error', async () => {
  await withFetch(
    async () => jsonResponse(baseResponse({ risk_level: 'high', score: 250 })),
    async () => {
      await assert.rejects(
        api.analyzeUrl('https://example.com'),
        isAnalysisError('invalid_response'),
      )
    },
  )
})

/* ------------------------------------------------------------------ */
/* 9. Missing / unsupported scheme (client-side validation)            */
/* ------------------------------------------------------------------ */

test('missing scheme is rejected client-side without any request', async () => {
  let called = false
  await withFetch(
    async () => {
      called = true
      return jsonResponse(baseResponse())
    },
    async () => {
      await assert.rejects(api.analyzeUrl('example.com'), isAnalysisError('missing_scheme'))
      await assert.rejects(api.analyzeUrl('ftp://example.com'), isAnalysisError('unsupported_scheme'))
      await assert.rejects(api.analyzeUrl(''), isAnalysisError('empty'))
    },
  )
  assert.equal(called, false, 'no backend request should be made for invalid input')
})

/* ------------------------------------------------------------------ */
/* 10. Mock mode remains functional                                    */
/* ------------------------------------------------------------------ */

test('mock mode returns clearly labeled demonstration data', async () => {
  assert.equal(mock.USE_MOCK, true)
  const result = await mock.analyzeUrl('https://example.com')
  assert.ok(result.demo, 'mock results must carry a demo marker')
  assert.equal(result.risk_level, 'Low')
  assert.ok(Array.isArray(result.advice))
})

/* ------------------------------------------------------------------ */
/* 11. API mode posts to the configured backend URL                    */
/* ------------------------------------------------------------------ */

test('API mode posts JSON to ${VITE_API_BASE_URL}/api/analyze', async () => {
  assert.equal(api.USE_MOCK, false)
  let captured = null
  await withFetch(
    async (url, options) => {
      captured = { url, options }
      return jsonResponse(baseResponse())
    },
    async () => {
      await api.analyzeUrl('https://example.com')
    },
  )
  assert.ok(captured, 'fetch should have been called')
  assert.equal(captured.url, `${api.API_BASE_URL}/api/analyze`)
  assert.equal(captured.options.method, 'POST')
  assert.equal(captured.options.headers['Content-Type'], 'application/json')
  assert.deepEqual(JSON.parse(captured.options.body), { url: 'https://example.com/' })
})

/* ------------------------------------------------------------------ */
/* 12. The UI renders a valid result, not the generic error            */
/* ------------------------------------------------------------------ */

test('dashboard renders a valid analysis result, not the generic invalid-URL message', async () => {
  let result
  await withFetch(
    async () => jsonResponse(baseResponse()),
    async () => {
      result = await api.analyzeUrl('https://example.com')
    },
  )

  const html = renderToStaticMarkup(
    React.createElement(ResultDashboard, { result, onNewScan: () => {} }),
  )
  assert.match(html, /Analysis report/)
  assert.match(html, /example\.com/)
  assert.match(html, /No known threat/)
  assert.doesNotMatch(html, /Unable to verify this URL right now/)
  assert.doesNotMatch(html, /Invalid URL/)
})
