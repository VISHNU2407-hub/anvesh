/**
 * URLens — frontend analysis service.
 *
 * Single entry point for URL analysis. In mock mode (VITE_USE_MOCK=true)
 * results come from local, clearly labeled demonstration data. Otherwise the
 * service POSTs to ${VITE_API_BASE_URL}/api/analyze with JSON headers,
 * a request timeout, HTTP error handling, and response validation.
 *
 * This module never fabricates scores or threat data: in API mode the
 * backend's risk score and category are used exactly as returned.
 */

import { buildMockResult, RISK_LEVELS } from '../data/mockResults'

/** True when the frontend should use local demonstration data. */
export const USE_MOCK = String(import.meta.env.VITE_USE_MOCK ?? 'true').toLowerCase() !== 'false'

/** Base URL of the FastAPI backend (no trailing slash). */
export const API_BASE_URL = String(
  import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000',
).replace(/\/+$/, '')

const REQUEST_TIMEOUT_MS = 10000
const MOCK_DELAY_MS = [650, 1150]

/** Structured, user-safe error with a stable code the UI can branch on. */
export class AnalysisError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'AnalysisError'
    this.code = code
  }
}

const FALLBACK_ERROR =
  'Unable to verify this URL right now. Please try again.'

/* ------------------------------------------------------------------ */
/* URL validation                                                      */
/* ------------------------------------------------------------------ */

const SCHEME_RE = /^[a-z][a-z0-9+.-]*:/i

/**
 * Validate user input before any analysis.
 * Accepts HTTP and HTTPS URLs only.
 * @returns {{ok: true, url: string} | {ok: false, code: string, message: string}}
 */
export function validateUrl(raw) {
  const value = String(raw ?? '').trim()

  if (!value) {
    return {
      ok: false,
      code: 'empty',
      message: 'Please enter a URL to analyze.',
    }
  }

  if (/\s/.test(value)) {
    return {
      ok: false,
      code: 'malformed',
      message: 'Please enter a valid URL, including https:// — URLs cannot contain spaces.',
    }
  }

  if (!SCHEME_RE.test(value)) {
    return {
      ok: false,
      code: 'missing_scheme',
      message: 'Please enter a valid URL, including https:// (for example, https://example.com).',
    }
  }

  if (!/^https?:/i.test(value)) {
    return {
      ok: false,
      code: 'unsupported_scheme',
      message: 'Only http:// and https:// links can be analyzed. Please enter a valid URL, including https://.',
    }
  }

  const rest = value.replace(/^https?:\/\//i, '')
  if (!rest || rest.startsWith('/') || rest.startsWith('?') || rest.startsWith('#')) {
    return {
      ok: false,
      code: 'missing_hostname',
      message: "We couldn't find a hostname in this address. Please enter a valid URL, including https://.",
    }
  }

  let parsed
  try {
    parsed = new URL(value)
  } catch {
    return {
      ok: false,
      code: 'malformed',
      message: 'Please enter a valid URL, including https://.',
    }
  }

  if (!parsed.hostname) {
    return {
      ok: false,
      code: 'missing_hostname',
      message: "We couldn't find a hostname in this address. Please enter a valid URL, including https://.",
    }
  }

  return { ok: true, url: parsed.href }
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

/**
 * Analyze a URL. Always resolves to an analysis result object or rejects
 * with an AnalysisError carrying a friendly, non-technical message.
 */
export async function analyzeUrl(rawUrl) {
  const validation = validateUrl(rawUrl)
  if (!validation.ok) {
    throw new AnalysisError(validation.code, validation.message)
  }

  if (USE_MOCK) {
    await delay(rand(MOCK_DELAY_MS[0], MOCK_DELAY_MS[1]))
    return buildMockResult(validation.url)
  }

  return requestAnalysis(validation.url)
}

/* ------------------------------------------------------------------ */
/* Backend request                                                     */
/* ------------------------------------------------------------------ */

async function requestAnalysis(url) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)

  let response
  try {
    response = await fetch(`${API_BASE_URL}/api/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    })
  } catch {
    if (controller.signal.aborted) {
      throw new AnalysisError(
        'timeout',
        'The analysis request timed out. Please try again.',
      )
    }
    throw new AnalysisError(
      'network',
      'Unable to verify this URL right now. The analysis service could not be reached. Please try again.',
    )
  } finally {
    clearTimeout(timer)
  }

  if (!response.ok) {
    throw new AnalysisError(
      'http',
      `Unable to verify this URL right now. The service responded with an error (HTTP ${response.status}). Please try again.`,
    )
  }

  let data
  try {
    data = await response.json()
  } catch {
    throw new AnalysisError(
      'invalid_response',
      'We received an unreadable response from the analysis service. Please try again.',
    )
  }

  return normalizeResponse(data, url)
}

/**
 * Validate the backend response against the expected contract.
 * Never invents a score — a malformed response becomes an error the UI can
 * show, instead of a fabricated result.
 */
function normalizeResponse(data, requestedUrl) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new AnalysisError('invalid_response', 'The analysis service returned an unexpected response. Please try again.')
  }

  const riskLevel = typeof data.risk_level === 'string'
    ? RISK_LEVELS.find((l) => l.toLowerCase() === data.risk_level.trim().toLowerCase())
    : undefined
  if (!riskLevel) {
    throw new AnalysisError('invalid_response', 'The analysis service returned an unexpected response. Please try again.')
  }

  const hasScore = typeof data.risk_score === 'number' && Number.isFinite(data.risk_score)
  if (riskLevel !== 'Unknown' && (!hasScore || data.risk_score < 0 || data.risk_score > 100)) {
    throw new AnalysisError('invalid_response', 'The analysis service returned an unexpected response. Please try again.')
  }
  if (riskLevel === 'Unknown' && hasScore && (data.risk_score < 0 || data.risk_score > 100)) {
    throw new AnalysisError('invalid_response', 'The analysis service returned an unexpected response. Please try again.')
  }

  const findings = Array.isArray(data.findings) ? data.findings : null
  if (!findings) {
    throw new AnalysisError('invalid_response', 'The analysis service returned an unexpected response. Please try again.')
  }

  const advice = Array.isArray(data.advice) ? data.advice : []
  const url = typeof data.url === 'string' && data.url ? data.url : requestedUrl
  const domain = typeof data.domain === 'string' && data.domain
    ? data.domain
    : (() => {
        try {
          return new URL(url).hostname
        } catch {
          return '—'
        }
      })()

  const reputation =
    data.reputation && typeof data.reputation === 'object'
      ? {
          status: typeof data.reputation.status === 'string' ? data.reputation.status : 'unavailable',
          message:
            typeof data.reputation.message === 'string'
              ? data.reputation.message
              : 'Reputation check unavailable',
        }
      : { status: 'unavailable', message: 'Reputation check unavailable' }

  return {
    url,
    domain,
    risk_level: riskLevel,
    risk_score: hasScore ? Math.round(data.risk_score) : null,
    findings: findings
      .filter((f) => f && typeof f === 'object')
      .map((f) => ({
        name: typeof f.name === 'string' ? f.name : 'Finding',
        severity: normalizeSeverity(f.severity),
        explanation: typeof f.explanation === 'string' ? f.explanation : '',
        ...(typeof f.evidence === 'string' ? { evidence: f.evidence } : {}),
      })),
    reputation,
    advice: advice.filter((a) => typeof a === 'string'),
    scanned_at:
      typeof data.scanned_at === 'string' ? data.scanned_at : new Date().toISOString(),
    // API mode results are backend assessments, not browser simulations.
    demo: null,
  }
}

function normalizeSeverity(value) {
  const v = String(value ?? '').toLowerCase()
  if (['high', 'medium', 'low'].includes(v)) return v
  return 'informational'
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function rand(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min
}

export { FALLBACK_ERROR }
