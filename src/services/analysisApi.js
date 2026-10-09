/**
 * URLens — frontend analysis service.
 *
 * Single entry point for URL analysis. In mock mode (VITE_USE_MOCK=true)
 * results come from local, clearly labeled demonstration data. Otherwise the
 * service POSTs to ${VITE_API_BASE_URL}/api/analyze with JSON headers,
 * a request timeout, HTTP error handling, and response validation against
 * the backend contract:
 *   { url, risk_level, verdict, score, findings, reputation_status, advice, reputation }
 *
 * This module never fabricates scores or threat data: in API mode the
 * backend's risk score, verdict, and findings are used exactly as returned
 * and mapped to the internal UI shape.
 */

import { buildMockResult } from '../data/mockResults'

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

export const VALID_RISK_LEVELS = ['low', 'medium', 'high', 'unknown']
export const VALID_VERDICTS = [
  'confirmed_malicious',
  'suspicious',
  'unknown',
  'verified_safe',
]
export const VALID_REPUTATION_STATUSES = [
  'threat_detected',
  'no_known_threat',
  'unavailable',
]

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
    // Try to surface a meaningful validation message for 400/422.
    if (response.status === 400 || response.status === 422) {
      let detail = ''
      try {
        const body = await response.json()
        detail = typeof body.detail === 'string' ? body.detail : ''
        if (!detail && typeof body.message === 'string') detail = body.message
      } catch {
        /* ignore parse error */
      }
      const message = detail
        ? detail
        : response.status === 422
          ? 'Please enter a valid URL, including https://.'
          : 'Please enter a valid URL, including https://.'
      // Use the same presentation as client-side validation so the UI
      // shows an inline error rather than a generic service panel.
      throw new AnalysisError('malformed', message)
    }
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
 * Validate the backend response against the expected contract and map it
 * to the internal UI shape used by ResultDashboard et al.
 *
 * Never invents a score — a malformed response becomes an error the UI can
 * show, instead of a fabricated result.
 */
function normalizeResponse(data, requestedUrl) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new AnalysisError('invalid_response', 'The analysis service returned an unexpected response. Please try again.')
  }

  // ---- risk_level: backend sends lowercase, UI expects Capitalized ----
  const rawRisk = typeof data.risk_level === 'string' ? data.risk_level.trim().toLowerCase() : ''
  const riskKey = VALID_RISK_LEVELS.includes(rawRisk) ? rawRisk : null
  if (!riskKey) {
    throw new AnalysisError('invalid_response', 'The analysis service returned an unexpected response. Please try again.')
  }
  // UI expects Capitalized RISK_LEVELS like 'Low'/'Medium'/'High'/'Unknown'
  const riskLevel = capitalizeRisk(riskKey)

  // ---- verdict: required for correct display, backend includes it ----
  const rawVerdict = typeof data.verdict === 'string' ? data.verdict.trim().toLowerCase() : ''
  // Fallback to 'unknown' if backend omits it (older contract), but validate when present
  const verdict = rawVerdict && VALID_VERDICTS.includes(rawVerdict) ? rawVerdict : 'unknown'

  // ---- score: backend field is `score`, legacy mocks used `risk_score` ----
  const rawScore = typeof data.score === 'number' ? data.score
    : typeof data.risk_score === 'number' ? data.risk_score
    : null
  const hasScore = typeof rawScore === 'number' && Number.isFinite(rawScore)
  if (riskKey !== 'unknown' && (!hasScore || rawScore < 0 || rawScore > 100)) {
    throw new AnalysisError('invalid_response', 'The analysis service returned an unexpected response. Please try again.')
  }
  if (riskKey === 'unknown' && hasScore && (rawScore < 0 || rawScore > 100)) {
    throw new AnalysisError('invalid_response', 'The analysis service returned an unexpected response. Please try again.')
  }

  // ---- findings: backend Finding[] { title, severity, description, ... } ----
  const rawFindings = Array.isArray(data.findings) ? data.findings : null
  if (!rawFindings) {
    throw new AnalysisError('invalid_response', 'The analysis service returned an unexpected response. Please try again.')
  }

  const findings = rawFindings
    .filter((f) => f && typeof f === 'object')
    .map(mapFinding)

  // ---- url / domain ----
  const url = typeof data.url === 'string' && data.url ? data.url : requestedUrl
  const domain = (() => {
    if (typeof data.domain === 'string' && data.domain) return data.domain
    try {
      return new URL(url).hostname
    } catch {
      return '—'
    }
  })()

  // ---- reputation: backend uses reputation_status + reputation.report ----
  const reputationStatusRaw = typeof data.reputation_status === 'string'
    ? data.reputation_status.trim().toLowerCase()
    : typeof data.reputation?.status === 'string'
      ? data.reputation.status.trim().toLowerCase()
      : 'unavailable'
  const reputationStatus = VALID_REPUTATION_STATUSES.includes(reputationStatusRaw)
    ? reputationStatusRaw
    : 'unavailable'

  // Backend reputation.report holds matches/error_reason/provider
  const repReport = data.reputation && typeof data.reputation === 'object' ? data.reputation : null
  const reputationMessage = deriveReputationMessage(reputationStatus, repReport, data.advice)

  const reputation = {
    status: mapReputationForUI(reputationStatus),
    // Keep raw backend status for precise UI checks (threat vs clean).
    rawStatus: reputationStatus,
    message: reputationMessage,
    provider: repReport?.provider || 'google_safe_browsing',
    matches: Array.isArray(repReport?.matches) ? repReport.matches : [],
    error_reason: repReport?.error_reason || null,
  }

  // ---- advice: backend advice is a string paragraph; UI expects string[] ----
  const advice = deriveAdviceArray(data.advice)

  const scannedAt = typeof data.scanned_at === 'string' ? data.scanned_at : new Date().toISOString()

  return {
    url,
    domain,
    risk_level: riskLevel,
    risk_score: hasScore ? Math.round(rawScore) : null,
    score: hasScore ? Math.round(rawScore) : null,
    verdict,
    reputation_status: reputationStatus,
    findings,
    reputation,
    advice,
    scanned_at: scannedAt,
    // API mode results are backend assessments, not browser simulations.
    demo: null,
    raw: data,
  }
}

function capitalizeRisk(key) {
  switch (key) {
    case 'low': return 'Low'
    case 'medium': return 'Medium'
    case 'high': return 'High'
    default: return 'Unknown'
  }
}

function mapReputationForUI(status) {
  // Map backend reputation_status to ThreatStatus's expected keys.
  // ThreatStatus now handles threat_detected/no_known_threat, but this
  // keeps backward compat with its legacy mapping.
  if (status === 'threat_detected') return 'threat_detected'
  if (status === 'no_known_threat') return 'no_known_threat'
  return 'unavailable'
}

function deriveReputationMessage(status, report, advice) {
  if (status === 'threat_detected') {
    const types = report?.matches?.map((m) => m.threat_type).filter(Boolean).join(', ')
    return types
      ? `This address matched known threat list(s): ${types}.`
      : 'This address matched a known threat entry.'
  }
  if (status === 'no_known_threat') {
    // Must NOT claim safe — backend advice already says "No known threats found; safety is not guaranteed."
    return 'No known threat match in the checked sources. This does not guarantee the URL is safe.'
  }
  // unavailable
  const reason = report?.error_reason
  if (reason) {
    const reasonText = {
      missing_api_key: 'Reputation check unavailable: service not configured.',
      timeout: 'Reputation check timed out.',
      quota_exceeded: 'Reputation check unavailable: service quota exceeded.',
      auth_error: 'Reputation check unavailable: authentication failed.',
      invalid_response: 'Reputation check returned an unreadable response.',
      provider_error: 'Reputation check encountered an error.',
      api_error: 'Reputation check could not be completed.',
      connection_error: 'Reputation check could not be reached.',
    }[reason] || `Reputation check unavailable (${reason}).`
    return reasonText
  }
  if (typeof advice === 'string' && advice.toLowerCase().includes('could not be completed')) {
    return 'Threat-intelligence data could not be retrieved for this scan.'
  }
  return 'Threat-intelligence data could not be retrieved for this scan.'
}

function deriveAdviceArray(adviceField) {
  if (Array.isArray(adviceField)) {
    return adviceField.filter((a) => typeof a === 'string' && a.trim())
  }
  if (typeof adviceField === 'string' && adviceField.trim()) {
    // Backend advice is a single paragraph with multiple sentences.
    // Split into sentences for the Recommendations list so each point
    // gets its own bullet, but keep it as one item if splitting looks odd.
    const trimmed = adviceField.trim()
    // Heuristic: split on ". " when sentence ends with period, but keep
    // Detection-flagged titles together.
    const parts = trimmed.split(/(?<=\.)\s+/).map((s) => s.trim()).filter(Boolean)
    // If backend already crafted a 2–5 sentence paragraph, 2–5 items is fine.
    // If it is a single long sentence, keep single item.
    if (parts.length >= 2 && parts.length <= 8 && parts.every((p) => p.length < 240)) {
      return parts
    }
    return [trimmed]
  }
  return []
}

function mapFinding(f) {
  // Backend: { engine, rule_id, title, description, severity, confidence }
  // Mock:    { name, severity, explanation, evidence }
  // Support both.
  const title = typeof f.title === 'string' && f.title
    ? f.title
    : typeof f.name === 'string' && f.name ? f.name : 'Finding'
  const severity = normalizeSeverity(f.severity)
  const explanation = typeof f.description === 'string' && f.description
    ? f.description
    : typeof f.explanation === 'string' ? f.explanation : ''
  // Evidence: prefer backend evidence/description trail, else f.evidence
  let evidence
  if (typeof f.evidence === 'string' && f.evidence) evidence = f.evidence
  else if (f.rule_id) evidence = f.rule_id
  else if (f.confidence) evidence = `confidence: ${f.confidence}`
  // Include confidence + rule_id + engine when available.
  const extras = []
  if (f.rule_id) extras.push(String(f.rule_id))
  if (f.confidence) extras.push(`confidence ${String(f.confidence)}`)
  if (f.engine && String(f.engine) !== 'linkshield_rule_engine') extras.push(String(f.engine))
  if (extras.length && !evidence) evidence = extras.join(' · ')
  // For linkshield engine, store structured meta for UI if needed.
  return {
    name: title,
    severity,
    explanation,
    ...(evidence ? { evidence } : {}),
    // Preserve raw for debugging / verdict pages that want details.
    rule_id: f.rule_id || null,
    confidence: f.confidence || null,
    engine: f.engine || null,
  }
}

function normalizeSeverity(value) {
  const v = String(value ?? '').toLowerCase()
  if (v === 'critical' || v === 'high') return 'high'
  if (v === 'medium') return 'medium'
  if (v === 'low') return 'low'
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
