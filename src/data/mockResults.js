/**
 * URLens — local mock data.
 *
 * Everything in this file is SIMULATED demonstration data produced in the
 * browser. No threat-intelligence feed, reputation database, or detection
 * engine is involved. Every generated result carries a `demo` marker so the
 * UI can label it clearly.
 */

/** Sample URLs offered as one-click buttons on the landing page. */
export const SAMPLE_URLS = {
  low: 'https://example.com',
  medium: 'https://login.secure.example-verify.net/auth',
  high: 'https://login-example.invalid/verify',
}

export const RISK_LEVELS = ['Low', 'Medium', 'High', 'Unknown']

const DEMO_REPUTATION = {
  status: 'not_checked',
  message:
    'Reputation status: unavailable in demo mode — no threat-intelligence lookup was performed for this scan.',
}

const SAFE_DEMO_NOTE =
  'Demonstration result. This score is simulated and does not establish that the URL is safe.'

/* ------------------------------------------------------------------ */
/* Scenario templates                                                  */
/* ------------------------------------------------------------------ */

const SCENARIOS = {
  /** Scenario A — low risk (https://example.com) */
  low: {
    risk_level: 'Low',
    risk_score: 10,
    scenario: 'A',
    findings: [
      {
        name: 'URL structure',
        severity: 'low',
        explanation:
          'The address follows a plain, standard structure with no odd encoding, redirects, or credential-style parameters.',
        evidence: 'simulated',
      },
      {
        name: 'Hostname format',
        severity: 'informational',
        explanation:
          'The hostname is short and uses a common top-level domain, with no hyphens or deep subdomain nesting.',
        evidence: 'simulated',
      },
      {
        name: 'Transport security',
        severity: 'informational',
        explanation:
          'The URL uses HTTPS, so traffic is encrypted in transit. HTTPS alone does not prove a site is trustworthy.',
        evidence: 'simulated',
      },
    ],
    advice: [
      'Verify the destination before entering sensitive information.',
      'Type the official address directly into your browser instead of following links from messages.',
      'Never share passwords, OTPs, or payment details with a page you found through a link.',
      'Keep your browser and devices up to date.',
    ],
  },

  /** Scenario B — medium risk (suspicious pattern sample) */
  medium: {
    risk_level: 'Medium',
    risk_score: 55,
    scenario: 'B',
    findings: [
      {
        name: 'Suspicious hostname pattern',
        severity: 'medium',
        explanation:
          'The hostname mixes words such as "login", "secure", and "verify", which frequently appear on credential-phishing pages.',
        evidence: 'simulated',
      },
      {
        name: 'Unusual subdomain structure',
        severity: 'medium',
        explanation:
          'Several subdomains are stacked before the registered domain — a technique often used to make a look-alike address appear legitimate.',
        evidence: 'simulated',
      },
      {
        name: 'Domain verification recommended',
        severity: 'low',
        explanation:
          'The registered domain could not be matched to a known official service in the demonstration dataset, so independent verification is recommended.',
        evidence: 'simulated',
      },
    ],
    advice: [
      'Do not enter passwords, OTPs, or payment details until you have confirmed the real owner of this site.',
      'Open the official website or app directly instead of following this link.',
      'Read the domain name carefully from the registered domain onward — look for misspellings or extra words.',
      'Treat this result cautiously: it is a simulated demonstration, not a verified assessment.',
    ],
  },

  /** Scenario C — high risk (https://login-example.invalid/verify) */
  high: {
    risk_level: 'High',
    risk_score: 85,
    scenario: 'C',
    findings: [
      {
        name: 'Credential-harvesting URL pattern',
        severity: 'high',
        explanation:
          'The hostname and path resemble a login-verification page, a shape commonly used to capture passwords and one-time codes.',
        evidence: 'simulated',
      },
      {
        name: 'Deceptive hostname construction',
        severity: 'high',
        explanation:
          'A brand-like word is joined with a hyphen inside a reserved, non-registrable domain — a pattern frequently reported in phishing campaigns.',
        evidence: 'simulated',
      },
      {
        name: 'No matching official service',
        severity: 'medium',
        explanation:
          'The hostname does not correspond to any known official service in the demonstration dataset, so the destination cannot be trusted from this result alone.',
        evidence: 'simulated',
      },
      {
        name: 'Threat intelligence not consulted',
        severity: 'informational',
        explanation:
          'No live threat feed was queried because this scan ran in demo mode. Real feeds require the backend service.',
        evidence: 'simulated',
      },
    ],
    advice: [
      'Do not enter passwords, OTPs, or payment information.',
      'Verify the website using its independently confirmed official address.',
      'Avoid interacting with the link until it has been verified.',
      'Report a suspected phishing attempt through the appropriate channel.',
      'If you already entered data on a page like this, change the affected password immediately from a trusted device.',
    ],
  },
}

/** Hostnames that map to each deterministic scenario. */
const SCENARIO_HOSTS = {
  low: ['example.com', 'www.example.com'],
  medium: ['login.secure.example-verify.net', 'example-verify.net'],
  high: ['login-example.invalid'],
}

/**
 * Resolve a URL to a known mock scenario key ('low' | 'medium' | 'high')
 * or null when no explicit scenario matches.
 */
export function matchScenario(rawUrl) {
  let hostname
  try {
    hostname = new URL(rawUrl).hostname.toLowerCase()
  } catch {
    return null
  }
  for (const [key, hosts] of Object.entries(SCENARIO_HOSTS)) {
    if (hosts.includes(hostname)) return key
  }
  return null
}

/* ------------------------------------------------------------------ */
/* Result assembly                                                     */
/* ------------------------------------------------------------------ */

function assemble({ url, domain, template, demo }) {
  return {
    url,
    domain,
    risk_level: template.risk_level,
    risk_score: template.risk_score,
    findings: template.findings,
    reputation: { ...DEMO_REPUTATION },
    advice: template.advice,
    scanned_at: new Date().toISOString(),
    demo,
  }
}

/**
 * Build the full analysis response for a URL.
 * Known scenario hosts get an exact deterministic result; every other URL
 * goes through clearly labeled heuristic demonstration rules that never
 * declare an unknown URL "safe".
 */
export function buildMockResult(rawUrl) {
  const url = normalizeUrl(rawUrl)
  const domain = safeHostname(url)
  const scenarioKey = matchScenario(url)

  if (scenarioKey) {
    const template = SCENARIOS[scenarioKey]
    return assemble({
      url,
      domain,
      template,
      demo: {
        simulated: true,
        label: 'DEMO RESULT',
        scenario: template.scenario,
        note: SAFE_DEMO_NOTE,
        source: 'explicit scenario',
      },
    })
  }

  return heuristicResult(url, domain)
}

function normalizeUrl(rawUrl) {
  try {
    return new URL(rawUrl).href
  } catch {
    return rawUrl
  }
}

function safeHostname(rawUrl) {
  try {
    return new URL(rawUrl).hostname
  } catch {
    return '—'
  }
}

/* ------------------------------------------------------------------ */
/* Labeled heuristic demonstration rules                              */
/* ------------------------------------------------------------------ */

const SUSPICIOUS_WORDS = [
  'login',
  'signin',
  'sign-in',
  'verify',
  'verification',
  'secure',
  'account',
  'update',
  'password',
  'passwd',
  'bank',
  'wallet',
  'confirm',
  'unlock',
  'otp',
  'recover',
  'validate',
]

const COMMON_TLDS = [
  'com',
  'org',
  'net',
  'edu',
  'gov',
  'io',
  'co',
  'dev',
  'app',
  'info',
  'us',
  'uk',
  'in',
]

const WEAK_TLDS = ['xyz', 'top', 'click', 'icu', 'zip', 'mov', 'buzz', 'rest']

function isIpAddress(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':')
}

function collectIndicators(url) {
  const u = new URL(url)
  const host = u.hostname.toLowerCase()
  const labels = host.split('.').filter(Boolean)
  const registeredTld = labels[labels.length - 1] || ''
  const indicatorList = []

  if (u.protocol === 'http:') {
    indicatorList.push({
      name: 'Unencrypted HTTP connection',
      severity: 'medium',
      explanation:
        'The URL does not use HTTPS, so anything typed on the page could be intercepted while in transit.',
    })
  }

  if (isIpAddress(host)) {
    indicatorList.push({
      name: 'Raw IP address used as hostname',
      severity: 'high',
      explanation:
        'The site is addressed by a numeric IP instead of a registered domain, which hides who actually operates it.',
    })
  }

  if (u.username || u.password) {
    indicatorList.push({
      name: 'Credentials embedded in the URL',
      severity: 'high',
      explanation:
        'The address contains an embedded username or password — a trick often used to disguise the real destination.',
    })
  }

  if (labels.length > 4) {
    indicatorList.push({
      name: 'Unusually deep subdomain structure',
      severity: 'medium',
      explanation:
        'Many subdomains are stacked before the registered domain, a layout commonly used to make look-alike addresses appear legitimate.',
    })
  }

  const suspiciousLabel = labels.find(hasSuspiciousWord)
  if (suspiciousLabel) {
    const word = findSuspiciousWord(suspiciousLabel)
    indicatorList.push({
      name: 'Suspicious wording in hostname',
      severity: 'medium',
      explanation: `The hostname contains "${word}", a word frequently used on credential-phishing pages.`,
    })
  }

  const domainLabel = labels.length >= 2 ? labels[labels.length - 2] : labels[0]
  if (domainLabel && domainLabel.includes('-')) {
    indicatorList.push({
      name: 'Hyphenated registered domain',
      severity: 'low',
      explanation:
        'The main domain name contains hyphens, which is common on quickly registered look-alike domains.',
    })
  }

  if (registeredTld && WEAK_TLDS.includes(registeredTld)) {
    indicatorList.push({
      name: 'Frequently abused top-level domain',
      severity: 'medium',
      explanation: `Domains ending in ".${registeredTld}" are inexpensive to register and are disproportionately represented in abuse reports.`,
    })
  } else if (registeredTld && !COMMON_TLDS.includes(registeredTld)) {
    indicatorList.push({
      name: 'Uncommon top-level domain',
      severity: 'low',
      explanation: `The ".${registeredTld}" extension is less common, so the operator of the site cannot be inferred from the address alone.`,
    })
  }

  const pathText = `${u.pathname} ${u.search}`.toLowerCase()
  const pathWord = SUSPICIOUS_WORDS.find((w) => pathText.includes(w))
  if (pathWord) {
    indicatorList.push({
      name: 'Suspicious wording in the page path',
      severity: 'medium',
      explanation: `The address path contains "${pathWord}", wording often used in verification or credential-capture flows.`,
    })
  }

  return indicatorList
}

function hasSuspiciousWord(label) {
  return Boolean(findSuspiciousWord(label))
}

function findSuspiciousWord(label) {
  const lower = label.toLowerCase()
  return SUSPICIOUS_WORDS.find((w) => lower.includes(w)) || null
}

const SEVERITY_POINTS = { high: 14, medium: 8, low: 4 }

function heuristicResult(url, domain) {
  const indicators = collectIndicators(url)

  // No matched rule: report "Unknown" instead of implying the URL is safe.
  if (indicators.length === 0) {
    return {
      url,
      domain,
      risk_level: 'Unknown',
      risk_score: null,
      findings: [
        {
          name: 'No assessment available in demo mode',
          severity: 'informational',
          explanation:
            'No explicit mock scenario or heuristic demonstration rule matched this URL, and the detection engine is not connected. No risk conclusion can be drawn.',
          evidence: 'heuristic-demo',
        },
      ],
      reputation: { ...DEMO_REPUTATION },
      advice: [
        'Treat unknown results cautiously — this demo could not assess the URL.',
        'Verify the destination through an official website or app before sharing any information.',
        'Do not enter passwords, OTPs, or payment details on pages reached from unsolicited links.',
        'A full assessment requires the backend detection engine, which is not part of this frontend demo.',
      ],
      scanned_at: new Date().toISOString(),
      demo: {
        simulated: true,
        label: 'SIMULATED RESULT',
        scenario: 'heuristic',
        note: 'No demonstration scenario matched this URL. This report was produced by labeled heuristic rules in the frontend and does not establish that the URL is safe or malicious.',
        source: 'heuristic demo rules',
      },
    }
  }

  const score = Math.min(
    95,
    42 +
      indicators.reduce((sum, i) => sum + (SEVERITY_POINTS[i.severity] ?? 4), 0),
  )
  const riskLevel = score >= 75 ? 'High' : score >= 40 ? 'Medium' : 'Low'

  const findings = [
    ...indicators.map((i) => ({ ...i, evidence: 'heuristic-demo' })),
    {
      name: 'Generated by demonstration rules',
      severity: 'informational',
      explanation:
        'These indicators come from simple frontend heuristics, not from the detection engine or any threat feed.',
      evidence: 'heuristic-demo',
    },
  ]

  const advice = [
    'Verify the destination through an official website or app before sharing any information.',
    'Avoid entering credentials on a page reached from this link until it is confirmed.',
    'Do not share OTPs or banking details through unverified links.',
    'Treat this result cautiously — it is a simulated heuristic demonstration.',
  ]
  if (riskLevel === 'High') {
    advice.unshift('Do not enter passwords, OTPs, or payment information on this page.')
    advice.push('Report a suspected phishing attempt through the appropriate channel.')
  }

  return {
    url,
    domain,
    risk_level: riskLevel,
    risk_score: score,
    findings,
    reputation: { ...DEMO_REPUTATION },
    advice,
    scanned_at: new Date().toISOString(),
    demo: {
      simulated: true,
      label: 'SIMULATED HEURISTIC RESULT',
      scenario: 'heuristic',
      note: 'Heuristic demonstration rules generated this result inside the browser. It was not produced by the detection engine and does not establish that the URL is safe or malicious.',
      source: 'heuristic demo rules',
    },
  }
}

/* ------------------------------------------------------------------ */
/* Seed scan history                                                   */
/* ------------------------------------------------------------------ */

function minutesAgo(mins) {
  return new Date(Date.now() - mins * 60 * 1000).toISOString()
}

function seedRecord(id, url, scenarioKey, scannedAt) {
  const result = buildMockResult(url)
  return {
    id,
    url: result.url,
    domain: result.domain,
    risk_level: result.risk_level,
    risk_score: result.risk_score,
    scanned_at: scannedAt,
    record_type: 'demo',
    result: { ...result, scanned_at: scannedAt, scenario: scenarioKey },
  }
}

/** A few clearly labeled demonstration records shown on first load. */
export const SEED_HISTORY = [
  seedRecord('seed-1', SAMPLE_URLS.low, 'low', minutesAgo(14)),
  seedRecord('seed-2', SAMPLE_URLS.medium, 'medium', minutesAgo(96)),
  seedRecord('seed-3', SAMPLE_URLS.high, 'high', minutesAgo(260)),
]

/**
 * Store only the parts of a URL that are useful for a history list.
 * Query strings and fragments are dropped so sensitive parameters are not
 * kept around unnecessarily.
 */
export function sanitizeForHistory(rawUrl) {
  try {
    const u = new URL(rawUrl)
    return `${u.protocol}//${u.host}${u.pathname}`
  } catch {
    return rawUrl
  }
}
