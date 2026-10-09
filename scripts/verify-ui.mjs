/**
 * URLens — end-to-end UI verification.
 * Drives the running dev server with headless Chrome and checks the
 * acceptance criteria: three demo scenarios, validation errors, unknown
 * results, navigation, demo labels, and mobile layout.
 *
 * Usage: node scripts/verify-ui.mjs  (dev server must be running)
 */
import puppeteer from 'puppeteer-core'
import { mkdirSync, existsSync } from 'node:fs'

const BASE = process.env.APP_URL ?? 'http://127.0.0.1:5173'
const CHROME =
  process.env.CHROME_PATH ??
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'

const SHOTS = 'verify-shots'
mkdirSync(SHOTS, { recursive: true })

if (!existsSync(CHROME)) {
  console.error(`Chrome not found at ${CHROME}. Set CHROME_PATH.`)
  process.exit(2)
}

let passed = 0
const failures = []
const consoleErrors = []

/** Case-insensitive contains (CSS text-transform affects innerText). */
function ci(haystack, needle) {
  return String(haystack ?? '')
    .toLowerCase()
    .includes(String(needle).toLowerCase())
}

function check(name, condition, detail = '') {
  if (condition) {
    passed += 1
    console.log(`  ok   ${name}`)
  } else {
    failures.push(`${name}${detail ? ` — ${detail}` : ''}`)
    console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`)
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function textExists(page, text, timeout = 6000) {
  try {
    await page.waitForFunction(
      (t) => document.body.innerText.toLowerCase().includes(t.toLowerCase()),
      { timeout },
      text,
    )
    return true
  } catch {
    return false
  }
}

async function bodyText(page) {
  return page.evaluate(() => document.body.innerText)
}

async function clickButtonByText(page, text) {
  const clicked = await page.evaluate((t) => {
    const buttons = [...document.querySelectorAll('button')]
    const btn = buttons.find((b) =>
      b.innerText.toLowerCase().includes(t.toLowerCase()),
    )
    if (btn) {
      btn.click()
      return true
    }
    return false
  }, text)
  if (!clicked) throw new Error(`button not found: "${text}"`)
}

async function setUrl(page, value) {
  await page.waitForSelector('#url-input', { timeout: 5000 })
  await page.$eval('#url-input', (el) => {
    const setter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype,
      'value',
    ).set
    setter.call(el, '')
    el.dispatchEvent(new Event('input', { bubbles: true }))
  })
  if (value) await page.type('#url-input', value, { delay: 8 })
}

async function run() {
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: 'new',
    args: ['--no-sandbox', '--disable-gpu'],
  })
  const page = await browser.newPage()
  await page.setViewport({ width: 1440, height: 900 })

  page.on('pageerror', (err) => consoleErrors.push(`pageerror: ${err.message}`))
  page.on('console', (msg) => {
    if (msg.type() === 'error') consoleErrors.push(`console: ${msg.text()}`)
  })

  /* ---------- 1. Landing page ---------- */
  console.log('\n[1] Landing page')
  await page.goto(BASE, { waitUntil: 'networkidle0' })
  check('hero heading renders', await textExists(page, 'Check a link before you click.'))
  const pageTitle = await page.title()
  check('page title rebranded to URLens', pageTitle.includes('URLens'), pageTitle)
  const headerBrand = await page.$eval('header a[aria-label]', (a) => a.innerText)
  check(
    'header logo shows URLens',
    headerBrand.replace(/\s/g, '').includes('URLens'),
    headerBrand,
  )
  const footerText = await bodyText(page)
  check('footer tagline present', ci(footerText, 'See the threat before you click.'))
  check('footer subtitle present', ci(footerText, 'Phishing & Malicious Link Detection'))
  check('supporting text renders', await textExists(page, 'Analyze a URL for suspicious patterns and known threats.'))
  check('DEMO MODE indicator visible', await textExists(page, 'Demo mode'))
  check('no result shown before scanning', !ci(footerText, 'Risk score'))
  await page.screenshot({ path: `${SHOTS}/01-landing.png`, fullPage: true })

  /* ---------- 2. Scenario A — low risk ---------- */
  console.log('\n[2] Scenario A: https://example.com → Low / 10')
  await clickButtonByText(page, 'Normal sample')
  const filled = await page.$eval('#url-input', (el) => el.value)
  check('sample fills input', filled === 'https://example.com', filled)
  await clickButtonByText(page, 'Analyze Link')
  check('loading state shown', await textExists(page, 'Analyzing URL'))
  check('demo loading explanation', await textExists(page, 'No live threat-intelligence checks are being performed'))
  await page.screenshot({ path: `${SHOTS}/02-loading.png` })
  check('navigated to report', await textExists(page, 'Analysis report', 9000))
  let text = await bodyText(page)
  check('Low Risk badge', ci(text, 'Low Risk'))
  check('score 10/100', ci(text, '10/100'))
  check('demo notice sentence', ci(text, 'This score is simulated and does not establish that the URL is safe'))
  check('threat intel: not checked in demo', ci(text, 'Not checked in demo mode'))
  check('findings rendered', ci(text, 'Security findings') && ci(text, 'URL structure'))
  check('recommendations rendered', ci(text, 'Safety recommendations'))
  const meterLabel = await page.$eval('[role="img"]', (el) => el.getAttribute('aria-label'))
  check('risk meter aria label', meterLabel && meterLabel.includes('10 out of 100'), meterLabel)
  await page.screenshot({ path: `${SHOTS}/03-result-low.png`, fullPage: true })

  /* ---------- 3. Scenario B — medium risk ---------- */
  console.log('\n[3] Scenario B: suspicious pattern sample → Medium / 55')
  await clickButtonByText(page, 'New Scan')
  await sleep(400)
  await clickButtonByText(page, 'Suspicious pattern sample')
  await clickButtonByText(page, 'Analyze Link')
  check('Medium Risk shown', await textExists(page, 'Medium Risk', 10000))
  text = await bodyText(page)
  check('score 55/100', ci(text, '55/100'))
  check('medium findings present', ci(text, 'Suspicious hostname pattern') && ci(text, 'Unusual subdomain structure'))
  check('demo banner shown', ci(text, 'score is simulated'))
  await page.screenshot({ path: `${SHOTS}/04-result-medium.png`, fullPage: true })

  /* ---------- 4. Scenario C — high risk ---------- */
  console.log('\n[4] Scenario C: login-example.invalid → High / 85')
  await clickButtonByText(page, 'New Scan')
  await sleep(400)
  await clickButtonByText(page, 'Phishing-style sample')
  await clickButtonByText(page, 'Analyze Link')
  check('High Risk shown', await textExists(page, 'High Risk', 10000))
  text = await bodyText(page)
  check('score 85/100', ci(text, '85/100'))
  check('warning banner present', ci(text, 'Simulated high-risk demonstration'))
  check('no confirmed-malicious claim', ci(text, 'not a confirmed malicious verdict'))
  check('high-risk recommendation', ci(text, 'Do not enter passwords, OTPs, or payment information'))
  await page.screenshot({ path: `${SHOTS}/05-result-high.png`, fullPage: true })

  /* ---------- 5. Unknown URL heuristic ---------- */
  console.log('\n[5] Unknown URL → Unknown / unable to determine')
  await clickButtonByText(page, 'New Scan')
  await sleep(400)
  await setUrl(page, 'https://portal.org/page')
  await clickButtonByText(page, 'Analyze Link')
  check('unknown result shows "Unable to determine risk"', await textExists(page, 'Unable to determine risk', 10000))
  text = await bodyText(page)
  check('unknown labeled simulated', ci(text, 'SIMULATED'))
  await page.screenshot({ path: `${SHOTS}/06-result-unknown.png`, fullPage: true })

  /* ---------- 6. Validation errors ---------- */
  console.log('\n[6] Validation & error states')
  await page.goto(`${BASE}/#/`, { waitUntil: 'networkidle0' })
  await page.waitForSelector('#url-input')
  await clickButtonByText(page, 'Analyze Link')
  check('empty input error', await textExists(page, 'Please enter a URL to analyze.'))
  await setUrl(page, 'not-a-url')
  await clickButtonByText(page, 'Analyze Link')
  check('malformed URL error (includes https://)', await textExists(page, 'including https://'))
  await setUrl(page, 'ftp://example.com/file')
  await clickButtonByText(page, 'Analyze Link')
  check('unsupported scheme error', await textExists(page, 'Only http:// and https://'))
  await setUrl(page, 'https:///missing-host')
  await clickButtonByText(page, 'Analyze Link')
  check('missing hostname error', await textExists(page, "couldn't find a hostname"))
  check('no stack traces shown', !ci(await bodyText(page), 'at Object.'))

  /* ---------- 7. Navigation ---------- */
  console.log('\n[7] Navigation')
  await page.goto(`${BASE}/#/`, { waitUntil: 'networkidle0' })
  const navLinks = await page.$$eval('header nav a', (els) =>
    els.map((a) => a.innerText.trim()),
  )
  check(
    'header nav links',
    ['Home', 'How It Works', 'History'].every((l) => navLinks.includes(l)),
    navLinks.join(','),
  )

  await page.goto(`${BASE}/#/how-it-works`, { waitUntil: 'networkidle0' })
  text = await bodyText(page)
  check(
    'How It Works: 4 steps',
    ['URL Parsing and Validation', 'Suspicious Pattern Analysis', 'Threat Intelligence', 'Risk Assessment and Safety Advice'].every((s) => ci(text, s)),
  )
  check('How It Works: demo note', ci(text, 'local mock data'))
  await page.screenshot({ path: `${SHOTS}/07-how-it-works.png`, fullPage: true })

  await page.goto(`${BASE}/#/history`, { waitUntil: 'networkidle0' })
  text = await bodyText(page)
  check('History: seed demo records', ci(text, 'Demo record'))
  check('History: View Result action', ci(text, 'View Result'))
  const rows = await page.$$eval('tbody tr', (els) => els.length)
  check('History: scans appended', rows >= 6, `${rows} rows`)
  await page.screenshot({ path: `${SHOTS}/08-history.png`, fullPage: true })
  await clickButtonByText(page, 'View Result')
  check('History View Result opens report', await textExists(page, 'Analysis report', 5000))

  /* ---------- 8. Mobile responsiveness ---------- */
  console.log('\n[8] Mobile layout (390x844)')
  await page.setViewport({ width: 390, height: 844, isMobile: true })
  await page.goto(`${BASE}/#/`, { waitUntil: 'networkidle0' })
  const overflow = await page.evaluate(() => ({
    scrollW: document.documentElement.scrollWidth,
    clientW: document.documentElement.clientWidth,
  }))
  check('no horizontal overflow', overflow.scrollW <= overflow.clientW + 1, JSON.stringify(overflow))
  const menuState = await page.evaluate(() => {
    const btn = document.querySelector('button[aria-controls="mobile-nav"]')
    if (!btn) return null
    btn.click()
    return 'clicked'
  })
  check('mobile menu button exists', menuState === 'clicked', String(menuState))
  await sleep(400)
  const expanded = await page.$eval('button[aria-controls="mobile-nav"]', (b) =>
    b.getAttribute('aria-expanded'),
  )
  check('mobile menu opens', expanded === 'true', String(expanded))
  check('mobile nav links visible', await textExists(page, 'How It Works'))
  await page.screenshot({ path: `${SHOTS}/10-mobile-home.png`, fullPage: true })

  await page.goto(`${BASE}/#/history`, { waitUntil: 'networkidle0' })
  const overflow2 = await page.evaluate(
    () => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1,
  )
  check('history no overflow on mobile', overflow2)
  await page.screenshot({ path: `${SHOTS}/11-mobile-history.png`, fullPage: true })

  /* ---------- Report ---------- */
  console.log('\nConsole/page errors:', consoleErrors.length ? consoleErrors : 'none')
  check('no console/page errors', consoleErrors.length === 0)

  console.log(`\n=== ${passed} passed, ${failures.length} failed ===`)
  if (failures.length) {
    console.log('Failures:')
    failures.forEach((f) => console.log(`  - ${f}`))
  }

  await browser.close()
  process.exit(failures.length ? 1 : 0)
}

run().catch((err) => {
  console.error('Verifier crashed:', err)
  process.exit(1)
})
