/**
 * Visibility diagnostic: finds CSS masks, opacity, or low-contrast styles
 * that hide rendered content, plus large gaps below the header.
 * Usage: node scripts/diagnose-visibility.mjs  (dev server on :5173)
 */
import puppeteer from 'puppeteer-core'

const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
const BASE = 'http://127.0.0.1:5173'

const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: 'new',
  args: ['--no-sandbox'],
})
const page = await browser.newPage()
await page.setViewport({ width: 1440, height: 900 })

const probe = () =>
  page.evaluate(() => {
    const issues = []

    // 1) Any element whose ancestor applies a mask or reduced opacity
    document.querySelectorAll('main *').forEach((el) => {
      const rect = el.getBoundingClientRect()
      if (rect.width < 4 || rect.height < 4) return
      let node = el
      let mask = 'none'
      let opacity = 1
      let visibility = 'visible'
      while (node && node !== document.body) {
        const cs = getComputedStyle(node)
        if (mask === 'none' && cs.maskImage && cs.maskImage !== 'none') {
          mask = `${cs.maskImage} (on ${node.className || node.tagName})`
        }
        if (cs.opacity !== '1') opacity = Math.min(opacity, Number(cs.opacity))
        if (cs.visibility !== 'visible') visibility = cs.visibility
        node = node.parentElement
      }
      const text = (el.innerText || '').trim().slice(0, 40)
      if (mask !== 'none') issues.push({ type: 'MASKED', text, mask })
      if (opacity < 1) issues.push({ type: 'OPACITY', text, opacity })
      if (visibility !== 'visible') issues.push({ type: 'HIDDEN', text, visibility })
    })

    // 2) Gap between header bottom and first main content
    const header = document.querySelector('header')
    const main = document.querySelector('main')
    const first = main?.querySelector('h1, h2, p, div')
    const gap = header && first
      ? Math.round(first.getBoundingClientRect().top - header.getBoundingClientRect().bottom)
      : null

    // 3) Main content height (reported by caller)

    // Dedupe
    const seen = new Set()
    const uniq = issues.filter((i) => {
      const k = i.type + i.mask + i.opacity + i.visibility
      if (seen.has(k)) return false
      seen.add(k)
      return true
    })

    return {
      url: location.hash || '#/',
      gapBelowHeader: gap,
      mainHeight: Math.round(main?.getBoundingClientRect().height ?? 0),
      issues: uniq.slice(0, 8),
      issueCount: uniq.length,
    }
  })

for (const route of ['/', '/how-it-works', '/history']) {
  await page.goto(`${BASE}/#${route}`, { waitUntil: 'networkidle0' })
  const r = await probe()
  console.log(`\n== ${r.url}  gapBelowHeader=${r.gapBelowHeader}px  mainHeight=${r.mainHeight}px`)
  console.log(`   issue kinds: ${r.issueCount}`)
  r.issues.forEach((i) =>
    console.log(
      `   ${i.type}: "${i.text}" ${i.mask ?? ''} ${i.opacity ?? ''} ${i.visibility ?? ''}`,
    ),
  )
}

// Loading / results / empty states on Home
await page.goto(`${BASE}/#/`, { waitUntil: 'networkidle0' })
await page.click('#url-input')
await page.type('#url-input', 'https://example.com', { delay: 3 })
await page.evaluate(() => {
  const b = [...document.querySelectorAll('button')].find((x) =>
    x.innerText.includes('Analyze Link'),
  )
  b.click()
})
await new Promise((r) => setTimeout(r, 800))
const loading = await probe()
console.log(`\n== [loading state] issues=${loading.issueCount}`)
loading.issues.forEach((i) => console.log(`   ${i.type}: "${i.text}" ${i.mask ?? ''} ${i.opacity ?? ''}`))

await browser.close()
