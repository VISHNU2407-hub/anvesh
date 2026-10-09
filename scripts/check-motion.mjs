/**
 * Motion verification: entrance animations settle at visible opacity, the
 * risk meter animates to the *supplied* score, reduced-motion shows content
 * immediately, and mobile stays overflow-free.
 * Usage: node scripts/check-motion.mjs  (dev server on :5173)
 */
import puppeteer from 'puppeteer-core'

const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
const BASE = 'http://127.0.0.1:5173'

let passed = 0
const failures = []
const check = (name, cond, detail = '') => {
  if (cond) {
    passed++
    console.log(`  ok   ${name}`)
  } else {
    failures.push(name)
    console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`)
  }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: 'new',
  args: ['--no-sandbox'],
})

/* 1) Normal motion: entrances settle at opacity 1 */
console.log('\n[1] Normal motion — entrances settle visible')
const page = await browser.newPage()
await page.setViewport({ width: 1440, height: 900 })
await page.goto(BASE, { waitUntil: 'networkidle0' })
await sleep(1400)
const settled = await page.evaluate(() => {
  const els = [
    document.querySelector('h1'),
    document.querySelector('#url-input'),
    document.querySelector('button[type="submit"]'),
    document.querySelector('.card'),
  ]
  return els.map((el) => (el ? getComputedStyle(el).opacity : 'missing'))
})
check(
  'hero, input, button, scanner card all opacity 1',
  settled.every((o) => o === '1'),
  JSON.stringify(settled),
)

/* 2) Risk meter animates ring to supplied score (score text always shown) */
console.log('\n[2] Risk meter ring animation')
await page.click('#url-input')
await page.type('#url-input', 'https://example.com', { delay: 3 })
await page.evaluate(() =>
  [...document.querySelectorAll('button')]
    .find((x) => x.innerText.includes('Analyze Link'))
    .click(),
)
const shown = await page.waitForFunction(
  () => document.body.innerText.includes('Analysis report'),
  { timeout: 9000 },
)
check('result page reached', Boolean(shown))
const sample = await page.evaluate(async () => {
  const circle = document.querySelector('[role="img"] svg circle:nth-of-type(2)')
  const first = getComputedStyle(circle).strokeDashoffset
  await new Promise((r) => setTimeout(r, 350))
  const mid = getComputedStyle(circle).strokeDashoffset
  await new Promise((r) => setTimeout(r, 1400))
  const final = getComputedStyle(circle).strokeDashoffset
  const meterText = document.querySelector('[role="img"]').innerText
  return { first, mid, final, meterText }
})
check(
  'ring visibly animates (mid value differs from final)',
  sample.first !== sample.final && sample.mid !== sample.final,
  JSON.stringify(sample),
)
check('score text shows actual 10 out of 100 during/after animation', sample.meterText.includes('10'))
check('no invented score text', !sample.meterText.includes('11') && !sample.meterText.includes('9'))

/* 3) Reduced motion: content visible immediately */
console.log('\n[3] prefers-reduced-motion: reduce')
const rm = await browser.newPage()
await rm.setViewport({ width: 1440, height: 900 })
await rm.emulateMediaFeatures([
  { name: 'prefers-reduced-motion', value: 'reduce' },
])
await rm.goto(BASE, { waitUntil: 'networkidle0' })
await sleep(120)
const rmVisible = await rm.evaluate(() => {
  const els = [
    document.querySelector('h1'),
    document.querySelector('#url-input'),
    document.querySelector('button[type="submit"]'),
    ...document.querySelectorAll('.card'),
  ]
  return els.map((el) => (el ? getComputedStyle(el).opacity : 'missing'))
})
check(
  'content visible immediately under reduced motion',
  rmVisible.every((o) => o === '1'),
  JSON.stringify(rmVisible),
)

/* 4) Mobile: no overflow after animation additions */
console.log('\n[4] Mobile overflow after animation changes')
const mob = await browser.newPage()
await mob.setViewport({ width: 390, height: 844, isMobile: true })
for (const route of ['/', '/how-it-works', '/history']) {
  await mob.goto(`${BASE}/#${route}`, { waitUntil: 'networkidle0' })
  await sleep(700)
  const ok = await mob.evaluate(
    () => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1,
  )
  check(`no horizontal overflow on ${route}`, ok)
}

console.log(`\n=== ${passed} passed, ${failures.length} failed ===`)
failures.forEach((f) => console.log('  -', f))
await browser.close()
process.exit(failures.length ? 1 : 0)
