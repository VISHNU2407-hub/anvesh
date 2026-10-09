import puppeteer from 'puppeteer-core'

const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
const BASE = 'http://127.0.0.1:5173'

const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: 'new',
  args: ['--no-sandbox'],
})
const page = await browser.newPage()
await page.setViewport({ width: 390, height: 844, isMobile: true })

for (const route of ['/', '/history', '/how-it-works', '/about']) {
  await page.goto(`${BASE}/#${route}`, { waitUntil: 'networkidle0' })
  const info = await page.evaluate(() => {
    const vw = document.documentElement.clientWidth
    const out = []
    document.querySelectorAll('*').forEach((el) => {
      const r = el.getBoundingClientRect()
      if (r.right > vw + 1 || r.left < -1) {
        out.push({
          tag: el.tagName,
          cls: (el.className || '').toString().slice(0, 90),
          left: Math.round(r.left),
          right: Math.round(r.right),
          w: Math.round(r.width),
        })
      }
    })
    return { vw, scrollW: document.documentElement.scrollWidth, out: out.slice(0, 12) }
  })
  console.log(`\n== ${route} vw=${info.vw} scrollW=${info.scrollW}`)
  info.out.forEach((o) => console.log('  ', o.tag, o.cls, `L${o.left} R${o.right} W${o.w}`))
}
await browser.close()
