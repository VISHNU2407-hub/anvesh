import puppeteer from 'puppeteer-core'

const browser = await puppeteer.launch({
  executablePath: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  headless: 'new',
  args: ['--no-sandbox'],
})
const page = await browser.newPage()
await page.setViewport({ width: 1440, height: 900 })

let allOk = true
for (const route of ['/', '/how-it-works', '/history']) {
  await page.goto(`http://127.0.0.1:5173/#${route}`, { waitUntil: 'networkidle0' })
  await new Promise((r) => setTimeout(r, 1500))
  const faded = await page.evaluate(() => {
    const out = []
    document.querySelectorAll('main *').forEach((el) => {
      // Only inspect rendered elements (skip display:none, e.g. the mobile
      // card list on desktop viewports, where animations never run).
      if (el.getClientRects().length === 0) return
      if (el.closest('[aria-hidden="true"]')) return
      const cs = getComputedStyle(el)
      if (cs.opacity !== '1' && (el.innerText || '').trim()) {
        out.push({ text: el.innerText.slice(0, 25), opacity: cs.opacity })
      }
    })
    return out
  })
  const ok = faded.length === 0
  allOk = allOk && ok
  console.log(
    `${route}: ${ok ? 'ok — all rendered content settled at opacity 1' : 'FAIL ' + JSON.stringify(faded)}`,
  )
}
await browser.close()
process.exit(allOk ? 0 : 1)
