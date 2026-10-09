import puppeteer from 'puppeteer-core'

const browser = await puppeteer.launch({
  executablePath: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  headless: 'new',
  args: ['--no-sandbox'],
})
const page = await browser.newPage()
await page.setViewport({ width: 1440, height: 900 })
await page.goto('http://127.0.0.1:5173/#/', { waitUntil: 'networkidle0' })
await page.type('#url-input', 'https://example.com', { delay: 3 })
await page.evaluate(() =>
  [...document.querySelectorAll('button')]
    .find((x) => x.innerText.includes('Analyze Link'))
    .click(),
)
await new Promise((r) => setTimeout(r, 900))

const faded = await page.evaluate(() => {
  const out = []
  document.querySelectorAll('main *').forEach((el) => {
    const cs = getComputedStyle(el)
    if (cs.opacity === '1') return
    if (el.closest('[aria-hidden="true"]')) return // decorative only
    out.push({
      tag: el.tagName,
      cls: String(el.className).slice(0, 60),
      opacity: cs.opacity,
      text: (el.innerText || '').slice(0, 30),
    })
  })
  return out
})
console.log('Faded non-decorative elements in loading state:', JSON.stringify(faded, null, 1))
await browser.close()
