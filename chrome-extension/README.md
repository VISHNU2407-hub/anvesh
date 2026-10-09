# URL Lens — Chrome Extension (Manifest V3)

Checks links against your **LinkShield AI FastAPI backend** (`POST /api/analyze`) before you open them.

| Score & evidence | Behavior |
|---|---|
| 0–29, no escalation | Navigate normally (unverified results get a `?` badge) |
| 30–65, or `suspicious` verdict | Warning page: hostname, score, reasons, **Go Back** + **Continue Anyway** |
| > 65, `risk_level: high`, `confirmed_malicious`, `threat_detected` | Block page: reasons + **Go Back to Safety** only — no bypass |

Plain JavaScript, no build step, no npm dependencies. Decision logic lives in `lib/` and is covered by Node tests (79) plus an optional real-Chrome E2E (10 scenarios).

## 1. Setup

**Backend:**

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env      # optional: GOOGLE_SAFE_BROWSING_API_KEY
uvicorn app.main:app --reload
```

Check: `curl http://127.0.0.1:8000/health`

**Load the extension:**

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. **Load unpacked** → select this `chrome-extension/` folder

Reload the unpacked extension after every code change; service-worker logs are under “service worker”.

## 2. Backend configuration

Popup → ⚙ (or right-click icon → Options):

| Setting | Default |
|---|---|
| Backend URL | `http://127.0.0.1:8000` (any http(s) origin) |
| Scan timeout | 8000 ms (1000–30000) |
| Links to protect | cross-origin (or all links) |

The loopback origins ship as required host permissions; any other origin is an **optional** permission requested when you save.

## 3. How it works

```
link click ─► content script (capture phase)
               preventDefault() before navigation
               ─► background: POST {backend}/api/analyze
               ◄─ allow → navigate | warn/block → local warning page

address bar / redirects ─► webNavigation.onBeforeNavigate
               analyze concurrently, swap tab to warning page if flagged
               (best-effort race — see limitations)
```

- **Policy** (`lib/policy.js`): block = `confirmed_malicious` / `threat_detected` / `risk_level high` / score > 65; warn = score 30–65 / `suspicious` / `risk_level medium`; else allow. `unknown`/`unavailable` is **never** treated as safe — it allows low-score navigation but is always marked *unverified* (badge `?`, popup banner, interstitial banner).
- **Fail-open**: timeout / backend down / malformed response → navigation proceeds, marked unverified.
- **Caching**: 5-min per-URL cache + in-flight dedupe (`chrome.storage.session`); “Continue Anyway” records a 30-min approval that survives service-worker restarts — no re-scan storms, no redirect loops. Continue uses `location.replace()` so Back skips the warning page.

## 4. Permissions

```json
"permissions": ["storage", "webNavigation"],
"host_permissions": ["http://127.0.0.1:8000/*", "http://localhost:8000/*"],
"optional_host_permissions": ["http://*/*", "https://*/*"]
```

| Permission | Why |
|---|---|
| `storage` | settings + scan cache/approvals |
| `webNavigation` | observe navigations the click interceptor can't stop (best-effort) |
| loopback host permissions | call your local backend without CORS issues |
| `optional_host_permissions` | custom backend origins, granted only on save |
| content script on `http(s)://*/*` | the core feature — intercept clicks automatically; `activeTab` can't do this without a prior gesture |

Security invariants (test-enforced): destination URLs go **only** in the JSON body of `POST /api/analyze` (never fetched/opened by the extension, `redirect: "error"`); no API keys in any extension file; MV3 CSP `script-src 'self'`; `chrome://`/`file:`/`about:` URLs never reach the API.

## 5. Protection coverage (honest)

| Surface | Coverage |
|---|---|
| Left-click / Ctrl-click / middle-click / `target="_blank"` / Enter on an external link | ✅ **Blocked before navigation** until analysis resolves |
| Repeated clicks, double-fire | ✅ one backend call (cache + dedupe) |
| Server redirects, address-bar/typed URLs, same-site navigations, drag-and-drop | ⚠️ **Best-effort** — analyzed concurrently; flagged results swap the tab to the interstitial, but the page may start loading first. MV3 cannot cancel a navigation from an async result. |
| Links inside iframes | ⚠️ observer only (main-frame clicks intercepted) |
| `chrome://`, NTP, Web Store, extension pages | ❌ Chrome does not allow extension instrumentation |
| `<a download>`, prefetch/prerender | ❌ not interceptable |
| Full pre-navigation blocking of typed URLs | ❌ needs an external component: Chrome enterprise `URLBlocklist`, a proxy/network filter, or Chrome's built-in Safe Browsing |

## 6. Tests

```bash
npm test        # 79 unit/flow tests + live-backend integration (skips if offline)
npm run test:e2e  # optional: real Chrome via CDP Extensions.loadUnpacked (Chrome 137+)
npm run icons   # regenerate icons
```

`npm test` covers: all tiers and boundaries (29/30/65/66), confirmed-malicious with low score, unknown/unavailable, timeout, network down, malformed responses, repeated clicks, redirects + approvals, Continue/Back, block-tier continuation refusal, escaping, secrets/manifest guardrails.

`npm run test:e2e` drives real clicks in headless Chrome and asserts the interstitial DOM, Continue/Back, no-bypass block page, dedupe, and fail-open.

## 7. Manual test steps

Backend running, extension loaded:

1. **Allow + `?` badge** — click any link to `https://example.com` → opens normally; popup shows “Not verified”.
2. **Popup states** — stop the backend → scan → *Backend unavailable*; set backend `http://10.255.255.1:8000` → *Scan timed out*; run `node -e "require('http').createServer((q,s)=>{s.writeHead(200,{'Content-Type':'application/json'});s.end('{\"hello\":1}')}).listen(8001)"`, point settings at `http://127.0.0.1:8001` → *Invalid response*. Restore `:8000`.
3. **Warning tier** — preview with curl:
   `curl -X POST http://127.0.0.1:8000/api/analyze -H "Content-Type: application/json" -d '{"url": "http://2130706433/"}'`
   then click a link to that URL → warning page; *Go Back* returns, *Continue Anyway* opens it.
4. **Block tier** — with a GSB key configured, click Google's test URL `http://malware.test.example/` → block page, no Continue button.
5. **Repeated clicks** — click the same flagged link 3× quickly → one `POST /api/analyze` in `backend/uvicorn.log`.
6. **Redirects** — `node -e "require('http').createServer((q,s)=>{s.writeHead(302,{Location:'http://2130706433/'});s.end()}).listen(8002)"`, visit `http://127.0.0.1:8002/` → warning for the redirect target; repeat after Continue → no loop.
7. **Fail-open** — with the backend stopped, click a link → it opens, badge shows `?`.

## 8. Structure

```
chrome-extension/
├── manifest.json               # MV3, minimal permissions
├── background/service_worker.js  # Chrome API wiring
├── content/content.js          # click interception
├── lib/                        # policy, api client, controller, renderers
├── warning/ popup/ options/    # local HTML/CSS/JS UIs
├── icons/ scripts/             # generated icons, e2e
├── tests/                      # node --test suite
└── README.md
```

## 9. Known limitations

- Typed URLs and redirects: best-effort only (race documented in §5).
- Browser-internal pages can't be scanned.
- Iframe link clicks and drag-to-tab are not click-intercepted.
- `unknown`/`unavailable` results are shown as *unverified* — URL Lens never claims a URL is safe without the backend's explicit `verified_safe` verdict (reserved, not currently emitted).
