# LinkShield AI — Chrome Extension (Manifest V3)

Protects users from suspicious and malicious URLs by checking them against
your **LinkShield AI FastAPI backend** (`POST /api/analyze`) and applying a
risk-tiered navigation policy:

| Score (and evidence)                    | Behavior |
|-----------------------------------------|----------|
| 0–29, no escalation trigger             | Navigate normally (badge/popup mark unverified results) |
| 30–65 inclusive, or `suspicious` verdict| Full-page warning: destination hostname, score, reasons, **Go Back** + **Continue Anyway** |
| > 65, `risk_level: high`, `confirmed_malicious`, or `reputation_status: threat_detected` | Full-page block: reasons + **Go Back to Safety** only — no bypass button |

Written in **plain modern JavaScript (ES modules)** — no build step, no npm
dependencies. You load the directory straight from `chrome://extensions`.
All decision logic lives in dependency-injected `lib/` modules covered by a
Node test suite (76 tests, `node --test`).

---

## 1. Setup

### 1.1 Start the backend

```bash
cd backend
python -m venv .venv
# macOS/Linux: source .venv/bin/activate   Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env      # optional: set GOOGLE_SAFE_BROWSING_API_KEY
uvicorn app.main:app --reload
```

Verify:

```bash
curl http://127.0.0.1:8000/health
curl -X POST http://127.0.0.1:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/"}'
```

The Google Safe Browsing key stays **server-side only**. The extension never
contains it (enforced by `tests/secrets.test.js`), and the backend never
returns it.

### 1.2 Load the extension

1. Open `chrome://extensions` in Chrome.
2. Enable **Developer mode** (toggle, top right).
3. Click **Load unpacked** and select this `chrome-extension/` directory.
4. Pin the LinkShield AI shield icon to the toolbar.

> Re-load the unpacked extension from `chrome://extensions` after every code
> change (service-worker logs are visible under “service worker”).

---

## 2. Backend configuration

Open the popup → ⚙ **Settings** (or right-click the toolbar icon →
Options):

| Setting | Default | Notes |
|---|---|---|
| Backend base URL | `http://127.0.0.1:8000` | Any `http(s)` origin. Saved to `chrome.storage.sync`. |
| Scan timeout | `8000` ms (1000–30000) | When `POST /api/analyze` does not answer in time, the scan is reported as **timed out**. |
| Links to protect | `cross-origin` | `cross-origin` checks links leaving the current site; `all` also checks same-site links. |

The default backend origins (`http://127.0.0.1:8000`, `http://localhost:8000`)
ship as **required** host permissions. If you save any other origin, Chrome
asks for an **optional** host permission for it at save time (user gesture);
scans fail with “Backend unavailable” until granted.

---

## 3. How it works (and where)

```
page click  ──► content/content.js (capture phase, document_start)
                  preventDefault() + stopImmediatePropagation()
                  ──► background/service_worker.js
                        POST {backend}/api/analyze   (URL only in the body)
                        decide(): allow | warn | block
                  ◄── allow: navigate (same tab / new tab / new window)
                  ◄── warn/block: swap tab → warning/warning.html

address-bar, server redirects, drag-and-drop ──► webNavigation.onBeforeNavigate
                  analyze concurrently (cannot cancel the navigation in MV3)
                  ◄── warn/block: replace the tab with the interstitial
                        (best-effort race — see limitations)
```

- **Popup** (`popup/`): *Scan Current Page* button, verdict chip, score bar,
  risk level, findings, advice, plus explicit **loading / timeout /
  backend-unavailable / invalid-response / bad-request** states.
- **Warning page** (`warning/`): local HTML/CSS/JS interstitial. URL data is
  rendered exclusively via `textContent` (tests make `innerHTML` usage throw).
  “Continue Anyway” exists **only** for the medium tier, and the background
  independently refuses `warning:continue` for block-tier cases (tested).
- **Fail-open, never fail-silent**: if a scan fails (timeout, backend down,
  malformed JSON/schema), navigation is allowed but the result is marked
  **UNVERIFIED** — toolbar badge `?`, popup banner, interstitial banner. An
  `unknown`/`unavailable` result is **never** presented as safe.
- **Repeated clicks & redirects**: analysis results are cached per URL
  (5 min TTL, `chrome.storage.session`) with in-flight deduplication, and
  “Continue Anyway” records a 30-minute session approval. Approvals survive
  MV3 service-worker restarts, which is what prevents re-scan storms and
  redirect ping-pong (the interstitial never navigates on its own; every
  approval is one-shot per navigation attempt).
- **Continue Anyway** is performed by the warning page itself with
  `location.replace()`, so the interstitial leaves the tab's back history:
  pressing Back on the destination returns straight to the page you came from.
- **Observer scope**: the `webNavigation` observer analyzes *every* main-frame
  http(s) navigation (address bar, redirects, same-site navigations,
  drag-and-drop) — not just cross-origin ones. Click interception respects the
  “Links to protect” setting; the observer does not, because from a
  navigation event it cannot know where the URL came from. Non-flagged results
  are allowed silently, so ordinary same-site browsing is unaffected.

### Risk policy details (documented, deterministic — `lib/policy.js`)

- Block: `verdict == confirmed_malicious` OR `reputation_status ==
  threat_detected` OR `risk_level == high` OR `score > 65`.
- Warn: `30 ≤ score ≤ 65` OR `verdict == suspicious` (verdict escalation —
  a strong detection finding is never waved through on score arithmetic
  alone) OR `risk_level == medium`.
- Allow: everything else (score ≤ 29 without escalation).
- `unknown` / `unavailable` → **never verified safe**. They allow
  low-score navigation (the backend reports `verdict: unknown` for
  essentially every benign URL — routing all of them through an interstitial
  would warn on nearly every click), but every such result carries
  `unverified: true`, which the badge, popup and interstitial all surface.

---

## 4. Permissions (minimal) and security

```json
"permissions": ["storage", "webNavigation"],
"host_permissions": ["http://127.0.0.1:8000/*", "http://localhost:8000/*"],
"optional_host_permissions": ["http://*/*", "https://*/*"]
```

| Permission | Why it is needed |
|---|---|
| `storage` | Settings (`sync`); scan cache, approvals, interstitial cases (`session`) |
| `webNavigation` | Observe main-frame navigations the click interceptor cannot stop (address bar, redirects) — best-effort analysis only |
| `host_permissions` (default backend) | Lets the service worker call your local backend without CORS problems. Only the two loopback origins are required. |
| `optional_host_permissions` | So a *custom* backend origin can be granted later, only on explicit user consent at save time |
| Content script on `http(s)://*/*` | The core feature: intercept clicks on external links **before** navigation. This is why Chrome shows “Read and change all your data on all websites” — automatic link protection cannot be limited to `activeTab` because it must run without a prior user gesture on the extension. |

Security invariants (test-enforced):

- The destination URL is only ever sent **inside the JSON body** of
  `POST {backend}/api/analyze`. The extension never fetches, opens, or
  pre-renders the analyzed URL; backend redirects are refused
  (`redirect: "error"`).
- No Google Safe Browsing key or other secret exists in any extension file.
- Manifest V3 CSP only (`script-src 'self'`): no remote code, no inline
  scripts; all UI is local HTML/CSS/JS.
- `chrome://`, `chrome-extension://`, `about:`, `file:` and `view-source:`
  URLs never reach the analysis API (tested).

---

## 5. Protection coverage — honest report

| Surface | Coverage | Mechanism |
|---|---|---|
| Left-click on an external link | ✅ **Strong** — navigation fully blocked until the analysis resolves | Capture-phase `preventDefault()` + `stopImmediatePropagation()` registered at `document_start` (page handlers cannot re-trigger it) |
| Ctrl/Cmd-click, middle-click, `target="_blank"` | ✅ Strong — new tab/window opens only after the decision (warning page opens instead when flagged) | Same interception; intent forwarded to the background |
| Keyboard Enter on a focused link | ✅ Covered (browsers dispatch a `click` event) | Same path |
| Repeated clicks / double-fire | ✅ Deduplicated (in-flight + cache) | One backend call per URL per cache TTL |
| Server-side redirects after an allowed navigation | ⚠️ **Best-effort** — the redirect target is analyzed and the tab replaced with the interstitial if flagged, racing the page load | `webNavigation.onBeforeNavigate` cannot be cancelled in MV3 |
| Address-bar / typed URLs | ⚠️ **Best-effort only** — analyzed concurrently; flagged results swap the tab to the interstitial, but the destination may start loading first | Same observer; **Chrome MV3 offers no API to cancel a navigation based on an async result** |
| Drag-and-drop of a link into the tab bar | ⚠️ Not intercepted by the click handler; only the best-effort observer applies | — |
| Links inside iframes | ⚠️ Click interception is main-frame only (`all_frames: false`); iframe/redirect navigations only get the best-effort observer | Delimited to keep risk/complexity low |
| `chrome://` pages, new tab page, extension pages, Web Store | ❌ Cannot be instrumented by extensions | Chrome platform restriction |
| Downloads (`<a download>`), drag-to-download | ❌ Not navigations; not intercepted | Documented |
| Prefetch / prerender of a destination by the page | ❌ Cannot be cancelled | Chrome platform restriction |
| Full pre-navigation blocking of typed URLs | ❌ **Not achievable with an extension alone** — see below | — |

### Why address-bar blocking cannot be complete (no faking)

Manifest V3 removed blocking `webRequest`, and no supported extension API
lets you **await an HTTP call and then cancel** a navigation that Chrome has
already started. The strongest genuinely-supported MV3 protection is what this
extension implements: (a) hard pre-navigation interception of *clicked* links,
plus (b) racing analysis + tab replacement for everything else. The race in
(b) is real and disclosed: a very fast malicious page may begin loading
before the interstitial replaces it.

If complete pre-navigation blocking of typed URLs is required, you need an
additional component **outside** the extension, for example:

1. **Chrome enterprise policy** — `URLBlocklist` / `URLAllowlist` (static
   lists pushed by an administrator, enforced by the browser itself), or
2. A **local proxy / secure-DNS or network filter** that consults the
   LinkShield API before forwarding requests (blocks before any bytes reach
   the destination), or
3. Chrome's built-in **Safe Browsing** real-time checks (browser-level, not
   extension-controlled).

---

## 6. Running the tests

### Unit + flow tests (default)

```bash
cd chrome-extension
npm test          # = node --test tests/*.test.js   (requires Node 18+)
```

No dependencies to install. The suite covers:

- **Tier policy** — low (0/15/29), medium (30/50/65), high (66/100),
  `confirmed_malicious` with a *low* score, `reputation_status:
  threat_detected`, `risk_level: high`, `suspicious` verdict escalation,
  `unknown`, `unavailable`, `verified_safe` (reserved).
- **Malformed responses** — non-object, wrong enums, string/out-of-range/NaN
  score, non-array findings, findings without titles.
- **Failure modes** — timeout, network refused, HTTP 400/500, non-JSON,
  wrong schema → explicit failure records that are *unverified*, never safe.
- **Flows** — concurrent/repeated clicks (one backend call), redirect chains,
  Continue Anyway approval, block-tier continuation refusal, back navigation,
  stale-result race guard, service-worker restart persistence, iframe/internal
  URL exclusion.
- **Rendering** — continue button absent for the block tier, `innerHTML`
  forbidden, hostname/score/banner rendering, back-button fallback.
- **Guardrails** — no secrets in the extension, manifest permissions pinned.
- **Live integration** (`tests/integration.live.test.js`) — runs the real
  controller against the real FastAPI backend on `http://127.0.0.1:8000` when
  it is up, proving the extension's schema validation and tier policy against
  the actual API; skips automatically when the backend is offline.

Regenerate icons (no dependencies): `npm run icons`.

### Real-browser end-to-end test (optional)

```bash
npm run test:e2e   # needs Chrome installed; CHROME_PATH=/path/to/chrome to override
```

Launches headless Chrome and loads the unpacked extension through the
Chrome-137+-supported CDP method `Extensions.loadUnpacked`
(`--remote-debugging-pipe --enable-unsafe-extension-debugging` — the
`--load-extension` flag was removed from branded builds), then drives real
page clicks and asserts, in a real DOM: allow-navigation, non-protected link
passthrough, the medium interstitial (hostname, score, reasons, unverified
banner, Continue + Go Back), Continue → destination → Back to source, the
block interstitial (**no** Continue button, forged `warning:continue`
refused, *Go Back to Safety*), rapid double-click = one backend scan, and
fail-open on malformed responses / backend downtime. A local fake backend
provides deterministic tier responses; `npm test` stays the offline-safe
suite.

---

## 7. Manual test steps

Prerequisites: backend running on `http://127.0.0.1:8000`, extension loaded.

1. **Benign / unverified (allow + badge `?`)**
   Visit any site and click a link to `https://example.com` → navigation
   proceeds. Toolbar badge shows `?`; popup shows the green/allow chip **plus**
   the “Not verified as safe” banner.
2. **Popup states**
   - Stop the backend → popup → *Scan Current Page* → **Backend unavailable**
     with a hint to start uvicorn.
   - Settings → Backend URL `http://10.255.255.1:8000` (non-routable) →
     scan → **Scan timed out**.
   - Run a fake backend returning garbage:
     `node -e "require('http').createServer((q,s)=>{s.writeHead(200,{'Content-Type':'application/json'});s.end('{\"hello\":1}')}).listen(8001)"`
     → set backend URL to `http://127.0.0.1:8001` (grant the permission when
     prompted) → scan → **Invalid backend response**.
   - Restore `http://127.0.0.1:8000`.
3. **Warning tier (score 30–65)**
   Predict the score first:
   `curl -X POST http://127.0.0.1:8000/api/analyze -H "Content-Type: application/json" -d '{"url": "http://2130706433/"}'`
   (a numeric-IP host usually yields a high-severity finding → score ≥ 30).
   Put that URL behind a link on any page and click it → **warning page** with
   hostname, score, reasons, *Go Back* and *Continue Anyway*.
   - *Go Back* returns to the original page.
   - *Continue Anyway* navigates to the destination; clicking the same link
     again warns again (approvals only suppress the passive observer, never a
     fresh click).
   - `verdict: suspicious` links also reach this tier even below score 30
     (e.g. plain-`http` pages) — this is the documented verdict escalation.
4. **Block tier (confirmed threat)** — requires `GOOGLE_SAFE_BROWSING_API_KEY`
   in `backend/.env`. Google publishes always-matching test URLs:
   `http://malware.test.example/` and `http://phishing.test.example/`.
   Click a link to one → block interstitial with **Go Back to Safety** only —
   inspect the DOM: no “Continue” button exists, and the background refuses
   `warning:continue` for that case (`tests/controller.test.js` covers it).
5. **Repeated clicks / backend load** — click the same medium-risk link 3×
   quickly, then check `backend/uvicorn.log`: exactly one `POST /api/analyze`
   for that URL (cache TTL 5 min).
6. **Redirect handling** —
   `node -e "require('http').createServer((q,s)=>{s.writeHead(302,{Location:'http://2130706433/'});s.end()}).listen(8002)"`
   → type `http://127.0.0.1:8002/` into the address bar → the observer
   analyzes the redirect target and (best-effort) replaces the tab with the
   warning page. Repeat the navigation after “Continue” → no loop, no second
   backend call.
7. **Address-bar best-effort** — type a block-tier URL directly into the
   address bar (with a GSB key configured). The interstitial appears after
   the analysis resolves; the destination may have begun loading — this is
   the disclosed race, not full pre-navigation blocking.
8. **New-tab intents** — Ctrl/Cmd-click and middle-click flagged links → the
   warning page opens in the new tab instead of the destination.
9. **Failure fail-open** — with the backend stopped, click an external link →
   navigation still happens (documented fail-open) with the `?` badge and an
   error chip; the popup reports the scan failure as *unverified*.

---

## 8. Project structure

```
chrome-extension/
├── manifest.json              # MV3: minimal permissions, CSP
├── background/service_worker.js  # thin Chrome-API wiring (ES module SW)
├── content/content.js         # capture-phase click interception (classic script)
├── lib/
│   ├── controller.js          # orchestration: cache, approvals, redirects, races
│   ├── policy.js              # response validation + documented tier policy
│   ├── api.js                 # POST /api/analyze client (timeout, redirect:error)
│   ├── links.js               # UMD link classifier (content script + tests)
│   ├── warning-view.js        # interstitial view model + textContent renderer
│   └── util.js                # URL helpers
├── warning/                   # full-page interstitial (local HTML/CSS/JS)
├── popup/                     # toolbar popup (scan + states)
├── options/                   # backend URL / timeout / protection mode
├── icons/ + scripts/generate-icons.mjs
├── tests/                     # node --test suite (76 tests)
└── README.md
```

## 9. Known limitations (summary)

- Typed/address-bar URLs and redirects are protected **best-effort only**
  (see §5) — complete pre-navigation blocking needs enterprise policy, a
  proxy/network filter, or browser-level Safe Browsing.
- Browser-internal pages (`chrome://`, NTP, Web Store) cannot be scanned or
  protected.
- Iframe link clicks and drag-and-drop navigation are not click-intercepted.
- The interstitial covers the tab it opens in; it cannot stop a page that was
  already rendering from issuing its own requests during the analysis race.
- `unknown`/`unavailable` scans are surfaced as *unverified* (badge, popup,
  banner) — LinkShield never claims a URL is safe without the backend's
  explicit `verified_safe` verdict (currently reserved and not emitted).
