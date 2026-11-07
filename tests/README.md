# Armorly test harness

Playwright-driven tests that load the built extension into a real Chromium
and exercise it against local fixture pages. Run locally:

```bash
npm install
npx playwright install --with-deps chromium
npm test
```

`npm test` runs `./build.sh chrome` first via the `pretest` hook, so the
`build/` directory the test loads from is always fresh.

## What's covered

- **SDK global-object interception** — `window.Koah` becomes a no-op proxy.
- **DOM ad removal** — `[data-sponsored="true"]` and `[data-koah-ad]` are
  deleted by the selector pass.
- **Imprezia real markup** — every ad format, captured verbatim from
  Imprezia's own playground (demo.imprezia.ai), is hidden both inside and
  outside the SDK's viewability wrapper; inline sponsored links are
  unwrapped to plain text.
- **Real SDK captures** — 101 ad formats captured verbatim from the real
  SDKs of Koah, Imprezia, Kontext, Gravity, Thrad, ZeroClick, Lulu,
  ChatAds and EarnLayer (`tests/fixtures/captures/`), plus Lulu's MCP-app
  frame documents (`tests/fixtures/captures-frames/`, also loaded inside
  `srcdoc` iframes). Every one must end up hidden.
- **No page breakage** — ordinary page globals (`var sponsored`) are left
  alone, and proxied SDK calls resolve to a destructurable "no ad" result.
- **Vendor sites exempt** — network rules don't block a vendor's own docs
  and dashboards.
- **No React crashes** — ads are hidden, not detached, so a framework that
  later calls `removeChild` on them doesn't throw and blank the app.
- **AI ad networks** — Imprezia (bundled SDK behind a same-origin proxy),
  Kontext, Gravity, EarnLayer and Lulu ad markup is removed; every
  ad-network domain is blocked by a DNR rule; Thrad and Gravity globals
  become no-op proxies.
- **First-party chatbot ads** — ChatGPT and Copilot ad units are removed
  when the fixture is served on the real hostname via `page.route`.
- **Affiliate-link cleaning** — `tag=` and `utm_source=` are stripped from
  hrefs; unrelated query params are preserved.
- **Hidden prompt-injection shield** — white-on-white text containing a
  known injection phrase is emptied; visible body content is left alone.
- **Server-side / OpenRTB ads** (`server-side-ads.spec.ts`). `serve.js`
  acts as a chatbot backend that stitches ads into JSON, SSE, NDJSON,
  AI-SDK, WebSocket (text, binary, Socket.IO), EventSource, XHR, RSC,
  streamed-array, XSSI and Anthropic-style responses (14 channels), and
  counts every hit on its tracker URLs. A control run without the extension proves every ad
  renders and every tracker fires; the Armorly run asserts no ad renders,
  no tracker reaches the server, ordinary analytics still does, disclosed
  HTML ad cards (zero-width / lookalike / split labels, closed shadow
  roots, srcdoc iframes) are hidden while neighbouring content and
  look-alike negatives stay, and a page can't forge the "disable" message.
- **Signature unit tests** (`unit/signatures.test.js`, `npm run
  test:unit`). Tables of real ad shapes that must match and everyday
  chat/web JSON and text that must not.
- **DOM hardening** (`fixtures/dom-hardening.html`): ads streamed before
  the answer, answers streaming into an ad's wrapper, localized and
  CSS-drawn labels, carousels, `<details>`, frame ads, paid inline links,
  and look-alike negatives (glossaries, headings, table headers,
  settings switches).
- **Resilience scorecard** (`resilience.spec.ts`): the 101 real SDK
  captures run against a build with every network-specific rule removed;
  prints how many the generic layers still hide and enforces a floor.

## What's NOT covered

- **Real chatbot landing pages** (ChatGPT, Perplexity, Claude, Gemini, Grok).
  These are flaky in CI: they need a recorded Playwright `storageState` per
  account, change layout often, and rate-limit unauthenticated traffic.
  Run them manually before a release if you've changed selector logic.
- **The popup UI.** It's straightforward DOM, and exercising it would
  require either an extension ID lookup or an end-to-end Chrome
  automation that doesn't add much over manual verification.
- **The background service worker's daily pattern fetch** (Phase 4.4).
  The `chrome.alarms` API doesn't accept sub-minute periods, so any test
  here would be a stub.

## Headless

The harness launches Chromium with `headless: true, channel: 'chromium'`,
which is Chromium's "new" headless mode and loads MV3 extensions. No
window opens locally and CI doesn't need `xvfb`.
