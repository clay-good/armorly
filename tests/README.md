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
- **Affiliate-link cleaning** — `tag=` and `utm_source=` are stripped from
  hrefs; unrelated query params are preserved.
- **Hidden prompt-injection shield** — white-on-white text containing a
  known injection phrase is emptied; visible body content is left alone.
- **Server-side / OpenRTB ads** (`server-side-ads.spec.ts`). `serve.js`
  acts as a chatbot backend that stitches ads into JSON, SSE, NDJSON,
  AI-SDK, WebSocket, EventSource and XHR responses, and counts every hit on
  its tracker URLs. A control run without the extension proves every ad
  renders and every tracker fires; the Armorly run asserts no ad renders,
  no tracker reaches the server, ordinary analytics still does, disclosed
  HTML ad cards (zero-width / lookalike / split labels, closed shadow
  roots, srcdoc iframes) are hidden while neighbouring content and
  look-alike negatives stay, and a page can't forge the "disable" message.
- **Signature unit tests** (`unit/signatures.test.js`, `npm run
  test:unit`). Tables of real ad shapes that must match and everyday
  chat/web JSON and text that must not.

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
