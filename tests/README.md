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

## Why headed mode

MV3 extensions don't load in the default Chromium headless mode at the
time of writing. The harness launches with `headless: false` and CI
prepends `xvfb-run -a` so it works on a headless Linux runner.
