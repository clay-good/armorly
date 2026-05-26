import { defineConfig } from '@playwright/test';

/**
 * Playwright config for Armorly's extension tests (SPEC.md Phase 2).
 *
 * The harness loads the built extension via `chromium.launchPersistentContext`
 * inside the test file; Playwright's default `chromium` browser doesn't load
 * extensions on its own. See tests/extension.spec.ts for the launch.
 *
 * Real-chatbot smoke tests (ChatGPT / Perplexity / Claude / Gemini landing
 * pages) are intentionally NOT in this config — they need a recorded
 * `storageState` per chatbot and are too flaky for CI. See tests/README.md.
 */
export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['github'], ['list']] : 'list',
  use: {
    // `npm run demo` forces video on for the @demo-tagged walkthrough so
    // the resulting webm can drive the Chrome Web Store listing recording
    // (SPEC.md Phase 3). Regular `npm test` keeps video on failure only.
    video: process.env.ARMORLY_DEMO ? 'on' : 'retain-on-failure',
    trace: 'retain-on-failure'
  },
  // Boots a tiny static server for the fixture pages. We avoid pulling in
  // `serve` or `http-server` to keep devDependencies to just Playwright.
  webServer: {
    command: 'node tests/serve.js',
    url: 'http://127.0.0.1:8421/',
    reuseExistingServer: !process.env.CI,
    stdout: 'ignore',
    stderr: 'pipe'
  }
});
