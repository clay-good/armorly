import { test, expect, chromium, type BrowserContext, type Browser, type Page } from '@playwright/test';
import path from 'node:path';

/**
 * Server-side / OpenRTB ads: the chatbot's backend runs the auction and
 * stitches the ad into its own responses, so there is no ad SDK and no
 * ad-network domain to block. tests/serve.js plays that backend and
 * counts every tracker request it receives.
 *
 * Each scenario runs twice against the same fixture:
 *   - control: plain headless Chromium, no extension. Proves every ad
 *     renders and every tracker reaches the server (the fixture is a real
 *     adversary, not a strawman).
 *   - armorly: same page with the extension loaded. No ad may render, no
 *     ad tracker may reach the server, and legitimate content/analytics
 *     must be untouched.
 *
 * Fully headless: Chromium's new headless mode (channel 'chromium') loads
 * MV3 extensions, so no window opens and CI doesn't need xvfb for this file.
 */

const extensionPath = path.resolve(__dirname, '..', 'build');
const ORIGIN = 'http://127.0.0.1:8421';
const PAGE = `${ORIGIN}/server-side-ads.html`;
const CHANNELS = ['json', 'sse', 'ndjson', 'aisdk', 'ws', 'eventsource', 'xhr'];

let armorly: BrowserContext;
let plain: Browser;

test.beforeAll(async () => {
  armorly = await chromium.launchPersistentContext('', {
    headless: true,
    channel: 'chromium',
    args: [`--disable-extensions-except=${extensionPath}`, `--load-extension=${extensionPath}`]
  });
  plain = await chromium.launch({ headless: true, channel: 'chromium' });
});

test.afterAll(async () => {
  await armorly?.close();
  await plain?.close();
});

async function resetHits() {
  await fetch(`${ORIGIN}/__reset`);
}

async function getHits(): Promise<Record<string, number>> {
  return (await fetch(`${ORIGIN}/__hits`)).json();
}

async function runScenario(page: Page) {
  await resetHits();
  await page.goto(PAGE);
  await page.evaluate(() => (window as any).runAll());
  // Let the DOM pass (100ms debounce) settle.
  await page.waitForTimeout(400);
  return getHits();
}

// Every tracker key the backend hands out, and the first-party ad events.
const AD_TRACKER_HITS = [
  'imp:json', 'imp:sse', 'view:sse', 'imp:sse-named', 'win:ndjson', 'bill:ndjson',
  'view:aisdk', 'win:ws', 'imp:xhr', 'imp:reuse', 'js:macro',
  'collect:ad_impression', 'collect:impression', 'api/telemetry:render'
];

test('control: without Armorly every server-side ad renders and every tracker fires', async () => {
  const page = await plain.newPage();
  const hits = await runScenario(page);

  for (const ch of CHANNELS) {
    await expect(page.locator(`#out-${ch}`), `channel ${ch}`).toContainText('AD:');
  }
  for (const key of AD_TRACKER_HITS) {
    expect(hits[key] || 0, `tracker ${key}`).toBeGreaterThan(0);
  }
  expect(hits['collect:page_view']).toBe(1);
  await expect(page.locator('#ad-card-zero-width')).toBeVisible();
  await page.close();
});

test('armorly: ads are stripped from JSON, SSE, NDJSON, AI-SDK, WebSocket, EventSource and XHR payloads', async () => {
  const page = await armorly.newPage();
  await runScenario(page);

  for (const ch of CHANNELS) {
    const out = page.locator(`#out-${ch}`);
    await expect(out, `channel ${ch} kept the real answer`).toContainText(/Logitech MX Master 3S|MX Master 3S review/);
    await expect(out, `channel ${ch} dropped the ad`).not.toContainText('AD:');
  }
  await page.close();
});

test('armorly: no proof of delivery reaches the ad server, ordinary analytics still does', async () => {
  const page = await armorly.newPage();
  const hits = await runScenario(page);

  for (const key of AD_TRACKER_HITS) {
    expect(hits[key] || 0, `tracker ${key}`).toBe(0);
  }
  expect(hits['collect:page_view'], 'non-ad analytics untouched').toBe(1);

  const adApi = await page.evaluate(() => (window as any).__adApi);
  expect([null, 'absent']).toContain(adApi.runAdAuction);
  await page.close();
});

test('armorly: server-stitched HTML ads are hidden by their disclosure label, neighbours stay', async () => {
  const page = await armorly.newPage();
  await page.goto(PAGE);

  for (const id of ['ad-card-zero-width', 'ad-prefix', 'ad-card-cyrillic', 'ad-card-icon', 'ad-card-split']) {
    await expect(page.locator(`#${id}`), id).toBeHidden();
  }
  await expect(page.locator('#ad-slot')).toHaveCount(0);

  // Same message, right next to the ad: untouched.
  for (const id of ['neg-prose-1', 'neg-prose-2', 'neg-prose-3', 'neg-prose-4', 'neg-prose-5']) {
    await expect(page.locator(`#${id}`), id).toBeVisible();
  }
  // Look-alikes that must never match.
  for (const id of ['neg-nih', 'neg-promoted-job', 'neg-invoice', 'neg-card', 'neg-composer', 'neg-footer']) {
    await expect(page.locator(`#${id}`), id).toBeVisible();
  }
  await expect(page.locator('#q')).toBeVisible();

  // Closed shadow root.
  await expect
    .poll(() => page.evaluate(() => {
      const el = (window as any).__closedRoot.querySelector('#ad-shadow');
      return el.checkVisibility();
    }))
    .toBe(false);

  // Same-origin srcdoc iframe.
  const frame = page.frameLocator('#friendly');
  await expect(frame.locator('#ad-iframe')).toBeHidden();
  await expect(frame.locator('#neg-iframe')).toBeVisible();
  await page.close();
});

test('armorly: hidden ads are out of the accessibility tree that browser agents read', async () => {
  const page = await armorly.newPage();
  await runScenario(page);
  const snapshot = await page.locator('body').ariaSnapshot();
  expect(snapshot).not.toContain('AD:');
  expect(snapshot).toContain('Logitech MX Master 3S');
  await page.close();
});

test('armorly: ad click redirects go straight to the destination, ping is dropped, normal links untouched', async () => {
  const page = await armorly.newPage();
  await page.goto(PAGE);
  const redirect = page.locator('#link-redirect');
  await expect(redirect).toHaveAttribute('href', 'https://acme.example/shoes');
  await expect(redirect).not.toHaveAttribute('ping', /.*/);
  await expect(page.locator('#link-search')).toHaveAttribute('href', 'https://www.google.com/url?q=https://example.org');
  await expect(page.locator('#link-plain')).toHaveAttribute('href', 'https://example.org/article?page=2');
  await page.close();
});

test('armorly: a page cannot switch the shield off by forging the disable message', async () => {
  const page = await armorly.newPage();
  await resetHits();
  await page.goto(PAGE);
  await page.evaluate(() => {
    window.postMessage({ source: 'armorly', type: 'disable-site' }, '*');
    window.postMessage({ source: 'armorly', type: 'disable-site', key: 'guess' }, '*');
  });
  await page.waitForTimeout(100);
  await page.evaluate(() => (window as any).runAll());
  await expect(page.locator('#out-json')).not.toContainText('AD:');
  expect((await getHits())['imp:json'] || 0).toBe(0);
  await page.close();
});

test('armorly: per-site disable really turns the shield off (user escape hatch)', async () => {
  let [worker] = armorly.serviceWorkers();
  if (!worker) worker = await armorly.waitForEvent('serviceworker');
  await worker.evaluate(() => chrome.storage.local.set({ disabled_domains: ['127.0.0.1'] }));
  try {
    const page = await armorly.newPage();
    const hits = await runScenario(page);
    await expect(page.locator('#out-json')).toContainText('AD:');
    expect(hits['imp:json']).toBeGreaterThan(0);
    await page.close();
  } finally {
    await worker.evaluate(() => chrome.storage.local.set({ disabled_domains: [] }));
  }
});
