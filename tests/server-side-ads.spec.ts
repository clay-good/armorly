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
const CHANNELS = ['json', 'sse', 'ndjson', 'aisdk', 'ws', 'eventsource', 'xhr', 'io', 'bin', 'rsc', 'jsonarr', 'xssi', 'anth', 'xhrsse'];

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
  'imp:io', 'imp:bin', 'imp:rsc', 'imp:jsonarr', 'imp:xssi', 'imp:anth', 'view:html',
  'collect:ad_impression', 'collect:impression', 'collect:ad_view', 'collect:ad_click', 'api/telemetry:render'
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
  // The Anthropic-style stream stayed well-formed: no hole where the
  // sponsored block was, later blocks renumbered.
  expect(await page.evaluate(() => (window as any).__anthError)).toBeNull();
  await expect(page.locator('#out-anth')).toContainText('The Logitech MX Master 3S is the best all-round wireless mouse for a Mac.');
  await page.close();
});

test('armorly: no proof of delivery reaches the ad server, ordinary analytics still does', async () => {
  const page = await armorly.newPage();
  const hits = await runScenario(page);

  for (const key of AD_TRACKER_HITS) {
    expect(hits[key] || 0, `tracker ${key}`).toBe(0);
  }
  expect(hits['collect:page_view'], 'non-ad analytics untouched').toBe(1);
  // A poisoned ad naming the site's own API / a JSON fragment as its
  // tracker or id must not block the chat's own requests.
  expect(hits['api/echo'], 'chat send still works').toBe(1);
  expect(await page.evaluate(() => (window as any).__echo)).toMatchObject({ ok: true });
  await expect(page.locator('#out-xhr')).toContainText('MX Master 3S review');

  // The innerHTML pixel was stopped by a tab-scoped rule the background
  // learned from the removed JSON ad (no in-page hook sees parsed <img>).
  let [worker] = armorly.serviceWorkers();
  if (!worker) worker = await armorly.waitForEvent('serviceworker');
  const learned = await worker.evaluate(async () =>
    (await chrome.declarativeNetRequest.getSessionRules()).map(r => r.condition.urlFilter || ''));
  expect(learned.some(f => f.includes('src=html'))).toBe(true);

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
  await expect(page.locator('#ad-slot')).toBeHidden();

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

// ---------------------------------------------------------------------------
// DOM hardening (tests/fixtures/dom-hardening.html)
// ---------------------------------------------------------------------------

const DOM_PAGE = `${ORIGIN}/dom-hardening.html`;

test('armorly: an ad streamed before the answer is hidden mid-stream, the answer stays', async () => {
  const page = await armorly.newPage();
  await page.goto(DOM_PAGE);
  const run = page.evaluate(() => (window as any).runStream());
  // Tokens arrive every 30ms, so the page never goes quiet; the ad must
  // still be gone well before the stream ends (~2.4s).
  await page.waitForTimeout(800);
  expect(await page.evaluate(() => (window as any).__streamDone)).toBe(false);
  await expect(page.locator('#stream-ad')).toBeHidden();
  await run;
  await page.waitForTimeout(300);
  await expect(page.locator('#stream-answer')).toBeVisible();
  await expect(page.locator('#stream-answer')).toContainText('tok79');
  await page.close();
});

test('armorly: an answer streaming into the ad\'s wrapper is not swallowed', async () => {
  const page = await armorly.newPage();
  await page.goto(DOM_PAGE);
  await page.evaluate(() => (window as any).runGrow());
  await expect(page.locator('#grow-ad')).toBeHidden();
  await expect(page.locator('.grow-answer').first()).toBeVisible();
  await expect(page.locator('.grow-answer')).toHaveCount(6);
  for (const el of await page.locator('.grow-answer').all()) await expect(el).toBeVisible();
  await page.close();
});

test('armorly: localized, CSS-drawn, <details>, carousel, onclick and frame ads are hidden', async () => {
  const page = await armorly.newPage();
  await page.goto(DOM_PAGE);
  for (const id of ['ad-de-strong', 'ad-de-lang', 'ad-ja', 'ad-css', 'ad-attr', 'ad-details', 'ad-carousel', 'ad-onclick', 'sup-label']) {
    await expect(page.locator(`#${id}`), id).toBeHidden();
  }
  await expect(page.frameLocator('#frame-ad').locator('text=AD:frame')).toBeHidden();
  await expect(page.frameLocator('#frame-neg').locator('#fneg')).toBeVisible();
  for (const id of ['neg-prose-i18n', 'neg-anzeige-en', 'neg-prose-css']) {
    await expect(page.locator(`#${id}`), id).toBeVisible();
  }
  await page.close();
});

test('armorly: paid links lose their link but keep their words; the sentence stays', async () => {
  const page = await armorly.newPage();
  await page.goto(DOM_PAGE);
  // <a>Acme</a><sup>Ad</sup>: link neutralized, paragraph intact.
  await expect(page.locator('#sup-p')).toBeVisible();
  await expect(page.locator('#sup-link')).not.toHaveAttribute('href', /.*/);
  expect(await page.locator('#sup-p').evaluate(e => (e as HTMLElement).innerText)).toContain('For trail shoes, try Acme or a pair');
  // rel="sponsored" inside a chat answer: neutralized in place.
  await expect(page.locator('#rel-chat')).not.toHaveAttribute('href', /.*/);
  await expect(page.locator('#rel-p')).toHaveText('You could buy Acme boots online.');
  // rel="sponsored" in a site's own footer: not a chat ad, left alone.
  await expect(page.locator('#rel-blog')).toHaveAttribute('href', 'https://partner.example');
  // "(AD)" abbreviation after a link on an ordinary page: link untouched.
  await expect(page.locator('#neg-ad-abbr a')).toHaveAttribute('href', 'https://en.wikipedia.org/wiki/Alzheimer%27s_disease');
  await page.close();
});

test('armorly: glossaries, headings, table headers, look-alikes and settings are left alone', async () => {
  const page = await armorly.newPage();
  await page.goto(DOM_PAGE);
  await page.waitForTimeout(400);
  for (const id of ['neg-glossary', 'neg-glossary-caps', 'neg-heading', 'neg-table', 'neg-ad5', 'neg-settings', 'neg-footer', 'neg-short-answer', 'neg-ad-abbr', 'neg-affiliate-box']) {
    const el = page.locator(`#${id}`);
    await expect(el, id).toBeVisible();
    expect(await el.evaluate(e => e.querySelectorAll('[data-armorly-ad], [data-armorly-hidden]').length), id).toBe(0);
  }
  await page.close();
});
