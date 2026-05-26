import { test, expect, chromium, type BrowserContext } from '@playwright/test';
import path from 'node:path';

/**
 * Armorly extension tests (SPEC.md Phase 2).
 *
 * Fixture-only: every test loads a page from the local static server
 * (tests/serve.js) so behavior is deterministic. Real-chatbot landing
 * pages are NOT in this file — see tests/README.md for why.
 *
 * The extension is loaded via launchPersistentContext because the
 * default Playwright `chromium` browser doesn't load extensions on
 * its own. CI runs this under xvfb because MV3 extension loading
 * requires a display server.
 */

const extensionPath = path.resolve(__dirname, '..', 'build');
const FIXTURES = 'http://127.0.0.1:8421';

let context: BrowserContext;

test.beforeAll(async () => {
  context = await chromium.launchPersistentContext('', {
    headless: false,
    args: [
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`,
      '--no-sandbox',
      '--disable-dev-shm-usage'
    ],
    // `npm run demo` records a walkthrough video for the Chrome Web Store
    // listing (SPEC.md Phase 3). Playwright's `use.video` config doesn't
    // apply to manually-launched persistent contexts, so we wire it here.
    ...(process.env.ARMORLY_DEMO
      ? { recordVideo: { dir: 'test-results/demo', size: { width: 1280, height: 720 } } }
      : {})
  });
});

test.afterAll(async () => {
  await context?.close();
});

test('SDK global-object interception installs a no-op Koah proxy', async () => {
  const page = await context.newPage();
  await page.goto(`${FIXTURES}/fake-ads.html`);
  await page.waitForFunction(() => (window as any).__armorlyProbeDone === true, undefined, { timeout: 5000 });

  expect(await page.evaluate(() => (window as any).__koahInstalled)).toBe(true);

  // The proxy returns Promise.resolve() for any method call. Check
  // thenability inside the page — Playwright auto-awaits any Promise
  // returned from page.evaluate, which would collapse it to undefined.
  const isThenable = await page.evaluate(() => {
    const r = (window as any).__koahInitResult;
    return r !== null && typeof r === 'object' && typeof r.then === 'function';
  });
  expect(isThenable).toBe(true);
});

test('DOM-removal pass deletes [data-sponsored="true"] and [data-koah-ad]', async () => {
  const page = await context.newPage();
  await page.goto(`${FIXTURES}/fake-ads.html`);

  await page.waitForFunction(
    () => !document.querySelector('#sponsored-flag') && !document.querySelector('#koah-ad'),
    undefined,
    { timeout: 5000 }
  );

  expect(await page.locator('#sponsored-flag').count()).toBe(0);
  expect(await page.locator('#koah-ad').count()).toBe(0);
});

test('affiliate-link cleaning strips tag= and utm_source= but keeps unrelated params', async () => {
  const page = await context.newPage();
  await page.goto(`${FIXTURES}/fake-ads.html`);

  // Wait until the content script flagged the link as cleaned.
  await page.waitForFunction(
    () => {
      const a = document.querySelector('#affiliate-link') as HTMLAnchorElement | null;
      return !!a && a.hasAttribute('data-armorly-cleaned');
    },
    undefined,
    { timeout: 5000 }
  );

  const href = await page.locator('#affiliate-link').getAttribute('href');
  expect(href).not.toBeNull();
  expect(href!).not.toContain('tag=');
  expect(href!).not.toContain('utm_source=');
  expect(href!).toContain('keep=yes');
});

// Phase 2.5 / Phase 3: a single end-to-end test tagged `@demo` that walks a
// ChatGPT-styled mock page through "Armorly off" -> "Armorly on", suitable
// for the README hero video. Run with `npm run demo` to enable video at
// 1280x720; the webm lands in test-results/demo/.
//
// Storyboard (~8 seconds):
//   t=0.0-2.5s   chatgpt-mock.html, Armorly disabled for this host
//                via chrome.storage. Sponsored "PrecisionGlide" card visible.
//                Pill in the corner reads "Armorly OFF" (red).
//   t=2.5-3.0s   service worker clears `disabled_domains` and the page reloads.
//   t=3.0-8.0s   Same page, now with Armorly active. Sponsored card is gone;
//                affiliate `tag=`/`utm_*` params on the inline link are
//                stripped. Pill reads "Armorly ON" (green).
test('@demo end-to-end ChatGPT-mock walkthrough for the hero video', async () => {
  // Find the extension service worker so we can drive chrome.storage from
  // the test. MV3 spins it up lazily — wait for it if it isn't there yet.
  let [worker] = context.serviceWorkers();
  if (!worker) worker = await context.waitForEvent('serviceworker');

  // Phase 1: Armorly disabled for localhost so the ad stays put.
  await worker.evaluate(() =>
    chrome.storage.local.set({ disabled_domains: ['127.0.0.1', 'localhost'] })
  );

  const page = await context.newPage();
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.goto(`${FIXTURES}/chatgpt-mock.html`);
  // Sanity: the sponsored card is visible while Armorly is off.
  await expect(page.locator('.sponsored')).toBeVisible();
  // Hold the "before" state long enough for the recording to land it.
  await page.waitForTimeout(2500);

  // Phase 2: enable Armorly and reload to show the cleanup happening.
  await worker.evaluate(() =>
    chrome.storage.local.set({ disabled_domains: [] })
  );
  await page.evaluate(() => {
    const pill = document.getElementById('status-pill');
    if (pill) { pill.textContent = 'Armorly ON'; pill.classList.add('on'); }
  });
  await page.reload();

  // After reload the page's status pill JS doesn't run (it's a static label),
  // so we re-apply the "on" state via page.evaluate before holding the frame.
  await page.evaluate(() => {
    const pill = document.getElementById('status-pill');
    if (pill) { pill.textContent = 'Armorly ON'; pill.classList.add('on'); }
  });

  // The sponsored card should be removed by the DOM-removal pass.
  await expect(page.locator('.sponsored')).toHaveCount(0, { timeout: 5000 });
  // Hold the "after" state.
  await page.waitForTimeout(5000);

  // Restore the disabled-domains list so other tests aren't affected.
  await worker.evaluate(() => chrome.storage.local.set({ disabled_domains: [] }));
});

test('hidden-content shield empties white-on-white injection but leaves visible content', async () => {
  const page = await context.newPage();
  await page.goto(`${FIXTURES}/hidden-injection.html`);

  await page.waitForFunction(
    () => {
      const el = document.querySelector('#hidden-injection');
      return !!el && el.textContent!.trim() === '';
    },
    undefined,
    { timeout: 5000 }
  );

  // Sentinel: legitimate body content must be untouched.
  await expect(page.locator('text=This sentinel paragraph is also visible')).toBeVisible();
});
