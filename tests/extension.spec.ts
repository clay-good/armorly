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

// Phase 2.5: a single end-to-end test tagged `@demo` that walks through the
// before/after of the fixture page. Playwright records video for any test in
// `npm run demo` thanks to the `video: 'on'` override there. The output ends
// up under test-results/<test-name>/video.webm.
test('@demo end-to-end fixture walkthrough for the screen recording', async () => {
  const page = await context.newPage();
  await page.goto(`${FIXTURES}/fake-ads.html`);
  await page.waitForFunction(() => (window as any).__armorlyProbeDone === true, undefined, { timeout: 5000 });
  await page.waitForFunction(
    () => !document.querySelector('#sponsored-flag') && !document.querySelector('#koah-ad'),
    undefined,
    { timeout: 5000 }
  );
  // Hold on the cleaned fake-ads page long enough that the recording shows it.
  await page.waitForTimeout(500);
  await page.goto(`${FIXTURES}/hidden-injection.html`);
  await page.waitForFunction(
    () => {
      const el = document.querySelector('#hidden-injection');
      return !!el && el.textContent!.trim() === '';
    },
    undefined,
    { timeout: 5000 }
  );
  await page.waitForTimeout(500);
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
