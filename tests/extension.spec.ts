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
 * its own. channel 'chromium' selects Chromium's new headless mode,
 * which loads MV3 extensions without opening a window.
 */

const extensionPath = path.resolve(__dirname, '..', 'build');
const FIXTURES = 'http://127.0.0.1:8421';

let context: BrowserContext;

test.beforeAll(async () => {
  context = await chromium.launchPersistentContext('', {
    headless: true,
    channel: 'chromium',
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
      ? { recordVideo: { dir: 'test-results/demo', size: { width: 1280, height: 800 } } }
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

test('DOM-removal pass hides [data-sponsored="true"] and [data-koah-ad]', async () => {
  const page = await context.newPage();
  await page.goto(`${FIXTURES}/fake-ads.html`);

  await expect(page.locator('#sponsored-flag')).toBeHidden({ timeout: 5000 });
  await expect(page.locator('#koah-ad')).toBeHidden({ timeout: 5000 });
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
  // 1280x800 is the Chrome Web Store listing aspect — sizing the @demo
  // recording to match means the same source webm yields both the README
  // GIF and the store listing stills (extracted via scripts/make-listing-stills.sh).
  await page.setViewportSize({ width: 1280, height: 800 });
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
  await expect(page.locator('.sponsored:visible')).toHaveCount(0, { timeout: 5000 });
  // Hold the "after" state.
  await page.waitForTimeout(5000);

  // Restore the disabled-domains list so other tests aren't affected.
  await worker.evaluate(() => chrome.storage.local.set({ disabled_domains: [] }));
});

test('auto-update bridge: cached pattern SDK names reach the MAIN-world interceptor', async () => {
  // SPEC.md Phase 4.4 was originally only wired to the isolated-world script,
  // so newly-added SDK function names from the daily refresh never got
  // proxied. This test seeds a synthetic name in `cached_patterns`, opens a
  // page, and asserts the MAIN-world sdk-blocker installed a proxy for it.
  let [worker] = context.serviceWorkers();
  if (!worker) worker = await context.waitForEvent('serviceworker');

  await worker.evaluate(() =>
    chrome.storage.local.set({
      cached_patterns: {
        version: '9999-12-31', // strictly newer than BUNDLED_VERSION
        adSDKs: {
          future_network: {
            functions: ['ArmorlyAutoUpdateProbe'],
            methods: ['init'],
            domainPatterns: []
          }
        }
      }
    })
  );

  const page = await context.newPage();
  await page.goto(`${FIXTURES}/fake-ads.html`);

  // The bridge is async: ai-ad-blocker's storage callback resolves, it
  // postMessages the new function list, sdk-blocker proxies it. Allow up
  // to 5s for the round trip — typically lands in well under 100ms.
  await page.waitForFunction(
    () => typeof (window as any).ArmorlyAutoUpdateProbe !== 'undefined',
    undefined,
    { timeout: 5000 }
  );
  expect(await page.evaluate(() => typeof (window as any).ArmorlyAutoUpdateProbe)).toBe('object');

  // Cleanup so the rest of the suite isn't influenced by a fake cached snapshot.
  await worker.evaluate(() => chrome.storage.local.set({ cached_patterns: null }));
});

test('per-site disable tears down MAIN-world SDK proxies (not just DOM removal)', async () => {
  // Before this fix, flipping "Protect this site" off only gated the
  // isolated-world script — sdk-blocker.js kept its proxies installed,
  // so window.Koah was still a no-op on disabled sites. Verify the
  // disable-site bridge actually un-proxies in MAIN world.
  let [worker] = context.serviceWorkers();
  if (!worker) worker = await context.waitForEvent('serviceworker');

  await worker.evaluate(() =>
    chrome.storage.local.set({ disabled_domains: ['127.0.0.1', 'localhost'] })
  );

  const page = await context.newPage();
  await page.goto(`${FIXTURES}/fake-ads.html`);
  // sdk-blocker installs proxies synchronously at document_start; the
  // disable signal arrives a tick later via the storage round-trip. Poll
  // for window.Koah to disappear.
  await page.waitForFunction(
    () => typeof (window as any).Koah === 'undefined',
    undefined,
    { timeout: 5000 }
  );
  expect(await page.evaluate(() => typeof (window as any).Koah)).toBe('undefined');

  // Restore so other tests aren't affected.
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

test('Imprezia bundled SDK via same-origin proxy: card removed, r.imprezia.net blocked', async () => {
  // Real publishers (e.g. TravelDealz.ai) bundle the Imprezia SDK with no
  // window global and route it through a same-origin /api/proxy, so neither
  // the MAIN-world proxy nor the ||imprezia.ai^ rule fires. The card markup
  // and the r.imprezia.net tracker frame are what Armorly has to catch.
  const page = await context.newPage();
  // Every r.imprezia.net request must be stopped by Armorly: either the
  // network rule rejects it (ERR_BLOCKED_BY_CLIENT) or the payload shield
  // stops it before it is sent. A request that goes out and fails for any
  // other reason (DNS, offline) still fails the test.
  const leaked: string[] = [];
  page.on('request', (req) => {
    if (!req.url().includes('imprezia.net')) return;
    req.response().then(() => leaked.push(req.url()), () => {});
  });
  page.on('requestfailed', (req) => {
    if (req.url().includes('imprezia.net') && req.failure()?.errorText !== 'net::ERR_BLOCKED_BY_CLIENT') leaked.push(req.url());
  });

  await page.goto(`${FIXTURES}/imprezia-bundled.html`);
  await page.waitForFunction(() => (window as any).__impreziaRendered === true, undefined, { timeout: 5000 });

  await expect(page.locator('.imprezia-card:visible')).toHaveCount(0, { timeout: 5000 });
  await expect(page.locator('text=Sponsored by Trip.com >> visible=true')).toHaveCount(0);
  await page.waitForTimeout(1000);
  expect(leaked).toEqual([]);
});

test('AI ad networks: Kontext, Gravity, EarnLayer and Lulu ads removed, legit content kept', async () => {
  const page = await context.newPage();
  await page.goto(`${FIXTURES}/ai-ad-networks.html`);

  for (const id of ['#kontext-ad', '#gravity-ad', '#earnlayer-ad', '#lulu-ad']) {
    await expect(page.locator(`${id}:visible`), id).toHaveCount(0, { timeout: 5000 });
  }
  await expect(page.locator('#answer')).toBeVisible();
  await expect(page.locator('#legit-link')).toBeVisible();
});

test('AI ad networks: no request to an ad-network domain reaches the network', async () => {
  const page = await context.newPage();
  // Each host must be stopped by Armorly: rejected by the network rules
  // (ERR_BLOCKED_BY_CLIENT) or, one step earlier, never sent because the
  // payload shield caught it. A request that goes out and completes or
  // fails for another reason (DNS, offline) counts as leaked.
  const leaked = new Set<string>();
  page.on('requestfinished', (req) => leaked.add(new URL(req.url()).hostname));
  page.on('requestfailed', (req) => {
    if (req.failure()?.errorText !== 'net::ERR_BLOCKED_BY_CLIENT') leaked.add(new URL(req.url()).hostname);
  });

  await page.goto(`${FIXTURES}/ai-ad-networks.html`);
  const hosts: string[] = await page.evaluate(() => (window as any).__adNetworkHosts);
  expect(hosts.length).toBeGreaterThan(10);

  await page.waitForTimeout(1000);
  expect(hosts.filter((h) => leaked.has(h))).toEqual([]);
});

test('AI ad networks: Thrad and Gravity page globals become no-op proxies', async () => {
  const page = await context.newPage();
  await page.goto(`${FIXTURES}/ai-ad-networks.html`);
  await page.waitForFunction(() => typeof (window as any).thrad !== 'undefined', undefined, { timeout: 5000 });

  const isThenable = await page.evaluate(() => {
    const r = (window as any).thrad.render({ target: document.body });
    const p = (window as any).gravityPixel.track('PageView');
    return [r, p].every((x) => x !== null && typeof x === 'object' && typeof x.then === 'function');
  });
  expect(isThenable).toBe(true);
});

test('first-party ads: ChatGPT ad units removed on chatgpt.com, answer and sources kept', async () => {
  const page = await context.newPage();
  // Serve the fixture on the real hostname so the chatgpt-only selectors apply.
  await page.route('https://chatgpt.com/armorly-fixture', (route) =>
    route.fulfill({ path: path.resolve(__dirname, 'fixtures', 'chatgpt-ads.html'), contentType: 'text/html' })
  );
  await page.goto('https://chatgpt.com/armorly-fixture');

  for (const id of ['#gpt-ad-unit', '#gpt-ad-border', '#gpt-ad-bazaar', '#gpt-ad-section', '#gpt-ad-aside', '#gpt-ad-card-root', '#gpt-ad-options']) {
    await expect(page.locator(`${id}:visible`), id).toHaveCount(0, { timeout: 5000 });
  }
  await expect(page.locator('#gpt-answer')).toBeVisible();
  await expect(page.locator('#gpt-sources')).toBeVisible();
});

test('first-party ads: Copilot ads card removed on copilot.microsoft.com', async () => {
  const page = await context.newPage();
  await page.route('https://copilot.microsoft.com/armorly-fixture', (route) =>
    route.fulfill({ path: path.resolve(__dirname, 'fixtures', 'copilot-ads.html'), contentType: 'text/html' })
  );
  await page.goto('https://copilot.microsoft.com/armorly-fixture');

  await expect(page.locator('#copilot-ad:visible')).toHaveCount(0, { timeout: 5000 });
  await expect(page.locator('#copilot-ad-rg:visible')).toHaveCount(0, { timeout: 5000 });
  await expect(page.locator('#copilot-answer')).toBeVisible();
});

test('ads are hidden, not detached, so React-style re-renders do not crash the page', async () => {
  const page = await context.newPage();
  await page.goto(`${FIXTURES}/framework-owned-ads.html`);

  await expect(page.locator('#ad-gate')).toBeHidden({ timeout: 5000 });
  // The node must still be where the framework put it.
  expect(await page.evaluate(() => document.getElementById('ad-gate')?.parentElement?.id)).toBe('chat');
  expect(await page.evaluate(() => (window as any).__rerender())).toBe('ok');
  await expect(page.locator('#answer')).toBeVisible();
});

test('Imprezia real SDK markup: every ad format hidden (with and without its wrapper), inline link unwrapped', async () => {
  // tests/fixtures/imprezia-real.html is the exact HTML Imprezia's SDK
  // rendered on demo.imprezia.ai for each ad format.
  const page = await context.newPage();
  const blockedImages: string[] = [];
  page.on('requestfailed', (req) => {
    if (req.url().includes('imprezia-assets') && req.failure()?.errorText === 'net::ERR_BLOCKED_BY_CLIENT') blockedImages.push(req.url());
  });
  await page.goto(`${FIXTURES}/imprezia-real.html`);

  const slots = page.locator('.slot');
  expect(await slots.count()).toBeGreaterThanOrEqual(20);
  // Each slot's ad must end up invisible, whichever form it was rendered in.
  await expect.poll(
    () => page.evaluate(() =>
      [...document.querySelectorAll('.slot')]
        .filter((s) => [...s.querySelectorAll('*')].some((e) => (e as HTMLElement).offsetWidth || (e as HTMLElement).offsetHeight))
        .map((s) => `${s.getAttribute('data-format')}/${s.getAttribute('data-variant')}`)
    ),
    { timeout: 5000 }
  ).toEqual([]);
  await expect(page.locator('text=/Sponsored by/ >> visible=true')).toHaveCount(0);

  // Inline sponsored link: no longer a link (href stripped in place, so
  // React keeps its node), sentence intact.
  await expect(page.locator('a.imprezia-link[href]')).toHaveCount(0);
  await expect(page.locator('#answer')).toContainText('the Shinjuku Washington Hotel is a solid pick');

  // Ad creative images never load.
  await expect.poll(() => blockedImages.length, { timeout: 5000 }).toBeGreaterThan(0);
});

// Verbatim ad markup captured from each network's real SDK (rendered in
// Chromium with the published package; ad servers mocked with API-shaped
// responses). One file per format in tests/fixtures/captures/. Each capture
// is mounted in its own slot; after Armorly runs, a slot may show no ad
// text, iframe or image. PUBLISHER_TEXT lists the few captures where the
// publisher's own words sit around an inline ad and must stay.
const CAPTURES_DIR = path.resolve(__dirname, 'fixtures', 'captures');
const PUBLISHER_TEXT: Record<string, string> = {
  'gravity-react-adtext.html': 'Try this:',
  'gravity-react-adtext-noclick.html': 'Try this:',
  // Thrad's no-fill notice is SDK chrome, not an ad.
  'thrad-nofill.html': 'No ad available',
  // ZeroClick ads are offer links inside the model's own sentence.
  'zeroclick-mcp-inline-offer-links.html': 'For trail running, the is a solid pick (sponsored). Another option is .',
  // ChatAds is the publisher's chatbot; its affiliate links are unwrapped to
  // plain text, so the answer reads the same without the tracking links.
  'chatads-inline-links.html': 'For a small kitchen I would go with the Ninja AF101 Air Fryer - compact and easy to clean. If you want more capacity, the Cosori Pro LE is worth a look. Our full air fryer guide has the test data.',
  'chatads-widget-panel.html': '× Which air fryer for a small kitchen? For a small kitchen I would go with the Ninja AF101 Air Fryer - compact and easy to clean. If you want more capacity, the Cosori Pro LE is worth a look. Our full air fryer guide has the test data. Hit daily limit. Try again tomorrow. Please keep your question under 100 words. Links may include affiliate offers Powered by ChatAds For a small kitchen I would go with the Ninja AF101 Air Fryer - compact and easy to clean. If you want more capacity, the Cosori Pro LE is worth a look. Our full air fryer guide has the test data.',
  // The README's own caption under the (hidden) sponsor badge.
  'lulu-readme-sponsor-badge-github-live.html': '↑ live rendered sponsor card — real rotating ad demand, refreshes every ~60s. Any claimed listing can embed this in its own README.'
};

test('real SDK captures: every network ad format is hidden', async () => {
  const fs = await import('node:fs');
  const files = fs.readdirSync(CAPTURES_DIR).filter((f) => f.endsWith('.html')).sort();
  expect(files.length).toBeGreaterThan(50);
  const slots = files
    .map((f, i) => {
      const body = fs.readFileSync(path.join(CAPTURES_DIR, f), 'utf8').replace(/\sid="slot"/g, '');
      return `<section class="capture" id="c${i}" data-file="${f}" data-allow="${PUBLISHER_TEXT[f] ?? ''}">${body}</section>`;
    })
    .join('\n');

  const page = await context.newPage();
  await page.route(`${FIXTURES}/__captures`, (route) =>
    route.fulfill({ contentType: 'text/html', body: `<!doctype html><html><head><meta charset="utf-8"></head><body>${slots}</body></html>` })
  );
  await page.goto(`${FIXTURES}/__captures`);

  const leaks = () =>
    page.evaluate(() =>
      [...document.querySelectorAll<HTMLElement>('section.capture')]
        .filter((s) => {
          // The whole slot hidden: caught, unless publisher text had to stay.
          // (innerText of a hidden element is its full text, so check first.)
          if (!s.checkVisibility()) return !!s.dataset.allow;
          const text = s.innerText.replace(/\s+/g, ' ').trim();
          const media = [...s.querySelectorAll<HTMLElement>('iframe, img, video')].some((e) => e.offsetWidth || e.offsetHeight);
          return media || text !== (s.dataset.allow ?? '');
        })
        .map((s) => `${s.dataset.file}: "${s.innerText.replace(/\s+/g, ' ').trim().slice(0, 60)}"`)
    );
  await expect.poll(leaks, { timeout: 5000 }).toEqual([]);
  // Paid links in an answer keep their words but stop being links.
  await expect(page.locator('section.capture a[rel~="sponsored"][href] >> visible=true')).toHaveCount(0);
});

// Lulu ads render as MCP-app frame documents (Claude.ai / ChatGPT apps).
// Each capture is loaded both as its own frame document and inside a
// srcdoc iframe, which needs match_about_blank + match_origin_as_fallback.
const FRAME_CAPTURES_DIR = path.resolve(__dirname, 'fixtures', 'captures-frames');
const SPONSOR_TEXT = /sponsored|lulu ads/i;

test('real SDK captures: Lulu widget and result-frame sponsors hidden, standalone and in srcdoc frames', async () => {
  const fs = await import('node:fs');
  const files = fs.readdirSync(FRAME_CAPTURES_DIR).filter((f) => f.endsWith('.html')).sort();
  expect(files.length).toBeGreaterThan(10);
  const page = await context.newPage();
  const visibleSponsorText = (frame: import('@playwright/test').Frame) =>
    frame.evaluate((re) => {
      const rx = new RegExp(re, 'i');
      return document.body.innerText.split('\n').map((l) => l.trim()).filter((l) => rx.test(l));
    }, SPONSOR_TEXT.source);

  const leaks: string[] = [];
  for (const f of files) {
    const doc = fs.readFileSync(path.join(FRAME_CAPTURES_DIR, f), 'utf8');

    await page.route(`${FIXTURES}/__frame`, (route) => route.fulfill({ contentType: 'text/html', body: doc }));
    await page.goto(`${FIXTURES}/__frame`);
    await expect.poll(() => visibleSponsorText(page.mainFrame()), { timeout: 5000 }).toEqual([]).catch(() => leaks.push(`${f} [standalone]`));
    await page.unroute(`${FIXTURES}/__frame`);

    const host = `<!doctype html><html><body><iframe id="app" style="width:600px;height:400px" srcdoc="${doc.replace(/&/g, '&amp;').replace(/"/g, '&quot;')}"></iframe></body></html>`;
    await page.route(`${FIXTURES}/__host`, (route) => route.fulfill({ contentType: 'text/html', body: host }));
    await page.goto(`${FIXTURES}/__host`);
    const frame = page.frames().find((fr) => fr !== page.mainFrame())!;
    await expect.poll(() => visibleSponsorText(frame), { timeout: 5000 }).toEqual([]).catch(() => leaks.push(`${f} [srcdoc]`));
    await page.unroute(`${FIXTURES}/__host`);
  }
  expect(leaks).toEqual([]);
});

test('network rules exempt the vendor\'s own site (docs and dashboards keep working)', async () => {
  const page = await context.newPage();
  const results: Record<string, string> = {};
  page.on('requestfinished', (r) => { if (r.url().includes('armorly-probe')) results[new URL(r.url()).hostname] = 'loaded'; });
  page.on('requestfailed', (r) => { if (r.url().includes('armorly-probe')) results[new URL(r.url()).hostname] = r.failure()?.errorText ?? 'failed'; });
  await page.route('https://cdn.thrad.ai/armorly-probe.gif', (route) => route.fulfill({ contentType: 'image/gif', body: Buffer.from('R0lGODlhAQABAAAAACw=', 'base64') }));
  await page.route('https://docs.thrad.ai/armorly-fixture', (route) =>
    route.fulfill({ contentType: 'text/html', body: '<!doctype html><img src="https://cdn.thrad.ai/armorly-probe.gif">' })
  );
  await page.goto('https://docs.thrad.ai/armorly-fixture');
  await expect.poll(() => results['cdn.thrad.ai'], { timeout: 5000 }).toBe('loaded');
});

test('SDK proxies do not break ordinary page code', async () => {
  const page = await context.newPage();
  await page.goto(`${FIXTURES}/page-globals.html`);
  expect(await page.evaluate(() => (window as any).__sponsoredCount)).toBe(3);
  await expect.poll(() => page.evaluate(() => (window as any).__koahResult), { timeout: 5000 }).toBe('no-fill');
});
