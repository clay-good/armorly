import { test, expect, chromium, type BrowserContext } from '@playwright/test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/**
 * Resilience scorecard: what if every AI ad network renamed its markup
 * tomorrow?
 *
 * Loads the 101 real SDK captures (tests/fixtures/captures/) into a copy
 * of the built extension with every network-specific selector and
 * inline-link rule removed. Only the generic layers remain: disclosure
 * labels (any language, obfuscated, CSS-drawn), generic ad-server markup
 * and rel="sponsored". The floor below is a regression guard; the actual
 * number is printed.
 */

const FIXTURES = 'http://127.0.0.1:8421';
const CAPTURES_DIR = path.resolve(__dirname, 'fixtures', 'captures');
// Publisher text that legitimately surrounds an inline ad (same list as
// the network-selector test in extension.spec.ts).
const PUBLISHER_TEXT: Record<string, string> = {
  'gravity-react-adtext.html': 'Try this:',
  'gravity-react-adtext-noclick.html': 'Try this:',
  'thrad-nofill.html': 'No ad available',
  'zeroclick-mcp-inline-offer-links.html': 'For trail running, the is a solid pick (sponsored). Another option is .',
  'chatads-inline-links.html': 'For a small kitchen I would go with the Ninja AF101 Air Fryer - compact and easy to clean. If you want more capacity, the Cosori Pro LE is worth a look. Our full air fryer guide has the test data.',
  'chatads-widget-panel.html': '× Which air fryer for a small kitchen? For a small kitchen I would go with the Ninja AF101 Air Fryer - compact and easy to clean. If you want more capacity, the Cosori Pro LE is worth a look. Our full air fryer guide has the test data. Hit daily limit. Try again tomorrow. Please keep your question under 100 words. Links may include affiliate offers Powered by ChatAds For a small kitchen I would go with the Ninja AF101 Air Fryer - compact and easy to clean. If you want more capacity, the Cosori Pro LE is worth a look. Our full air fryer guide has the test data.',
  'lulu-readme-sponsor-badge-github-live.html': '↑ live rendered sponsor card — real rotating ad demand, refreshes every ~60s. Any claimed listing can embed this in its own README.'
};
const FLOOR = 0.7;

let context: BrowserContext;
let genericBuild: string;

test.beforeAll(async () => {
  genericBuild = fs.mkdtempSync(path.join(os.tmpdir(), 'armorly-generic-'));
  fs.cpSync(path.resolve(__dirname, '..', 'build'), genericBuild, { recursive: true });
  const strip = `\n;(function(){var p=window.ArmorlyAdPatterns;if(!p)return;p.platformSelectors={generic:p.platformSelectors.generic};p.inlineAdLinks=[];})();\n`;
  for (const f of ['lib/ad-patterns.js', 'lib/ad-patterns-main.js']) fs.appendFileSync(path.join(genericBuild, f), strip);
  context = await chromium.launchPersistentContext('', {
    headless: true,
    channel: 'chromium',
    args: [`--disable-extensions-except=${genericBuild}`, `--load-extension=${genericBuild}`]
  });
});

test.afterAll(async () => {
  await context?.close();
  fs.rmSync(genericBuild, { recursive: true, force: true });
});

test('resilience: generic layers alone still hide most real AI-network ad formats', async () => {
  const files = fs.readdirSync(CAPTURES_DIR).filter((f) => f.endsWith('.html')).sort();
  const slots = files
    .map((f, i) => {
      const body = fs.readFileSync(path.join(CAPTURES_DIR, f), 'utf8').replace(/\sid="slot"/g, '');
      return `<section class="capture" id="c${i}" data-file="${f}" data-allow="${PUBLISHER_TEXT[f] ?? ''}">${body}</section>`;
    })
    .join('\n');

  const page = await context.newPage();
  await page.route(`${FIXTURES}/__resilience`, (route) =>
    route.fulfill({ contentType: 'text/html', body: `<!doctype html><html lang="en"><head><meta charset="utf-8"></head><body>${slots}</body></html>` })
  );
  page.on('console', (m) => { if (m.text().includes('[Armorly] scan error')) console.log(m.text()); });
  await page.goto(`${FIXTURES}/__resilience`);
  await page.waitForTimeout(1500);

  const leaks: string[] = await page.evaluate(() =>
    [...document.querySelectorAll<HTMLElement>('section.capture')]
      .filter((s) => {
        // The whole capture hidden: caught, unless publisher text had to stay.
        if (!s.checkVisibility()) return !!s.dataset.allow;
        const text = s.innerText.replace(/\s+/g, ' ').trim();
        const media = [...s.querySelectorAll<HTMLElement>('iframe, img, video')].some((e) => e.offsetWidth || e.offsetHeight);
        return media || text !== (s.dataset.allow ?? '');
      })
      .map((s) => s.dataset.file as string)
  );
  const caught = files.length - leaks.length;
  const rate = caught / files.length;
  console.log(`[resilience] generic layers alone hide ${caught}/${files.length} captures (${Math.round(rate * 100)}%)`);
  const byNetwork: Record<string, [number, number]> = {};
  for (const f of files) {
    const n = f.split('-')[0];
    byNetwork[n] = byNetwork[n] || [0, 0];
    byNetwork[n][1]++;
    if (!leaks.includes(f)) byNetwork[n][0]++;
  }
  console.log('[resilience] by network:', Object.entries(byNetwork).map(([n, [c, t]]) => `${n} ${c}/${t}`).join(', '));
  console.log('[resilience] not caught:', leaks.join(', '));
  expect(rate).toBeGreaterThanOrEqual(FLOOR);
});
