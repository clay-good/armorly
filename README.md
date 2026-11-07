# Armorly

**An ad blocker built for AI chatbots.** Intercepts ad SDKs, removes sponsored labels, cleans affiliate tracking from links, and quietly neutralizes hidden prompt-injection attacks on the side.

[![build](https://github.com/clay-good/armorly/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/clay-good/armorly/actions/workflows/build.yml)
[![MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

![Armorly removing a sponsored card from a ChatGPT-style response](docs/demo.gif)

<sup>Recorded by [`npm run demo`](tests/extension.spec.ts) against a ChatGPT-styled fixture page (the real chatbots don't show ads yet — Armorly is ready for when they do). [How the demo is generated.](#demo-generation)</sup>

<details>
<summary>Popup screenshots</summary>

![Armorly popup showing protection status on Perplexity](docs/screenshots/armorly-perplexity.jpg)
![Armorly popup showing protection status on ChatGPT](docs/screenshots/armorly-chatgpt.jpg)
![Armorly console logs confirming the blocker is active](docs/screenshots/armorly-console.jpg)

</details>

## Install

| Browser | How |
|---|---|
| **Chrome** | [Chrome Web Store](https://chromewebstore.google.com/detail/armorly/ojjmbhddhccnnepgojahamfilcpfddbp) |
| **Brave** | Same Chrome Web Store listing — Brave installs Chrome extensions directly |
| **Edge** | Edge Add-ons (submission pending) — until then, `armorly-edge.zip` from the [latest release](https://github.com/clay-good/armorly/releases/latest) |
| **Firefox** | Mozilla AMO (submission pending) — until then, `armorly-firefox.zip` from the [latest release](https://github.com/clay-good/armorly/releases/latest) |
| **Opera** | `armorly-opera.zip` from the [latest release](https://github.com/clay-good/armorly/releases/latest) — manual install via `opera://extensions` |
| **Safari** | Source bundle `armorly-safari.zip` — wrap with `xcrun safari-web-extension-converter` on macOS |

After install, click the Armorly toolbar icon to see protection status. The popup shows:

- Current site being monitored, with a **Protect this site** toggle for false-positive recovery (reload to apply).
- Per-session counts of SDKs blocked and links cleaned.
- **Since install** lifetime totals, with a Reset button.
- Active protections at a glance.

## What it does

AI ads come from the same API as the real chatbot response — there's no separate ad domain a traditional ad blocker can drop. Armorly tackles AI advertising with six independent, fully deterministic layers (fixed rules, no AI models, no remote code), so a new ad network has to defeat all of them to reach you. It also shields you from a real AI security threat (hidden prompt injection) that traditional blockers don't address at all.

## How it works

1. **SDK interception.** A MAIN-world content script wraps `window.koah`, `window.thrad`, `window.GravityAd`, etc. in no-op proxies *before* any page script runs. Calls resolve to a "no ad" result and never reach the network.
2. **DOM removal.** Per-platform selectors and FTC-disclosure pattern matching hide sponsored cards, promoted suggestions, and ad containers as they appear. Conservative — only elements with explicit ad markers (`data-sponsored`, `data-koah-ad`, `aria-label="Sponsored"`, etc.) are touched.
3. **Affiliate-link cleaning.** Outbound links get `tag=`, `utm_*`, `ref`, `affiliate`, etc. stripped from their query strings. Non-affiliate params are preserved.
4. **Network-level blocking** (v2.3.0+). Static `declarativeNetRequest` rules drop requests to AI ad-network domains — Koah, Imprezia, Kontext, Gravity, Thrad, ZeroClick, Lulu, ChatAds, Monetzly — covering every request type (scripts, XHR, frames, images, beacons, WebSockets, media), plus the ad-verification vendors brands use to confirm an ad was seen. Each vendor's own site (docs, dashboards) is exempt.
5. **Payload shield, for server-side / OpenRTB ads.** When the chatbot's own server runs the ad auction and stitches the ad into its response, there is no SDK and no ad domain. The ad still has to reach the page as data, so a MAIN-world script filters JSON, streamed (SSE / NDJSON / AI-SDK) responses, WebSocket and EventSource messages, and drops every object that is an ad by structure: OpenRTB bids (`seatbid`, `adm` + `nurl`/`burl`), native-ad trackers (`imptrackers`, `eventtrackers`), or objects that declare themselves sponsored and carry ad plumbing. The page's code never sees the ad.
6. **Proof-of-delivery blocking.** Advertisers only pay when the browser confirms the ad was shown. Armorly blocks those confirmations: tracker URLs and ad ids learned from removed ads, ad-event analytics (`ad_impression`, `impression` + ad id), unsubstituted OpenRTB macros, `ping`/`attributionsrc` attributes, ad click-redirects (rewritten straight to the destination), and the browser's own ad APIs (Protected Audience auctions, Topics). Ad cards rendered as HTML are hidden by their legally required disclosure label ("Sponsored", "Ad", "Promoted"…), with zero-width characters and lookalike letters normalized away, including inside closed shadow roots and same-origin iframes. Hidden ads are also removed from the accessibility tree, so browser agents reading the page don't see them either.

Armorly targets ads served into AI chat and agent surfaces. For broad web advertising, run uBlock Origin or Brave alongside it.

### Hidden prompt-injection shield

Malicious websites can hide instructions in invisible text. When you paste content from these pages into an AI, the hidden instructions get included and can manipulate the AI's behavior.

Armorly detects deceptively-hidden elements (white-on-white text, `font-size: 0`) and removes their content **only when** it matches a known prompt-injection phrase ("ignore previous instructions", "jailbreak", "DAN mode", `[SYSTEM]:` prefixes, etc.). This conservative match prevents false positives while catching real attacks.

When the shield fires, a small toast appears in the bottom-right of the page so the protection is visible. Click × to suppress the toast on that hostname forever; otherwise it auto-dismisses after 8 seconds. The shield itself keeps running regardless.

## Supported platforms

Works on every website. Platform-specific detection for:

- ChatGPT / OpenAI (live sponsored cards and shopping units)
- Perplexity AI (active sponsored follow-ups)
- Grok / X (active promoted suggestions)
- Microsoft Copilot and You.com (ads cards)
- Claude, Gemini, Poe
- Any chatbot that serves ads through an ad SDK, an ad network, or its own server (OpenRTB / server-side insertion)
- Any chatbot using Koah, Imprezia, Kontext, Gravity, Thrad, ZeroClick, Lulu, ChatAds, EarnLayer, or Monetzly
- Selectors are tested against ad markup captured from each network's real SDK ([tests/fixtures/captures/](tests/fixtures/captures/))

## Verify it's working

1. Visit any supported chatbot (e.g. [chatgpt.com](https://chatgpt.com), [perplexity.ai](https://perplexity.ai)).
2. Open DevTools (`Cmd+Option+I` / `Ctrl+Shift+I`) and switch to the Console tab.
3. You should see `[Armorly] AI ad blocker active` shortly after page load.
4. Click the Armorly toolbar icon — the popup will show "Monitoring" and the current site.

If you don't see the console line, the content script didn't inject — open an issue with the URL and the console output.

## Privacy

- No data sent to external servers.
- No telemetry, analytics, or user tracking.
- Local storage is used only for the per-site disable list and lifetime block counts. Never synced. Never sent anywhere.
- Open source and auditable.

## Why ads will destroy AI

Advertising is incompatible with AI's value proposition.

AI's entire purpose is to give you the best answer. Ads require giving you a paid answer. These goals are mutually exclusive. When an AI recommends a specific product because the company paid for placement rather than because it's actually the best option for your trip, the AI has stopped being useful. It's now a salesperson pretending to be an advisor.

Traditional search survived ads because users understood the transaction: free results in exchange for attention. AI is different. Users ask AI questions expecting genuine expertise. They trust the response. Injecting paid content into that trust relationship isn't advertising — it's deception. The moment users realize AI recommendations are for sale, the entire value of AI-as-advisor collapses.

The ad-supported model also creates perverse incentives. An AI optimized for engagement (to show more ads) will give you answers that keep you asking questions, not answers that solve your problem. It will recommend products with high affiliate commissions, not products that fit your needs. It will become a worse AI to become a better ad platform.

OpenAI, Google, and others are walking into this trap anyway because ads are easy money. Armorly exists because some of us still want AI that works for us, not for advertisers.

## Limitations

What this extension cannot do:

1. **Mobile apps are unprotected.** Browser extensions don't run on iOS or Android. ChatGPT's mobile app, Perplexity's app, any mobile browser — Armorly can't help you there.
2. **Server-side ads are caught by structure and label, not by meaning.** A server-stitched ad is blocked when it arrives as structured data (OpenRTB, native-ad trackers, a sponsored flag with ad plumbing) or renders with a disclosure label. Ad text blended into the answer's own prose, with no label and no ad metadata, can't be told apart deterministically (and is undisclosed advertising under FTC rules).
3. **Impressions counted entirely on the server can't be blocked.** If an ad platform bills on "delivered" (the server sent it) instead of "viewed" (the browser confirmed it), there is nothing in the browser to stop. Most brand spend requires viewability measured in the browser, which Armorly blocks, but a server-side count is out of any extension's reach.
4. **New ad formats have an update window.** When a network changes SDK function names or DOM structure, there's a gap before we update. Pattern auto-update (v2.5.0+) closes part of this gap automatically — the flat data fields in [extension/lib/ad-patterns.json](extension/lib/ad-patterns.json) refresh once a day from this repo's `main` branch. Regex-driven detection still needs an extension version bump.
5. **We don't block "useful" recommendations.** If an AI recommends a product because it's actually good and no money changed hands, Armorly won't remove it. We block disclosed sponsored content and known ad SDK calls, not editorial choices.
6. **Undisclosed paid recommendations are undetectable.** If an AI company accepts payment to recommend products and doesn't label them as sponsored (illegal under FTC rules, but enforcement is slow), we have no way to know.
7. **Safari is on the roadmap, not implemented.** Chrome / Edge / Brave / Opera install directly from the Chrome zip. Firefox has its own AMO-compatible zip. Safari requires Xcode + an Apple Developer Program account to ship; the source bundle is built by CI but not yet published.
8. **Iframes with restrictive CSP may bypass content script injection.** Rare but possible.
9. **We don't block what you explicitly asked for.** Asking "recommend a hotel in Tokyo" gets you a recommendation. We can't tell whether it's paid.
10. **False positives happen.** Legitimate content containing words like "Sponsored" or "Ad" in certain contexts may get flagged. The per-site disable toggle is the escape hatch.
11. **Generic web ads are uBlock's job.** Armorly focuses on AI chat and agent surfaces. Run a traditional blocker alongside it for the rest of the web.
12. **A site that actively fights extensions can evade in-page hooks.** The payload shield runs before any page script, but a determined site can, for example, re-fetch through a fresh frame. Network rules and the DOM layer still apply; a network-level blocker (Pi-hole, NextDNS) is the stronger guarantee if you need one.

## For developers

### Project structure

```
armorly/
├── extension/
│   ├── manifest.json
│   ├── background.js              # MV3 service worker (pattern auto-update)
│   ├── icons/
│   ├── popup/
│   │   ├── popup.html
│   │   └── popup.js
│   ├── content/
│   │   ├── sdk-blocker.js         # MAIN-world SDK proxy installer
│   │   ├── payload-shield.js      # MAIN-world: strips ads from responses, blocks ad trackers
│   │   ├── ai-ad-blocker.js       # DOM removal, disclosed ad cards, link cleaning, stats
│   │   └── hidden-content-blocker.js
│   ├── lib/
│   │   ├── ad-patterns.js         # patterns library (data + helpers)
│   │   ├── ad-signatures.js       # deterministic ad classifiers (payloads, requests, labels)
│   │   └── ad-patterns.json       # auto-updatable subset
│   └── rules/
│       └── ad-sdks.json           # declarativeNetRequest static rules
├── tests/                         # Playwright fixture tests + node:test unit tests
├── .github/workflows/             # build + release CI
└── build.sh                       # ./build.sh [chrome|firefox|edge|brave|opera|safari]
```

### Permissions

| Permission | Why |
|---|---|
| `<all_urls>` (host) | Inject content scripts on all sites to detect ads |
| `storage` | Per-site disable list, lifetime counters, cached pattern snapshot. Local-only |
| `declarativeNetRequest` | Static rules blocking AI-specific ad-SDK domains. Shipped with the extension; no remote loading |
| `alarms` | Wake the background service worker once a day to refresh `ad-patterns.json`. Data only |

No `tabs`, no `webRequest`, no `cookies`, no `history`.

### Development build

```bash
git clone https://github.com/clay-good/armorly.git
cd armorly
./build.sh                  # Chrome (default; also valid for Edge, Brave, Opera)
./build.sh firefox          # Firefox (manifest mutated for AMO)
./build.sh safari           # Safari source bundle
```

Then in Chromium-family browsers: `chrome://extensions/` → enable Developer mode → "Load unpacked" → select `build/`. In Firefox: `about:debugging#/runtime/this-firefox` → "Load Temporary Add-on…" → pick `build/manifest.json`.

### Test suite

```bash
npm install
npx playwright install --with-deps chromium
npm test
```

`npm test` rebuilds the extension, runs the signature unit tests, then runs the Playwright suite headless (no browser window opens). The server-side ad suite plays a chatbot backend that stitches ads into JSON, SSE, NDJSON, AI-SDK, WebSocket, EventSource and XHR responses and counts every tracker hit, then checks that with Armorly loaded no ad renders and no tracker reaches the server. See [tests/README.md](tests/README.md) for what's covered and what isn't.

### Release flow

Tag-driven. See [docs/RELEASING.md](docs/RELEASING.md) for the runbook.

### Demo generation

The hero GIF at the top of this README is reproducible. `npm run demo` runs
a single Playwright test that opens a ChatGPT-styled mock page with the
extension disabled (sponsored card visible), waits, toggles Armorly on via
the service worker, reloads, and waits again. Output: `test-results/demo/*.webm`.
Convert to GIF with:

```bash
./scripts/make-demo-gif.sh        # needs ffmpeg + gifsicle
# writes docs/demo.gif (~400-900 KB, 12fps, 960px wide)

npm run stills                    # rebuild + extract before.png/after.png
# writes docs/listing/{before,after}.png (1280x800, Chrome Web Store aspect)
```

## Contributing

Pattern updates and bug reports are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a new ad-network pattern. For security disclosures, see [SECURITY.md](SECURITY.md). User-facing changes per release live in [CHANGELOG.md](CHANGELOG.md).

## License

MIT — see [LICENSE](LICENSE).
