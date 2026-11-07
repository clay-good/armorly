# Changelog

All notable user-facing changes to Armorly are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **Server-side / OpenRTB ad blocking.** Ads that a chatbot's own server auctions and stitches into its response (no SDK, no ad domain) are now blocked three ways, all deterministic:
  - **Payload shield** ([payload-shield.js](extension/content/payload-shield.js), MAIN world): filters JSON, SSE, NDJSON, AI-SDK data streams, WebSocket and EventSource messages and XHR responses, dropping objects that are ads by structure (OpenRTB bid responses and bids, native-ad tracker arrays, self-declared sponsored objects with ad plumbing, `ad`/`sponsored_*` containers). Fails open on any error.
  - **Proof-of-delivery blocking**: impression/view/win/billing requests via `fetch`, XHR, `sendBeacon`, image/script/iframe `src` and `setAttribute` are blocked when they hit a tracker URL learned from a removed ad, mention a removed ad's id, report an ad event, carry an unsubstituted OpenRTB macro, or target an ad-network/verification host. `ping` and `attributionsrc` are dropped; Protected Audience (`runAdAuction`, interest groups) and Topics return "no ad".
  - **Disclosed ad cards** ([ai-ad-blocker.js](extension/content/ai-ad-blocker.js)): elements whose whole text is a disclosure label ("Sponsored", "Ad", "Promoted", "Sponsored by X", "Sponsored: …" prefixes) are found after normalizing zero-width characters, lookalike letters and split spans, and the smallest enclosing card with a link/button is hidden (`display:none`, `aria-hidden`, `inert`). Works in closed shadow roots and same-origin/srcdoc iframes. Guard rails keep it off forms, the composer, main/log regions and neighbouring content.
  - Ad click-redirects are rewritten to their destination; ad click-ids (`gclid`, `msclkid`, `ttclid`, …) are stripped.
- Shared classifier library [ad-signatures.js](extension/lib/ad-signatures.js) with 165 `node:test` unit tests (`npm run test:unit`): real AI ad-network payloads that must be caught, and everyday chat/web JSON and text that must not.
- Headless end-to-end suite [server-side-ads.spec.ts](tests/server-side-ads.spec.ts): a fixture backend stitches ads into 14 delivery channels and counts tracker hits; a control run proves every ad and tracker fires without Armorly, the Armorly run proves none do. Plus a DOM-hardening fixture (streaming, localized, CSS-drawn, carousel, frame ads, and look-alike negatives).
- **Coverage of real AI ad networks.** Payload signatures built from each network's published SDK types (Kontext, Gravity, Thrad, Imprezia, Lulu, ChatAds, EarnLayer, ChatGPT ad units): 15 of 17 real response shapes are stripped (was 3). Formats added: OpenRTB 3.0 (`purl`), VAST, AI SDK `data-*` parts, tracker maps, JSON hidden in string fields (MCP tool text), React Server Component rows.
- **More delivery channels:** streamed JSON arrays (filtered element by element, so they keep streaming), XSSI-prefixed JSON, Socket.IO, SignalR, binary WebSocket frames, RSC (`text/x-component`), SSE/NDJSON over XHR (append-only), XHR `arraybuffer`, `Request`/Blob bodies, Blob beacons, `srcset`, `a.ping`, socket listeners bound via `EventTarget.prototype`.
- **Tab-scoped block rules for learned trackers.** Tracker URLs learned from removed ads become `declarativeNetRequest` session rules for that tab only, cleared on navigation. They stop pixels created by HTML parsing (`innerHTML`), which no JS hook can see.
- **Stream repair.** When an ad is the payload of a stream envelope (Anthropic `content_block`, OpenAI Responses `item`, …) the whole event is dropped, its follow-up deltas go with it, and later `index`/`output_index` values are renumbered so SDK accumulators stay valid.
- **DOM layer:** localized disclosure labels (~100 strings in 30 languages; ambiguous words like "Anzeige" only count when the page language matches); evasions (spaced letters, RTL override, more lookalikes); labels drawn with CSS `::before`/`::after`, `img alt`, `aria-labelledby`; `<details>` ads, carousels, `onclick` cards, whole-frame ads, box-drawn ads in code blocks, "(sponsored)" inline markers; cards that are one link wrapper hidden whole; card-shaped `<a rel="sponsored">` hidden, inline ones neutralized in chats.
- **Resilience scorecard** ([resilience.spec.ts](tests/resilience.spec.ts)): with every network-specific selector removed, the generic layers alone still hide 74 of 101 real SDK ad captures (the 11 that carry no disclosure label at all can't be caught generically).
- Whole-domain network rules now cover every request type (WebSocket, media, fonts, …), plus three ad-verification vendors.
- Generic ad-server markup selectors (`data-ad-slot`, `data-creative-id`, `data-impression-url`, `fencedframe`, …).

### Fixed
- **Ads stayed visible for the whole streamed answer.** The DOM scan used a trailing-only debounce, so it never ran while tokens kept arriving. It now scans at least every 300 ms during a stream, only over the subtrees that changed; on a 3,000-message page the ad is gone ~370 ms after it appears and stream throughput is unchanged.
- **Network selectors added by the daily pattern update were never applied** (the per-network list was hard-coded). New networks' selectors now apply automatically.
- **A page could switch Armorly off on itself.** The "disable this site" bridge to the MAIN world was a plain `window.postMessage` any page script could forge. It is now authenticated with per-page keys exchanged through a `<html>` attribute before any page script runs, one key per message type, so seeing a pattern-update message never reveals the disable key.

### Changed
- Tests run fully headless (Chromium new headless loads MV3 extensions); CI no longer needs `xvfb`.
- Popup: "SDKs Blocked" is now "Ads Blocked" and also counts stripped ad payloads and blocked ad trackers.
- Inline sponsored links (Imprezia, ChatAds, `rel="sponsored"` in chat answers) are neutralized in place (no `href`, words kept) instead of being replaced with a text node, which could crash React-rendered answers.
- Safety: an "ad" container key only counts when its value carries ad plumbing; weak ids (campaign, placement, bid) never block a request on their own; only event-shaped request bodies are judged (a chat request carrying history is never blocked); learned ids must look like ids and match exactly; learned trackers on the site's own host block pixels/beacons only, never the site's own API; ad-manager consoles (ads.google.com, …) are skipped.
- CI test job pinned to `ubuntu-24.04` (Playwright doesn't support 26.04 yet).

## [2.10.1]

### Fixed
- **No more blank pages on React chat apps.** Armorly used to delete ad elements outright. Chat apps are mostly React, and when React later re-rendered (new chat, regenerate) it tried to remove the node itself, threw `removeChild … not a child of this node`, and unmounted the whole app. Reproduced with React 18.3.1. Ads are now hidden with an inline `display: none !important` (the same approach EasyList/uBlock use), so the framework's tree stays intact. New regression test replays React's `removeChild` step.
- **Imprezia: every ad format is covered, not just the `<a>` cards.** Verified against the exact markup Imprezia's SDK renders on its own playground (demo.imprezia.ai) for all 12 formats. 2.10.0 caught them only through the SDK's `data-imprezia-viewability-gate` wrapper; Lead Gen, Date Picker, Text CTA and Hyperlink CTA leaked whenever a publisher rendered cards without it. Now matched directly: `.imprezia-card` (any element), `.imprezia-cta-container`, `.imprezia-cta-link`, `.imprezia-cta-button`, `.imprezia-cta-sponsored`.
- **Imprezia inline sponsored links** (`a.imprezia-link`, woven into the AI's answer) are unwrapped to plain text, so the tracking link is gone but the sentence still reads.
- Imprezia ad creative images (`storage.googleapis.com/imprezia-assets/`) are blocked at the network layer.
- **Every network re-verified against its real SDK.** Selectors were previously written from reading SDK code. Each network's real SDK has now been rendered in Chromium (ad servers mocked with API-shaped responses), and 101 formats were captured verbatim into `tests/fixtures/captures/`. The new tests require every one to be hidden. 2.10.0 left 14 of them visible, plus every Lulu MCP-app frame. Gaps closed:
  - **Kontext:** the React SDK emits no classes. It's now matched by its fixed iframe `title` + `data-testid`.
  - **Gravity:** `GravityAd.mount()` slots, lead-in wrappers and lead-form cards are hidden, the `window.GravityAd` global is proxied, and the jsDelivr/unpkg embed builds are blocked.
  - **Thrad:** the SDK wrapper `div.adsdk-container[data-thrad-format]` is hidden.
  - **Koah:** `[data-koah="root"]` added as a backup to `.koah-ad-container`.
  - **ZeroClick:** offer links in answers (`mcp.zeroclick.ai/…/offers`, `zeroclick.dev/api/v2/clicks`, `zero.click/…`) are hidden, and `zeroclick.dev` and `zero.click` are blocked.
  - **Lulu:** MCP-app widgets, result-frame sponsor strips, README sponsor badges, and text sponsor cards/suffixes in answers are hidden.
  - **ChatAds:** affiliate links in the widget's answers are unwrapped to plain text, and the legacy `chataside.com` script is blocked.
  - **EarnLayer:** `@earnlayer/ai-ads-sdk` components are hidden.
- **Ads inside `srcdoc` / `about:blank` frames** (how MCP-app hosts embed widgets) are now reached: content scripts run with `match_about_blank` and `match_origin_as_fallback`.
- **ChatGPT, Copilot and You.com:** added the ad units EasyList, uBlock and AdGuard currently target (ChatGPT `data-ad-card-root` and image cards, Copilot `data-ads-rg`, You.com `youchat-ads`), plus Character.ai's ad slot.
- **Page breakage:** Armorly proxied `window.sponsored`, so any page with `var sponsored = …` got Armorly's object back. Sponsored.so turned out not to exist (unregistered domain, no SDK anywhere) and has been removed. Proxied SDK calls now resolve to `{ filled: false }` instead of `undefined`, so publisher code like `const { filled } = await koah.requestAd(…)` no longer throws.
- **Vendor sites keep working:** every network rule now exempts requests made by the vendor's own sites, so their docs and dashboards load. Ads are still blocked on publisher sites.

### Removed
- Monetzly's selectors and globals. It has no browser SDK: it rewrites the LLM stream server-side. Only its API host stays blocked.
- `zeroclick.io` (seller payments, not ads), `koahlabs.com` (docs and dashboard only), and the EarnLayer domain rules. EarnLayer is defunct, and `earnlayerai.com` now belongs to an unrelated site.

## [2.10.0]

### Added
- **Blocks the rest of the AI ad networks.** Coverage now spans every AI ad network with a published browser SDK or ad domain, not just the original four. Selectors come from each network's real npm SDK, and domains are cross-checked against EasyList/EasyPrivacy:
  - **Kontext** (`.kontextso-ad-container`, ad iframes from `server.megabrain.co`)
  - **Gravity** (`[data-gravity-ad]`, `[data-gravity-frame]`, `window.gravityPixel`, `trygravity.ai/.com`)
  - **Thrad** (`window.thrad`, `sdk.thrad.ai`, `thrads.ai`)
  - **ZeroClick** (`zeroclick.io`/`.ai` badge + API)
  - **EarnLayer** (`.earnlayer-ad`, `earnlayerai.com`)
  - **Lulu** (`ads.getlulu.dev` sponsored links)
  - **ChatAds** (`getchatads.com`)
  - **Koah** (adds `koahlabs.com`)

  13 new network rules.
- **ChatGPT, Copilot and You.com first-party ads.** Added the ChatGPT ad units EasyList currently tracks on chatgpt.com (`aside[data-assistant-ads-unit]`, `bazaar-*` shopping cards, "Ad options" cards, `section:has(> [aria-label="Sponsored"])`, …) and added Copilot's `ads-card` and You.com's `microsoft-ads`.
- **Chrome Web Store listing stills, automated.** The `@demo` Playwright test now records at 1280×800 (the listing hero aspect), and a new `scripts/make-listing-stills.sh` extracts `docs/listing/before.png` (Armorly OFF, sponsored card visible) and `docs/listing/after.png` (Armorly ON, card gone) straight from the same source webm. One command end-to-end: `npm run stills`. SPEC.md Phase 3.4 items previously requiring a manual screen capture are now reproducible.

### Fixed
- Platform and SDK selectors now run before the generic label selectors, so removing an inner "Sponsored" label no longer leaves the outer ad container behind.
- **Imprezia ads are now actually blocked.** Real Imprezia publishers (e.g. TravelDealz.ai) bundle the SDK with no `window.Imprezia` global and route it through a same-origin `/api/proxy`, so neither the SDK proxy nor the `||imprezia.ai^` rule ever fired and the "Sponsored by …" cards stayed on the page. Armorly now removes Imprezia's card markup (`a.imprezia-card`, `.imprezia-card-banner-html`, `[data-imprezia-viewability-gate]`) on every site and blocks the `r.imprezia.net` tracker frames with a new network rule. A new Playwright fixture ([tests/fixtures/imprezia-bundled.html](tests/fixtures/imprezia-bundled.html)) reproduces the bundled, proxied setup; its test fails on the old code and passes now. Pattern version bumped to `2026-10-16`.

### Changed
- Hero `docs/demo.gif` regenerated at the new 1280×800 source resolution — file size dropped to 422 KB even though the source is now taller, because the regenerated palette dedupes better against the cleaner background.

## [2.9.0]

### Fixed
- **Per-site disable now actually disables SDK interception.** The popup's "Protect this site" toggle was gating only the isolated-world `ai-ad-blocker.js` — DOM removal stopped on disabled hosts, but `sdk-blocker.js` (MAIN world) kept its proxies installed because content scripts in MAIN world can't read `chrome.storage`. So a legit page using `window.Koah` (etc.) as a non-ad global on a disabled site stayed broken. Fix: when `ai-ad-blocker.js` sees its host is disabled, it now posts `{source:'armorly', type:'disable-site'}` to MAIN world; `sdk-blocker.js` listens and tears down every installed proxy (`Object.defineProperty` now uses `configurable: true` so removal works). New Playwright test asserts `window.Koah` is `undefined` after seeding `disabled_domains` and reloading.
- **SDK auto-update reaches the interceptor.** Phase 4.4 wired the daily refresh into `chrome.storage.local.cached_patterns` and merged the snapshot into the isolated-world script's patterns object — but the MAIN-world [sdk-blocker.js](extension/content/sdk-blocker.js) only saw the bundled list, so any *newly-named* SDK from the daily refresh was never proxied. Fix: when the isolated-world script merges a newer snapshot, it postMessages the updated function list to MAIN world; sdk-blocker installs proxies for any names it hasn't seen yet (deduped via a Set). New Playwright test seeds a synthetic name in `cached_patterns` and asserts the proxy lands.

### Added
- **Automated demo recording (Phase 3).** New ChatGPT-styled fixture page ([tests/fixtures/chatgpt-mock.html](tests/fixtures/chatgpt-mock.html)) plus an off→on storyboard in the `@demo` Playwright test produce a deterministic 7.6-second walkthrough. `./scripts/make-demo-gif.sh` converts the webm to a 900 KB GIF via ffmpeg + gifsicle. Output is committed at [docs/demo.gif](docs/demo.gif) and embedded at the top of the README — what used to require a manual screen recording now lives in the repo and replays the same every build.
- **`npm run demo`** now actually records video. Sets `ARMORLY_DEMO=1`, which flips `recordVideo` on the persistent context (Playwright's `use.video` config doesn't apply to manually-launched contexts, so the option is wired directly in [tests/extension.spec.ts](tests/extension.spec.ts)) and runs only the `@demo`-tagged walkthrough at 1280×720.
- **[docs/RELEASING.md](docs/RELEASING.md)** — runbook for the tag-driven release flow: version-bump checklist, the secrets needed per store, manual-only stores, and rollback procedure.
- Phase 2.5 `@demo`-tagged Playwright test (separate from the four functional gates) exercising the full off→on user journey, used as the video source for Phase 3.
- **README restructured** along the SPEC.md Phase 1.1 outline: install table at the top, "Why ads will destroy AI" essay below the practical sections, developer content under a single "For developers" heading, build-status badge added. Stale facts corrected — limitation #4 now reflects the v2.5.0 auto-update, limitation #12's "no network-level blocking" claim removed (we added that in v2.3.0), the project tree now lists `background.js`, `sdk-blocker.js`, `rules/`, and `ad-patterns.json`.

### Changed
- CI: switched `npm install` → `npm ci` (we have a committed lock file) and set `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true` at workflow level to opt into Node 24 ahead of GitHub's June 2026 default flip. Silences the deprecation banner on every run.
- `Object.defineProperty` for SDK proxies is now `configurable: true` (was `false`). The trade-off: a hostile page could `delete window.<SDK>` to evade us. The targeted ad SDKs don't do this, and the upside is that the per-site disable bridge can actually remove proxies.

## [2.8.0]

### Fixed
- **Critical: SDK global-object interception was broken since launch.** The SDK-blocking proxies were being installed on the content script's *isolated-world* `window`, which is a different object from the page's `window`. Page-level scripts reading `window.Koah` (etc.) never saw the proxy, so the headline feature of the extension was a no-op in production. The hidden bug went unnoticed because the SDKs in question also default to `undefined` when not loaded — there was no behavioural difference. This release moves the proxy installer to a new MAIN-world content script ([extension/content/sdk-blocker.js](extension/content/sdk-blocker.js)); the isolated-world script now listens for a postMessage from it and bumps the stats counter on each absorbed call. Detected by Phase 2's new fixture test.

### Added
- **Phase 2 Playwright harness.** `npm test` builds the extension, boots a tiny static server, and exercises the built `build/` directory against fixture pages under headed Chromium. Four tests gate every commit: SDK proxy install, DOM removal of `[data-sponsored="true"]` and `[data-koah-ad]`, affiliate-param stripping (with non-affiliate params preserved), and the hidden-injection shield emptying white-on-white text. Real-chatbot smoke tests are intentionally out of scope — see [tests/README.md](tests/README.md).
- New CI job (`test`) runs Playwright under `xvfb` after the build matrix passes.

### Notes
- `extension/lib/ad-patterns.js` is now copied to `lib/ad-patterns-main.js` at build time because Chrome dedupes identical content-script paths across world entries, leaving the MAIN-world entry without a patterns dependency. Source still has one file.

## [2.7.0]

### Added
- **Six browser targets, all built in CI.** `./build.sh` now accepts `chrome`, `firefox`, `edge`, `brave`, `opera`, and `safari`. The non-Firefox targets are byte-identical to `chrome` with renamed output; Firefox keeps its `jq` manifest transform. Safari produces an extension source bundle ready for `xcrun safari-web-extension-converter` on macOS.
- **CI matrix.** `.github/workflows/build.yml` now uses a strategy matrix over all six targets so every push and PR proves every browser build.
- **GitHub Release on every tag.** `.github/workflows/release.yml` builds all six zips, creates a GitHub Release with auto-generated notes, and attaches every zip to it. This is the canonical distribution channel for Safari, Opera, and Brave — and a useful fallback for the auto-published stores.
- **Edge auto-deploy job.** Tag-triggered Chrome / Firefox / Edge store publishing remains gated on `vars.DEPLOY_*` + secrets; the workflow stays green until each store is wired up.

### Notes
- Safari / Opera have no public publishing API; submit the matching `armorly-<browser>.zip` from the GitHub Release manually.
- Brave reuses the Chrome Web Store listing; `armorly-brave.zip` exists for sideload/testing.
- Tagging now validates that the tag's version matches the manifest version before any deploy runs.

## [2.6.0]

### Added
- **Multi-target build.** `./build.sh chrome` (default) and `./build.sh firefox` produce browser-specific zips (`armorly-chrome.zip`, `armorly-firefox.zip`). Edge accepts the Chrome zip unmodified. Firefox manifest is generated via `jq` with `browser_specific_settings.gecko.id`, `strict_min_version: "115.0"` (ESR baseline), and `background.scripts` (the AMO-recommended MV3 form). The legacy `armorly-extension.zip` is preserved as an alias for the Chrome build.
- **`.github/workflows/build.yml`** runs on every push and PR to `main`: validates JSON, syntax-checks every JS file with `node --check`, asserts that `BUNDLED_VERSION` matches `ad-patterns.json`, builds both targets, and uploads the zips as artifacts.
- **`.github/workflows/release.yml`** scaffolds publish jobs for the Chrome Web Store, Firefox AMO, and Edge Add-ons when a `v*` tag is pushed. Each job is gated on a per-store `vars.DEPLOY_*` flag plus the secrets it needs, so the workflow stays green until a store is wired up. See the comments at the top of `release.yml` for the exact secrets/vars each store requires.

### Notes
- Safari has no public publishing API; submissions there remain manual (App Store Connect / Transporter).
- Opera reviews manually too. Brave reuses the Chrome Web Store listing, so no separate flow is needed.

## [2.5.0]

### Added
- **Pattern auto-update.** A new background service worker ([extension/background.js](extension/background.js)) fetches `extension/lib/ad-patterns.json` from the `main` branch on install and once every 24 hours via `chrome.alarms`. Snapshots are validated against a strict schema (object/array/string types only — no functions, no eval, no remote code) and stored in `chrome.storage.local.cached_patterns`. Content scripts apply the cached snapshot before initializing, but only as a **union** with the bundled patterns: bundled values are the floor, so a compromised remote can at most ADD spurious selectors (causing self-DoS via over-removal), never REMOVE shipped protections.
- New flat-data JSON mirror at [extension/lib/ad-patterns.json](extension/lib/ad-patterns.json) — function names, domain patterns, platform selectors, and affiliate params/domains. Regex-driven detection (script URL patterns, ad-label regexes, commercial-intent regexes) intentionally stays bundled-only.
- New `alarms` permission.

### Changed
- `build.sh` now copies `background.js`, verifies the new files are present, and asserts that `BUNDLED_VERSION` in [ad-patterns.js](extension/lib/ad-patterns.js) matches the `version` field in [ad-patterns.json](extension/lib/ad-patterns.json) — bumping one without the other will fail the build instead of silently shipping a stale cache comparison.

## [2.4.0]

### Added
- **"Saw an ad we missed? Report it" link** in the popup footer. Pre-fills the [GitHub issue template](.github/ISSUE_TEMPLATE/missed-ad.md) with the current tab's URL, the Armorly version, and the user-agent string — so reports show up with the context maintainers actually need.
- **Hidden-injection toast.** When the prompt-injection shield removes content, a small dismissible toast appears in the bottom-right of the page: "Armorly blocked a hidden prompt injection." Auto-dismisses after 8s; the × button hides it permanently for that hostname (stored under `dismissed_injection_toast` in `chrome.storage.local`). Rendered in a closed shadow root so page CSS can't restyle it.

### Deferred
- Phase 4.4 (auto-update of the ad-pattern data from GitHub) is intentionally postponed — it needs `ad-patterns.js` split into pure-data JSON + a loader plus a background service worker, which is too much to land alongside two visible UX features. Tracked in SPEC.md.

## [2.3.0]

### Added
- **Network-level SDK blocking.** New static `declarativeNetRequest` ruleset ([extension/rules/ad-sdks.json](extension/rules/ad-sdks.json)) drops requests to Koah, Monetzly, Sponsored.so, and Imprezia domains before they reach the page. Defense-in-depth on top of the existing global-object interception — if the SDK inlines, the global hook still catches it.
- New `declarativeNetRequest` permission. Rules are static and shipped with the extension; nothing is loaded remotely. We deliberately do **not** include generic ad networks (AdSense, DoubleClick) — that remains uBlock/Brave territory.

### Changed
- `build.sh` copies and verifies the new `rules/` directory.

## [2.2.0]

### Added
- **Per-site whitelist.** New "Protect this site" toggle in the popup. Disabling Armorly on a domain stops both the ad-SDK interceptor and the prompt-injection shield from running there (reload to apply). Backed by `chrome.storage.local`.
- **Lifetime stats.** Popup now shows cumulative "Since install" totals for SDKs blocked, links cleaned, and elements removed, alongside the existing session counters. Includes a Reset button.
- New `storage` permission to support the above. Storage is local-only; no data leaves the browser.
- `CONTRIBUTING.md`, `SECURITY.md`, and GitHub issue templates for "missed ad" and "false positive" reports.

### Fixed
- Restored `extension/lib/ad-patterns.js` to the repository so a fresh clone builds without manual zip extraction.
- Popup footer version is now pulled from the manifest at runtime, fixing the `v2.0.2` / `v2.1.0` drift.

### Changed
- Marketing screenshots moved to `docs/screenshots/` to keep the repo root clean.
- README points at the canonical GitHub URL and documents how to verify the extension is active.
- `build.sh` reads the version from the manifest so the banner no longer drifts on bumps.

## [2.1.0] — Chrome Web Store launch

- First public release on the Chrome Web Store.
- AI ad-SDK interception (Koah, Monetzly, Sponsored.so, Imprezia, and more).
- Sponsored-label DOM removal across ChatGPT, Perplexity, Grok, Claude, and Gemini.
- Affiliate-link parameter cleaning.
- Hidden-prompt-injection shield (pattern-based, conservative).
- Popup status UI showing the monitored site and per-session block counts.
