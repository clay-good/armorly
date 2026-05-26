# Changelog

All notable user-facing changes to Armorly are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **Automated demo recording (Phase 3).** New ChatGPT-styled fixture page ([tests/fixtures/chatgpt-mock.html](tests/fixtures/chatgpt-mock.html)) plus an off→on storyboard in the `@demo` Playwright test produce a deterministic 7.6-second walkthrough. `./scripts/make-demo-gif.sh` converts the webm to a 900 KB GIF via ffmpeg + gifsicle. Output is committed at [docs/demo.gif](docs/demo.gif) and embedded at the top of the README — what used to require a manual screen recording now lives in the repo and replays exactly the same every build.

### Changed
- **README restructured** along the lines of SPEC.md Phase 1.1: install table moved to the top, "Why ads will destroy AI" essay shifted below the practical sections, developer content consolidated under a single "For developers" heading. Stale facts corrected — limitation #4 now reflects the v2.5.0 pattern auto-update, limitation #12's "no network-level blocking" claim removed (we added that in v2.3.0), the project-structure tree now lists `background.js`, `sdk-blocker.js`, `rules/`, and `ad-patterns.json`. Added a build-status badge linking to the [build workflow](.github/workflows/build.yml).
- **`npm run demo`** now actually produces a webm. It sets `ARMORLY_DEMO=1`, which flips `recordVideo` on the persistent context and runs only the `@demo`-tagged walkthrough — the existing fixture pages, end to end, at 1280×720. Output lands in `test-results/demo/`.

### Added
- **[docs/RELEASING.md](docs/RELEASING.md)** — runbook for the tag-driven release flow: version-bump checklist, the secrets needed per store, manual-only stores, and rollback procedure.
- Phase 2.5 `@demo`-tagged Playwright test exercising the full fake-ads → hidden-injection walkthrough, used as the video source for Phase 3.

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
