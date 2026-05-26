# Changelog

All notable user-facing changes to Armorly are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
