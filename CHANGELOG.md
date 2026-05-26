# Changelog

All notable user-facing changes to Armorly are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
