# Changelog

All notable user-facing changes to Armorly are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed
- Restored `extension/lib/ad-patterns.js` to the repository so a fresh clone builds without manual zip extraction.
- Popup footer version is now pulled from the manifest at runtime, fixing the `v2.0.2` / `v2.1.0` drift.

### Changed
- Marketing screenshots moved to `docs/screenshots/` to keep the repo root clean.
- README points at the canonical GitHub URL and documents how to verify the extension is active.

### Added
- `CONTRIBUTING.md`, `SECURITY.md`, and GitHub issue templates for "missed ad" and "false positive" reports.

## [2.1.0] — Chrome Web Store launch

- First public release on the Chrome Web Store.
- AI ad-SDK interception (Koah, Monetzly, Sponsored.so, Imprezia, and more).
- Sponsored-label DOM removal across ChatGPT, Perplexity, Grok, Claude, and Gemini.
- Affiliate-link parameter cleaning.
- Hidden-prompt-injection shield (pattern-based, conservative).
- Popup status UI showing the monitored site and per-session block counts.
