# Contributing to Armorly

Thanks for helping keep AI chatbots ad-free. The most useful contribution you can make is teaching Armorly about a new ad SDK, sponsored selector, or affiliate-tracking parameter.

## Adding a new ad-network pattern

1. **Add an entry to `adSDKs`** in [extension/lib/ad-patterns.js](extension/lib/ad-patterns.js). At minimum, include:
   - The SDK's global object name(s) (e.g. `window.Koah`).
   - The script URL or domain it loads from, if any.
   - A short comment with a link to the network's docs or a real-world page where you saw it.

2. **Add platform selectors** if the ad surfaces in a specific chatbot's DOM. Selectors live alongside the SDK definition; keep them tight to avoid false positives on legitimate UI.

3. **Add affiliate / tracking parameters** to the `AFFILIATE_PARAMS` or `REDIRECT_DOMAINS` lists if the network rewrites outbound links.

4. **Run the test suite** once it lands (see [SPEC.md](SPEC.md) Phase 2). Until then, manually load the unpacked `build/` extension and verify on a real page or a fixture you include with the PR.

5. **Open a PR** with:
   - A fixture page (HTML file under `tests/fixtures/`, even if the harness isn't merged yet) that reproduces the ad.
   - A before/after screenshot or short console transcript.
   - A note about where you encountered the network in the wild.

## Bug reports

Use the issue templates:

- **"Missed ad"** — Armorly didn't block something it should have.
- **"False positive"** — Armorly hid legitimate content.

Include the URL, a screenshot, and the relevant console output (`[Armorly] …` lines).

## Code style

- Vanilla JS, no build step beyond `./build.sh` copying files.
- Prefer adding to the data-driven pattern library over adding new code paths.
- Keep content scripts cheap — they run at `document_start` on every page.

## Security

If you find a vulnerability that affects users, please follow the disclosure process in [SECURITY.md](SECURITY.md) rather than opening a public issue.
