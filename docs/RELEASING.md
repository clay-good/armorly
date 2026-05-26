# Releasing Armorly

Releases are tag-driven. Pushing a `v*` tag triggers [release.yml](../.github/workflows/release.yml), which:

1. Builds all six browser targets (`chrome`, `firefox`, `edge`, `brave`, `opera`, `safari`).
2. Creates a GitHub Release with auto-generated notes and every zip attached.
3. Runs gated store-publish jobs for Chrome / Firefox / Edge.

## Cutting a release

```bash
# 1. Bump the manifest version (single source of truth).
#    Update extension/manifest.json's "version" field.
#    Update package.json's "version" field to match (kept for npm tooling).
#    Don't forget to also bump the date in extension/lib/ad-patterns.json's
#    "version" field AND extension/lib/ad-patterns.js's BUNDLED_VERSION
#    const if you changed any auto-updatable data field. The build script
#    fails if the two are out of sync.

# 2. Add an entry at the top of CHANGELOG.md under the new version.

# 3. Commit and push to main.
git commit -am "v<X.Y.Z>: <one-line summary>"
git push origin main

# 4. After CI is green on main, tag and push.
#    The tag value (minus the `v`) must match the manifest version exactly,
#    or the release workflow refuses to deploy.
git tag v<X.Y.Z>
git push origin v<X.Y.Z>
```

## Store auto-publish (one-time setup per store)

Each store job runs only when its `vars.DEPLOY_*` flag is `"true"` AND the corresponding secrets exist. Until both are set, the job is a green no-op.

### Chrome Web Store

- Repo → Settings → Variables → `DEPLOY_CHROME = "true"`
- Repo → Settings → Secrets, set: `CHROME_EXTENSION_ID`, `CHROME_CLIENT_ID`, `CHROME_CLIENT_SECRET`, `CHROME_REFRESH_TOKEN`
- Reference: [developer.chrome.com/docs/webstore/using-api](https://developer.chrome.com/docs/webstore/using-api/)

### Firefox AMO

- Repo → Settings → Variables → `DEPLOY_FIREFOX = "true"`
- Repo → Settings → Secrets, set: `FIREFOX_JWT_ISSUER`, `FIREFOX_JWT_SECRET`
- Generate at [addons.mozilla.org/.../api/key/](https://addons.mozilla.org/en-US/developers/addon/api/key/)
- First submission must be done manually; thereafter every tag updates the existing listing.

### Edge Add-ons

- Repo → Settings → Variables → `DEPLOY_EDGE = "true"`
- Repo → Settings → Secrets, set: `EDGE_PRODUCT_ID`, `EDGE_CLIENT_ID`, `EDGE_CLIENT_SECRET`
- Generate via Partner Center → API access.

## Manual stores

Safari, Opera, and (transitionally) Brave have no public publishing API:

- **Safari** — App Store Connect submission requires Xcode + an Apple Developer Program account. Build the `armorly-safari.zip` from the GitHub Release locally on macOS and wrap with `xcrun safari-web-extension-converter`. Manual upload from there.
- **Opera** — Upload `armorly-opera.zip` from the GitHub Release to [addons.opera.com](https://addons.opera.com/). Manual review takes days.
- **Brave** — Reuses the Chrome Web Store listing once `DEPLOY_CHROME` is wired up; nothing to do per release.

## What the release tag actually verifies

The release job runs an explicit check that the tag matches the manifest version before any deploy fires:

```bash
TAG="${GITHUB_REF_NAME#v}"
MANIFEST=$(jq -r .version extension/manifest.json)
[ "$TAG" = "$MANIFEST" ] || exit 1
```

So `git tag v2.9.0` on a commit where `manifest.json` says `2.8.0` fails fast with a clear error instead of pushing a mislabelled build to the stores.

## Rolling back

GitHub Releases don't auto-roll-back on later edits. To pull a release:

1. `gh release delete v<X.Y.Z>` — removes the GitHub Release and its assets.
2. `git push origin --delete v<X.Y.Z>` — removes the tag.

Stores require manual rollback:

- **Chrome Web Store** — the dashboard lets you revert to the previous reviewed version.
- **Firefox AMO** — same, via the developer dashboard.
- **Edge** — submit the previous version's zip again with a higher version field (Edge doesn't allow re-publishing the same `version`).

For a stuck deploy, prefer **fixing forward** (a new tagged release with the fix) over rolling back, unless the bug is actively harmful.
