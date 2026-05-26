#!/bin/bash
# Build script for Armorly browser extension.
#
# Usage:
#   ./build.sh               # Chrome Web Store target (default)
#   ./build.sh chrome        # explicit
#   ./build.sh firefox       # Firefox MV3-compatible zip
#   ./build.sh edge          # Edge Add-ons (Chromium; same content as chrome)
#   ./build.sh brave         # Brave (uses Chrome Web Store listing, same content)
#   ./build.sh opera         # Opera Add-ons (Chromium; same content as chrome)
#   ./build.sh safari        # Safari source bundle (needs xcrun
#                            # safari-web-extension-converter on macOS)
#
# Only Firefox needs manifest mutations. The other targets are byte-identical
# to the Chrome zip with renamed output for clarity.

set -e

TARGET="${1:-chrome}"
case "$TARGET" in
  chrome|firefox|edge|brave|opera|safari) ;;
  *)
    echo "❌ Unknown target: $TARGET (expected chrome|firefox|edge|brave|opera|safari)"
    exit 1
    ;;
esac

VERSION=$(grep -E '"version"' extension/manifest.json | head -1 | sed -E 's/.*"version": *"([^"]+)".*/\1/')

echo "🛡️  Building Armorly v${VERSION} for ${TARGET}..."

# Clean previous build
echo "📦 Cleaning previous build..."
rm -rf build
# Remove the artifact for the target we're about to produce. We don't touch
# zips for OTHER targets so cross-target builds don't wipe them.
rm -f "armorly-${TARGET}.zip"
# Legacy alias only ever follows the Chrome build.
if [ "$TARGET" = "chrome" ]; then rm -f armorly-extension.zip; fi

mkdir -p build

echo "📋 Copying extension files..."
cp extension/manifest.json build/
cp -r extension/icons build/
cp -r extension/content build/
cp -r extension/lib build/
cp -r extension/popup build/
cp -r extension/rules build/
cp extension/background.js build/

# Firefox needs a tweaked manifest: gecko addon ID + minimum version, and a
# `background.scripts` field instead of `background.service_worker` (the
# service_worker key is only stable in Firefox 121+, while scripts is the
# AMO-recommended MV3 form for current ESR).
if [ "$TARGET" = "firefox" ]; then
  if ! command -v jq >/dev/null 2>&1; then
    echo "❌ jq is required to build the Firefox target. Install via Homebrew (mac) or apt (linux)."
    exit 1
  fi
  jq '. + {
        "browser_specific_settings": {
          "gecko": {
            "id": "armorly@claygood.com",
            "strict_min_version": "115.0"
          }
        }
      } | .background = { "scripts": ["background.js"] }' \
    extension/manifest.json > build/manifest.json
fi

# Verify critical files
echo "✅ Verifying build..."
for f in build/manifest.json build/lib/ad-patterns.js build/lib/ad-patterns.json \
         build/content/ai-ad-blocker.js build/content/hidden-content-blocker.js \
         build/rules/ad-sdks.json build/background.js; do
  if [ ! -f "$f" ]; then
    echo "❌ Error: $f missing!"
    exit 1
  fi
done

# Phase 4.4: BUNDLED_VERSION in ad-patterns.js must match the `version` field
# in ad-patterns.json — otherwise mergeCachedPatterns misbehaves.
JS_VER=$(grep -E "const BUNDLED_VERSION" extension/lib/ad-patterns.js | head -1 | sed -E "s/.*'([^']+)'.*/\1/")
JSON_VER=$(grep -E '"version"' extension/lib/ad-patterns.json | head -1 | sed -E 's/.*"version": *"([^"]+)".*/\1/')
if [ "$JS_VER" != "$JSON_VER" ]; then
  echo "❌ Error: BUNDLED_VERSION ($JS_VER) in ad-patterns.js does not match version ($JSON_VER) in ad-patterns.json"
  exit 1
fi

# Package
ZIP_NAME="armorly-${TARGET}.zip"
echo "📦 Creating ${ZIP_NAME}..."
cd build
zip -r "../${ZIP_NAME}" . -q
cd ..

# Backwards-compat alias: keep armorly-extension.zip pointing at the chrome
# build so anyone with bookmarks or scripts referencing the old name still
# gets a usable artifact.
if [ "$TARGET" = "chrome" ]; then
  cp "${ZIP_NAME}" armorly-extension.zip
fi

SIZE=$(du -h "${ZIP_NAME}" | cut -f1)
FILE_COUNT=$(find build -type f | wc -l | tr -d ' ')

echo ""
echo "✅ Extension packaged successfully!"
echo "📦 Package: ${ZIP_NAME}"
echo "📊 Size: $SIZE"
echo "📁 Files: $FILE_COUNT"
echo ""
case "$TARGET" in
  chrome|edge|brave|opera)
    echo "🚀 Next steps:"
    echo "   1. Go to chrome://extensions/ (or edge://extensions, opera://extensions, brave://extensions)"
    echo "   2. Enable 'Developer mode'"
    echo "   3. Click 'Load unpacked' and select the 'build' folder"
    echo "   OR"
    echo "   4. Upload ${ZIP_NAME} to the corresponding extension store."
    ;;
  firefox)
    echo "🚀 Next steps:"
    echo "   1. Go to about:debugging#/runtime/this-firefox"
    echo "   2. Click 'Load Temporary Add-on...' and select build/manifest.json"
    echo "   OR"
    echo "   3. Upload ${ZIP_NAME} to addons.mozilla.org"
    ;;
  safari)
    echo "🚀 Next steps (Safari requires macOS + Xcode):"
    echo "   1. unzip ${ZIP_NAME} into a working directory"
    echo "   2. xcrun safari-web-extension-converter ./<that dir>"
    echo "   3. Open the generated Xcode project, sign with your Apple Dev ID, run."
    echo "   App Store Connect submission has no public API — upload manually."
    ;;
esac

# TODO(phase-2): headless smoke test — load the built extension in Chromium
# and assert the console emits `[Armorly] AI ad blocker active`. See SPEC.md
# Phase 2 (Playwright harness) for the implementation plan.
echo ""
