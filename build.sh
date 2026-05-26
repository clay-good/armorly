#!/bin/bash
# Build script for Armorly Chrome Extension
# AI ad blocker with popup UI - no network blocking, just client-side protection

set -e  # Exit on error

# Read version from manifest so this script never drifts.
VERSION=$(grep -E '"version"' extension/manifest.json | head -1 | sed -E 's/.*"version": *"([^"]+)".*/\1/')

echo "🛡️  Building Armorly v${VERSION} (AI Ad Blocker)..."

# Clean previous build
echo "📦 Cleaning previous build..."
rm -rf build
rm -f armorly-extension.zip

# Create build directory
echo "📁 Creating build directory..."
mkdir -p build

# Copy required files from extension folder
echo "📋 Copying extension files..."

# Core files
cp extension/manifest.json build/

# Directories
cp -r extension/icons build/
cp -r extension/content build/
cp -r extension/lib build/
cp -r extension/popup build/
cp -r extension/rules build/

# Verify critical files exist
echo "✅ Verifying build..."

if [ ! -f build/manifest.json ]; then
  echo "❌ Error: manifest.json missing!"
  exit 1
fi

if [ ! -f build/lib/ad-patterns.js ]; then
  echo "❌ Error: ad-patterns.js missing!"
  exit 1
fi

if [ ! -f build/content/ai-ad-blocker.js ]; then
  echo "❌ Error: ai-ad-blocker.js missing!"
  exit 1
fi

if [ ! -f build/content/hidden-content-blocker.js ]; then
  echo "❌ Error: hidden-content-blocker.js missing!"
  exit 1
fi

if [ ! -f build/rules/ad-sdks.json ]; then
  echo "❌ Error: rules/ad-sdks.json missing!"
  exit 1
fi

# Create zip package
echo "📦 Creating extension package..."
cd build
zip -r ../armorly-extension.zip . -q
cd ..

# Get file size
SIZE=$(du -h armorly-extension.zip | cut -f1)
FILE_COUNT=$(find build -type f | wc -l | tr -d ' ')

echo ""
echo "✅ Extension packaged successfully!"
echo "📦 Package: armorly-extension.zip"
echo "📊 Size: $SIZE"
echo "📁 Files: $FILE_COUNT"
echo ""
echo "🚀 Next steps:"
echo "   1. Go to chrome://extensions/"
echo "   2. Enable 'Developer mode'"
echo "   3. Click 'Load unpacked' and select the 'build' folder"
echo "   OR"
echo "   4. Upload armorly-extension.zip to Chrome Web Store"

# TODO(phase-2): headless smoke test — load the built extension in Chromium
# and assert the console emits `[Armorly] AI ad blocker active`. See SPEC.md
# Phase 2 (Playwright harness) for the implementation plan.
echo ""
