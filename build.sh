#!/bin/bash
# Build script for Armorly Chrome Extension v2.0.1
# Minimal AI ad blocker - no UI, no network blocking, just client-side protection

set -e  # Exit on error

echo "🛡️  Building Armorly v2.0.1 (AI Ad Blocker)..."

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

# Directories (minimal set - no background, no rules)
cp -r extension/icons build/
cp -r extension/content build/
cp -r extension/lib build/

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
echo ""
