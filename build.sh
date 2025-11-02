#!/bin/bash
# Build script for Armorly Chrome Extension
# Creates a clean package ready for Chrome Web Store submission

set -e  # Exit on error

echo "🛡️  Building Armorly Extension..."

# Clean previous build
echo "📦 Cleaning previous build..."
rm -rf build
rm -f armorly-extension.zip

# Create build directory
echo "📁 Creating build directory..."
mkdir -p build

# Copy required files
echo "📋 Copying extension files..."

# Core files
cp manifest.json build/
cp armorly.jpg build/

# Directories
cp -r icons build/
cp -r background build/
cp -r content build/
cp -r lib build/
cp -r popup build/
cp -r options build/
cp -r rules build/

# Remove unnecessary files from lib
echo "🧹 Removing development files..."
rm -f build/lib/pattern-library.module.js
rm -f build/content/pattern-library-content.js

# Verify critical files exist
echo "✅ Verifying build..."
if [ ! -f build/manifest.json ]; then
  echo "❌ Error: manifest.json missing!"
  exit 1
fi
if [ ! -f build/lib/pattern-library-global.js ]; then
  echo "❌ Error: pattern-library-global.js missing!"
  exit 1
fi
if [ ! -f build/lib/performance-monitor-global.js ]; then
  echo "❌ Error: performance-monitor-global.js missing!"
  exit 1
fi

# Create zip package
echo "📦 Creating extension package..."
cd build
zip -r ../armorly-extension.zip . -q
cd ..

# Get file size
SIZE=$(du -h armorly-extension.zip | cut -f1)

echo ""
echo "✅ Extension packaged successfully!"
echo "📦 Package: armorly-extension.zip"
echo "📊 Size: $SIZE"
echo ""
echo "🚀 Next steps:"
echo "   1. Go to chrome://extensions/"
echo "   2. Enable 'Developer mode'"
echo "   3. Click 'Load unpacked' and select the 'build' folder"
echo "   OR"
echo "   4. Upload armorly-extension.zip to Chrome Web Store"
echo ""

