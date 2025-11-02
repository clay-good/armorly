#!/bin/bash

# Sync source files to build directory
# Run this script after making changes to source files

echo "🔄 Syncing files to build directory..."

# Sync popup files
echo "  📄 Syncing popup files..."
cp -v popup/popup.js build/popup/popup.js
cp -v popup/popup.html build/popup/popup.html
cp -v popup/popup.css build/popup/popup.css

# Sync background files
echo "  📄 Syncing background files..."
cp -v background/*.js build/background/ 2>/dev/null || true

# Sync content files
echo "  📄 Syncing content files..."
cp -v content/*.js build/content/ 2>/dev/null || true

# Sync lib files
echo "  📄 Syncing lib files..."
cp -v lib/*.js build/lib/ 2>/dev/null || true

# Sync options files
echo "  📄 Syncing options files..."
cp -v options/*.js build/options/ 2>/dev/null || true
cp -v options/*.html build/options/ 2>/dev/null || true
cp -v options/*.css build/options/ 2>/dev/null || true

# Sync manifest
echo "  📄 Syncing manifest..."
cp -v manifest.json build/manifest.json

echo ""
echo "✅ Sync complete!"
echo ""
echo "📋 Next steps:"
echo "  1. Go to chrome://extensions"
echo "  2. Find Armorly"
echo "  3. Click the 🔄 Reload button"
echo "  4. Test the extension"
echo ""

