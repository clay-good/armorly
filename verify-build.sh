#!/bin/bash

# Verify build directory is ready for testing

echo "🔍 Verifying build directory..."
echo ""

# Check if build directory exists
if [ ! -d "build" ]; then
    echo "❌ build/ directory not found!"
    exit 1
fi

echo "✅ build/ directory exists"

# Check for manifest
if [ ! -f "build/manifest.json" ]; then
    echo "❌ build/manifest.json not found!"
    exit 1
fi
echo "✅ build/manifest.json exists"

# Check popup files
if [ ! -f "build/popup/popup.js" ]; then
    echo "❌ build/popup/popup.js not found!"
    exit 1
fi
echo "✅ build/popup/popup.js exists"

if [ ! -f "build/popup/popup.html" ]; then
    echo "❌ build/popup/popup.html not found!"
    exit 1
fi
echo "✅ build/popup/popup.html exists"

if [ ! -f "build/popup/popup.css" ]; then
    echo "❌ build/popup/popup.css not found!"
    exit 1
fi
echo "✅ build/popup/popup.css exists"

# Check if popup.js has the new debug code
if grep -q "DEBUG_MODE = true" build/popup/popup.js; then
    echo "✅ build/popup/popup.js has DEBUG_MODE"
else
    echo "❌ build/popup/popup.js missing DEBUG_MODE - needs sync!"
    echo "   Run: ./sync-to-build.sh"
    exit 1
fi

if grep -q "Popup loaded - Starting initialization" build/popup/popup.js; then
    echo "✅ build/popup/popup.js has new initialization code"
else
    echo "❌ build/popup/popup.js has old initialization code - needs sync!"
    echo "   Run: ./sync-to-build.sh"
    exit 1
fi

# Check line count
BUILD_LINES=$(wc -l < build/popup/popup.js | tr -d ' ')
SOURCE_LINES=$(wc -l < popup/popup.js | tr -d ' ')

if [ "$BUILD_LINES" -eq "$SOURCE_LINES" ]; then
    echo "✅ build/popup/popup.js line count matches source ($BUILD_LINES lines)"
else
    echo "⚠️  Line count mismatch: build=$BUILD_LINES, source=$SOURCE_LINES"
    echo "   Run: ./sync-to-build.sh"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Build directory is ready!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📋 Next steps:"
echo "  1. Go to chrome://extensions"
echo "  2. Remove Armorly if already loaded"
echo "  3. Click 'Load unpacked'"
echo "  4. Select: $(pwd)/build"
echo "  5. Click Armorly icon to open popup"
echo "  6. Right-click popup → Inspect"
echo "  7. Check console for debug output"
echo ""
echo "Expected console output:"
echo "  [Armorly] Popup loaded - Starting initialization"
echo "  [Armorly Debug] DOM Content Loaded event fired"
echo "  [Armorly Debug] Available elements in DOM: {...}"
echo "  ..."
echo "  [Armorly] Popup initialization complete ✓"
echo ""
echo "❌ Should NOT see:"
echo "  [Armorly] Error loading statistics"
echo "  [Armorly] Error loading performance stats"
echo "  [Armorly] Error loading AI agent status"
echo ""

