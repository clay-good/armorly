#!/bin/bash

# Script to replace console.log statements with logger calls
# This is a helper script for the logging optimization task

echo "🔍 Replacing console.log statements with logger calls..."
echo ""

# Count current console.log statements
TOTAL=$(grep -r "console\.log" --include="*.js" . | grep -v node_modules | grep -v build | grep -v scripts | wc -l | tr -d ' ')
echo "Found $TOTAL console.log statements"
echo ""

# Background scripts (use logger.info or logger.debug)
echo "📝 Processing background scripts..."

# Service worker
if [ -f "background/service-worker.js" ]; then
  echo "  - background/service-worker.js"
fi

# Other background scripts
for file in background/*.js; do
  if [ -f "$file" ] && [ "$file" != "background/service-worker.js" ]; then
    echo "  - $file"
  fi
done

# Content scripts (use window.ArmorlyLogger)
echo ""
echo "📝 Processing content scripts..."
for file in content/*.js; do
  if [ -f "$file" ]; then
    echo "  - $file"
  fi
done

# Lib scripts
echo ""
echo "📝 Processing lib scripts..."
for file in lib/*.js; do
  if [ -f "$file" ] && [[ ! "$file" =~ "logger" ]]; then
    echo "  - $file"
  fi
done

echo ""
echo "✅ Analysis complete!"
echo ""
echo "Note: This script only analyzes files. Manual replacement is recommended"
echo "to ensure correct component names and log levels are used."
echo ""
echo "Replacement pattern:"
echo "  console.log('[Armorly Component]', 'message') → logger.info('Component', 'message')"
echo "  console.error('[Armorly]', 'error') → logger.error('Component', 'error')"
echo "  console.warn('[Armorly]', 'warning') → logger.warn('Component', 'warning')"

