# Quick Debug Reference Card

## 🚀 Quick Start

1. Load extension in browser
2. Click Armorly icon
3. Right-click popup → "Inspect"
4. Check Console tab

## 🔍 What to Look For

### ✅ Good (No Errors)
```
[Armorly] Popup loaded - Starting initialization
[Armorly Debug] Element check: protection-toggle - EXISTS
[Armorly Debug] Step 1: Complete
[Armorly] Popup initialization complete ✓
```

### ⚠️ Info (Safe to Ignore)
```
[Armorly Debug] Element check: pages-scanned - MISSING
[Armorly Debug] INFO - avg-overhead element not found (optional)
```
These are optional elements - code handles them gracefully.

### ❌ Error (Needs Attention)
```
[Armorly] Error loading statistics: TypeError: ...
[Armorly Debug] FAILED with error: ...
```
Check the error stack trace for details.

## 🛠️ Common Fixes

### Error: "Cannot set properties of null"
**Cause**: Trying to access missing DOM element
**Fix**: Already handled with null checks - should not appear anymore

### Error: "Cannot read properties of null"
**Cause**: Trying to read from missing DOM element
**Fix**: Already handled with null checks - should not appear anymore

### Warning: "Content script not available"
**Cause**: Normal - some pages don't allow content scripts
**Fix**: Not an error - code handles it correctly

### Error: "Response was not successful"
**Cause**: Background script not responding
**Fix**: Check if background.js is running:
1. Go to `chrome://extensions`
2. Find Armorly
3. Click "service worker" or "background page"
4. Check for errors there

## 📊 Debug Mode Control

### Turn ON (Verbose Logging)
In `popup/popup.js` line 8:
```javascript
const DEBUG_MODE = true;
```

### Turn OFF (Production)
```javascript
const DEBUG_MODE = false;
```

## 🎯 Element Status Quick Check

Look for this log on popup load:
```javascript
[Armorly Debug] Available elements in DOM: {
  'protection-toggle': true,     // ✅ Required
  'status-indicator': true,      // ✅ Required
  'status-text': true,           // ✅ Required
  'threats-blocked': true,       // ✅ Required
  'current-url': true,           // ✅ Required
  'threat-list': true,           // ✅ Required
  'view-docs': true,             // ✅ Required
  'pages-scanned': false,        // ⚠️ Optional
  'avg-overhead': false,         // ⚠️ Optional
  'perf-status': false,          // ⚠️ Optional
  'ai-agent-status': false,      // ⚠️ Optional
  'scan-page': false,            // ⚠️ Optional
  'check-memory': false,         // ⚠️ Optional
  'view-performance': false,     // ⚠️ Optional
  'open-settings': false         // ⚠️ Optional
}
```

## 📝 What to Report

If errors persist, share:
1. **Browser**: BrowserOS / Perplexity Comet / Chrome / etc.
2. **Page URL**: Where you opened the popup
3. **Console Output**: Full log from popup DevTools
4. **Element Status**: The "Available elements in DOM" object
5. **Error Stack**: Any error stack traces

## 🔧 Advanced Debugging

### Check Background Script
1. Go to `chrome://extensions`
2. Find Armorly → Click "service worker"
3. Check console for errors

### Check Content Script
1. Open any webpage
2. Press F12 (DevTools)
3. Console tab
4. Look for `[Armorly]` messages

### Reload Extension
1. Go to `chrome://extensions`
2. Find Armorly
3. Click reload icon 🔄
4. Try popup again

## 💡 Tips

- **Clear Console**: Click 🚫 icon to clear old messages
- **Filter Logs**: Type "Armorly" in console filter box
- **Preserve Log**: Check "Preserve log" to keep messages across reloads
- **Copy Output**: Right-click console → "Save as..." to export logs

## ✨ Success Indicators

You should see:
- ✅ No red error messages
- ✅ "Popup initialization complete ✓"
- ✅ All required elements show "EXISTS"
- ✅ Optional elements show "MISSING" (OK) or "EXISTS" (better)
- ✅ Protection toggle works
- ✅ Statistics display correctly

