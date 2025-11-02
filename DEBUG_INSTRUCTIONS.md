# Armorly Popup Debug Instructions

## What Was Fixed

Added comprehensive debug logging to `popup/popup.js` to help troubleshoot the null reference errors.

### Key Changes:

1. **Debug Mode Toggle** - Set `DEBUG_MODE = true` at the top of the file for verbose logging
2. **Element Checking** - Added `checkElement()` function that logs whether each element exists
3. **Function Tracing** - Every function now logs:
   - When it starts
   - What data it receives
   - What elements it's trying to access
   - Whether operations succeed or fail
   - Full error stacks when errors occur

4. **Startup Diagnostics** - On popup load, logs all available DOM elements

## How to Debug

### Step 1: Open the Extension Popup
1. Load the extension in BrowserOS or Perplexity Comet
2. Click the Armorly extension icon to open the popup

### Step 2: Open Developer Tools for the Popup
1. Right-click on the popup window
2. Select "Inspect" or "Inspect Element"
3. This opens DevTools specifically for the popup

### Step 3: Check the Console
Look for these debug messages:

```
[Armorly Debug] DOM Content Loaded event fired
[Armorly Debug] Available elements in DOM: {...}
[Armorly Debug] Step 1: Loading protection status...
[Armorly Debug] Element check: protection-toggle - EXISTS/MISSING
```

### Step 4: Identify the Problem

The debug logs will show you:

1. **Which elements are missing** - Look for "MISSING" in element checks
2. **Which function is failing** - Look for "FAILED with error" messages
3. **What line is causing the error** - Check the error stack traces
4. **What data is being received** - Check response objects from background script

### Common Issues to Look For:

#### Issue 1: Elements Don't Exist in HTML
```
[Armorly Debug] Element check: pages-scanned - MISSING
```
**Solution**: Either add the element to `popup.html` or remove the code trying to access it

#### Issue 2: Background Script Not Responding
```
[Armorly Debug] loadStatistics: Response received null
```
**Solution**: Check if the background script is running and handling messages

#### Issue 3: Content Script Not Loaded
```
[Armorly Debug] loadCurrentPageInfo: Content script not available (normal)
```
**Solution**: This is normal for some pages - the code handles it gracefully

## Turning Off Debug Mode

Once you've identified and fixed the issues, set:
```javascript
const DEBUG_MODE = false;
```

This will reduce console noise while keeping error logging active.

## What to Share

If you still see errors after checking the debug logs, please share:

1. The full console output from the popup DevTools
2. Which browser you're testing in (BrowserOS, Perplexity Comet, etc.)
3. The URL of the page where you opened the popup
4. Any error messages with their full stack traces

## Expected Output (Success)

When everything works correctly, you should see:

```
[Armorly] Popup loaded - Starting initialization
[Armorly Debug] DOM Content Loaded event fired
[Armorly Debug] Available elements in DOM: {...}
[Armorly Debug] Step 1: Loading protection status...
[Armorly Debug] Element check: protection-toggle - EXISTS
[Armorly Debug] Element check: status-indicator - EXISTS
[Armorly Debug] Element check: status-text - EXISTS
[Armorly Debug] Step 1: Complete
...
[Armorly Debug] Step 7: Complete
[Armorly] Popup initialization complete ✓
```

No errors should appear in the console!

