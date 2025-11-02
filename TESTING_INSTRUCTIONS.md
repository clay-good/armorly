# 🧪 Testing Instructions for Armorly

## ⚠️ IMPORTANT: Build Directory Issue

**The extension loads from the `build/` directory, NOT the root directory!**

When you edit source files in:
- `popup/popup.js`
- `background/*.js`
- `content/*.js`
- etc.

You MUST sync them to the `build/` directory for the browser to see the changes.

---

## 🔄 How to Test Changes

### Step 1: Make Your Edits
Edit files in the source directories:
- `popup/`
- `background/`
- `content/`
- `lib/`
- `options/`

### Step 2: Sync to Build Directory

**Option A: Use the sync script (Recommended)**
```bash
./sync-to-build.sh
```

**Option B: Manual sync**
```bash
cp popup/popup.js build/popup/popup.js
cp popup/popup.html build/popup/popup.html
cp popup/popup.css build/popup/popup.css
# ... repeat for other changed files
```

### Step 3: Reload Extension in Browser

1. Go to `chrome://extensions` (or your browser's extension page)
2. Find **Armorly**
3. Click the **🔄 Reload** button
4. Close any open Armorly popups
5. Click the Armorly icon to open a fresh popup

### Step 4: Verify Changes Loaded

Open the popup, right-click → Inspect, check console for:

```
[Armorly] Popup loaded - Starting initialization
[Armorly Debug] DOM Content Loaded event fired
```

If you see just `[Armorly] Popup loaded` (without "Starting initialization"), the old file is still cached.

---

## 🎯 Quick Test for Current Fix

### 1. Verify File is Synced
```bash
head -n 10 build/popup/popup.js
```

Should show:
```javascript
// Debug mode - set to true for verbose logging
const DEBUG_MODE = true;
```

### 2. Load Extension from Build Directory

**Make sure you're loading from:**
```
/Users/user/Documents/armorly-123/build
```

**NOT from:**
```
/Users/user/Documents/armorly-123
```

### 3. Reload Extension

1. Remove Armorly from `chrome://extensions`
2. Click **Load unpacked**
3. Select `/Users/user/Documents/armorly-123/build` folder
4. Open popup and inspect

### 4. Check Console Output

You should see:
```
[Armorly] Popup loaded - Starting initialization
[Armorly Debug] DOM Content Loaded event fired
[Armorly Debug] Available elements in DOM: {
  protection-toggle: true,
  status-indicator: true,
  status-text: true,
  threats-blocked: true,
  current-url: true,
  threat-list: true,
  view-docs: true,
  pages-scanned: false,
  avg-overhead: false,
  perf-status: false,
  ai-agent-status: false,
  scan-page: false,
  check-memory: false,
  view-performance: false,
  open-settings: false
}
[Armorly Debug] Step 1: Loading protection status...
[Armorly Debug] loadProtectionStatus: Starting...
[Armorly Debug] Element check: protection-toggle - EXISTS
[Armorly Debug] Element check: status-indicator - EXISTS
[Armorly Debug] Element check: status-text - EXISTS
...
[Armorly] Popup initialization complete ✓
```

**NO ERRORS should appear!**

---

## 🐛 Troubleshooting

### Problem: Still seeing old errors
**Solution:** 
1. Verify you're loading from `build/` directory
2. Run `./sync-to-build.sh` again
3. Remove and re-add extension
4. Hard refresh browser (Cmd+Shift+R on Mac)

### Problem: "Popup loaded" without "Starting initialization"
**Solution:** Old file is still loaded
1. Check `build/popup/popup.js` line 28
2. Should say: `console.log('[Armorly] Popup loaded - Starting initialization');`
3. If not, run `./sync-to-build.sh`

### Problem: Toggle button not working
**Solution:** Check console for errors
1. Open popup → Right-click → Inspect
2. Look for error messages
3. Verify `protection-toggle` element EXISTS in debug output

### Problem: Toggle moved to left side
**Solution:** CSS might not be synced
1. Run `./sync-to-build.sh` to sync CSS
2. Reload extension
3. Check `build/popup/popup.css` matches `popup/popup.css`

---

## ✅ Success Checklist

- [ ] Extension loaded from `/Users/user/Documents/armorly-123/build`
- [ ] Console shows "Popup loaded - Starting initialization"
- [ ] Console shows "Available elements in DOM" object
- [ ] Console shows debug logs for each step
- [ ] Console shows "Popup initialization complete ✓"
- [ ] NO error messages in console
- [ ] Toggle button works (changes Protected/Disabled text)
- [ ] Toggle button is centered (not on left)
- [ ] Statistics show "0" threats blocked
- [ ] Current page URL displays correctly

---

## 📝 Development Workflow

Going forward, always:

1. **Edit** source files in `popup/`, `background/`, etc.
2. **Sync** to build: `./sync-to-build.sh`
3. **Reload** extension in browser
4. **Test** functionality
5. **Check** console for errors

This ensures the browser always loads your latest changes!

---

## 🚀 Current Status

✅ **Fixed Issues:**
- Added comprehensive null checks to `popup.js`
- Added debug logging throughout
- Synced files to `build/` directory

🔄 **Next Steps:**
1. Load extension from `build/` directory
2. Reload extension
3. Open popup and inspect console
4. Verify no errors appear
5. Test toggle functionality

---

## 💡 Pro Tip

Add this alias to your shell profile for quick syncing:
```bash
alias armorly-sync='cd /Users/user/Documents/armorly-123 && ./sync-to-build.sh'
```

Then just run `armorly-sync` from anywhere!

