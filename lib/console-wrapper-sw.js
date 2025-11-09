/**
 * Console Wrapper for Service Worker (Background Context)
 *
 * Wraps console methods to conditionally enable/disable logging based on environment.
 * In production (packed extension), only errors and warnings are logged.
 * In development (unpacked extension), all logs are shown.
 *
 * This version is for ES6 modules (service worker).
 *
 * @module console-wrapper-sw
 * @author Armorly Security Team
 * @license MIT
 */

// Store original console methods
const originalConsole = {
  log: console.log.bind(console),
  info: console.info.bind(console),
  debug: console.debug.bind(console),
  warn: console.warn.bind(console),
  error: console.error.bind(console),
};

// Development mode flag
let isDevelopment = false;

// Apply console wrapper
function applyWrapper() {
  if (isDevelopment) {
    // Development: restore original console
    console.log = originalConsole.log;
    console.info = originalConsole.info;
    console.debug = originalConsole.debug;
    console.warn = originalConsole.warn;
    console.error = originalConsole.error;
  } else {
    // Production: suppress log/info/debug, keep warn/error
    console.log = function() {};
    console.info = function() {};
    console.debug = function() {};
    console.warn = originalConsole.warn;
    console.error = originalConsole.error;
  }
}

// Initialize: detect if running in development
async function initializeConsoleWrapper() {
  try {
    const result = await chrome.storage.local.get('armorly_dev_mode');

    if (result.armorly_dev_mode !== undefined) {
      isDevelopment = result.armorly_dev_mode;
    } else {
      // Auto-detect: if extension is unpacked, enable dev mode
      if (chrome.runtime && chrome.runtime.getManifest) {
        const manifest = chrome.runtime.getManifest();
        // Check if running in development (unpacked extension has no update_url)
        isDevelopment = !('update_url' in manifest);

        // Save to storage
        await chrome.storage.local.set({ armorly_dev_mode: isDevelopment });
      }
    }

    // Apply console wrapper
    applyWrapper();

    if (isDevelopment) {
      originalConsole.log('[Armorly Service Worker] Development mode enabled - all logs visible');
    } else {
      originalConsole.warn('[Armorly Service Worker] Production mode - console.log suppressed');
    }
  } catch (error) {
    // Fallback to production mode
    isDevelopment = false;
    applyWrapper();
  }
}

// API to toggle development mode
export const ArmorlyConsole = {
  setDevelopmentMode: async function(enabled) {
    isDevelopment = enabled;
    await chrome.storage.local.set({ armorly_dev_mode: enabled });
    applyWrapper();
    originalConsole.log(`[Armorly Console] Development mode ${enabled ? 'enabled' : 'disabled'}`);
  },

  isDevelopment: function() {
    return isDevelopment;
  },

  getOriginal: function() {
    return originalConsole;
  },

  initialize: initializeConsoleWrapper,
};

// Auto-initialize
initializeConsoleWrapper();

export default ArmorlyConsole;
