/**
 * Console Wrapper for Production Optimization
 * 
 * Wraps console methods to conditionally enable/disable logging based on environment.
 * In production (packed extension), only errors and warnings are logged.
 * In development (unpacked extension), all logs are shown.
 * 
 * This is a lightweight alternative to replacing all console.log statements.
 * 
 * @module console-wrapper
 * @author Armorly Security Team
 * @license MIT
 */

(function() {
  'use strict';

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

  // Initialize: detect if running in development
  async function initialize() {
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
        originalConsole.log('[Armorly Console] Development mode enabled - all logs visible');
      }
    } catch (error) {
      // Fallback to production mode
      isDevelopment = false;
      applyWrapper();
    }
  }

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

  // Expose API to toggle development mode
  window.ArmorlyConsole = {
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
  };

  // Initialize on load
  initialize();
})();

