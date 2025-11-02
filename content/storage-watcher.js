/**
 * Storage Watcher Content Script for Armorly
 * 
 * Monitors localStorage and sessionStorage changes on each page
 * Reports suspicious changes to the background service worker
 */

(function() {
  'use strict';

  // Track original storage methods
  const originalLocalStorageSetItem = Storage.prototype.setItem;
  const originalLocalStorageRemoveItem = Storage.prototype.removeItem;
  const originalLocalStorageClear = Storage.prototype.clear;

  /**
   * Wrap localStorage.setItem to monitor changes
   */
  Storage.prototype.setItem = function(key, value) {
    const oldValue = this.getItem(key);
    const storageType = this === window.localStorage ? 'localStorage' : 'sessionStorage';
    
    // Call original method
    originalLocalStorageSetItem.call(this, key, value);
    
    // Report change to background
    reportStorageChange(storageType, key, oldValue, value);
  };

  /**
   * Wrap localStorage.removeItem to monitor deletions
   */
  Storage.prototype.removeItem = function(key) {
    const oldValue = this.getItem(key);
    const storageType = this === window.localStorage ? 'localStorage' : 'sessionStorage';
    
    // Call original method
    originalLocalStorageRemoveItem.call(this, key);
    
    // Report change to background
    reportStorageChange(storageType, key, oldValue, null);
  };

  /**
   * Wrap localStorage.clear to monitor mass deletions
   */
  Storage.prototype.clear = function() {
    const storageType = this === window.localStorage ? 'localStorage' : 'sessionStorage';
    const keys = Object.keys(this);
    
    // Call original method
    originalLocalStorageClear.call(this);
    
    // Report mass deletion
    chrome.runtime.sendMessage({
      type: 'STORAGE_CLEARED',
      storageType,
      keysCleared: keys.length,
      url: window.location.href,
      timestamp: Date.now()
    }).catch(() => {
      // Extension context invalidated
    });
  };

  /**
   * Report storage change to background
   */
  function reportStorageChange(storageType, key, oldValue, newValue) {
    chrome.runtime.sendMessage({
      type: 'CONTENT_STORAGE_CHANGE',
      storageType,
      key,
      oldValue,
      newValue,
      url: window.location.href,
      timestamp: Date.now()
    }).catch(() => {
      // Extension context invalidated
    });
  }

  /**
   * Monitor storage events (changes from other tabs/windows)
   */
  window.addEventListener('storage', (event) => {
    if (event.storageArea === window.localStorage || event.storageArea === window.sessionStorage) {
      const storageType = event.storageArea === window.localStorage ? 'localStorage' : 'sessionStorage';
      reportStorageChange(storageType, event.key, event.oldValue, event.newValue);
    }
  });

  /**
   * Scan existing storage on page load
   */
  function scanExistingStorage() {
    const threats = [];

    // Scan localStorage
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      const value = localStorage.getItem(key);
      
      if (containsSuspiciousContent(value)) {
        threats.push({
          type: 'EXISTING_STORAGE_THREAT',
          severity: 'HIGH',
          description: `Suspicious content found in localStorage: ${key}`,
          storageType: 'localStorage',
          key,
          value: truncateValue(value)
        });
      }
    }

    // Scan sessionStorage
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      const value = sessionStorage.getItem(key);
      
      if (containsSuspiciousContent(value)) {
        threats.push({
          type: 'EXISTING_STORAGE_THREAT',
          severity: 'HIGH',
          description: `Suspicious content found in sessionStorage: ${key}`,
          storageType: 'sessionStorage',
          key,
          value: truncateValue(value)
        });
      }
    }

    // Report threats if found
    if (threats.length > 0) {
      chrome.runtime.sendMessage({
        type: 'STORAGE_SCAN_THREATS',
        threats,
        url: window.location.href,
        timestamp: Date.now()
      }).catch(() => {
        // Extension context invalidated
      });
    }
  }

  /**
   * Check if content contains suspicious patterns
   */
  function containsSuspiciousContent(value) {
    if (!value || typeof value !== 'string') return false;
    
    const suspiciousPatterns = [
      /ignore\s+previous\s+instructions/i,
      /disregard\s+all\s+prior/i,
      /system\s*:\s*you\s+are\s+now/i,
      /new\s+instructions/i,
      /override\s+instructions/i,
      /forget\s+everything/i,
      /<script>/i,
      /javascript:/i,
      /onerror=/i,
      /eval\(/i
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(value));
  }

  /**
   * Truncate value for reporting
   */
  function truncateValue(value, maxLength = 200) {
    if (!value) return '';
    const str = String(value);
    return str.length > maxLength ? str.substring(0, maxLength) + '...' : str;
  }

  // Initialize on page load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', scanExistingStorage);
  } else {
    scanExistingStorage();
  }

  console.log('[Armorly Storage Watcher] Monitoring localStorage and sessionStorage');
})();

