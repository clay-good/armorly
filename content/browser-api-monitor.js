/**
 * Browser API Monitor for Armorly
 * 
 * Monitors sensitive browser API access that could be exploited by malicious scripts:
 * - Credentials API (navigator.credentials)
 * - Local/Session Storage access
 * - Cookie access (document.cookie)
 * - Clipboard API (navigator.clipboard)
 * - Geolocation API (navigator.geolocation)
 * - Camera/Microphone access (getUserMedia)
 * 
 * @module browser-api-monitor
 * @author Armorly Security Team
 * @license MIT
 */

class BrowserAPIMonitor {
  constructor() {
    /**
     * Detected API access attempts
     */
    this.accessLog = [];

    /**
     * Suspicious patterns in API usage
     */
    this.suspiciousPatterns = {
      credentials: {
        threshold: 3, // Max calls per minute
        severity: 'HIGH',
        score: 60
      },
      storage: {
        threshold: 10, // Max writes per minute
        severity: 'MEDIUM',
        score: 40
      },
      cookie: {
        threshold: 5, // Max accesses per minute
        severity: 'HIGH',
        score: 55
      },
      clipboard: {
        threshold: 3, // Max reads per minute
        severity: 'MEDIUM',
        score: 45
      },
      geolocation: {
        threshold: 2, // Max requests per minute
        severity: 'MEDIUM',
        score: 50
      },
      media: {
        threshold: 1, // Max requests per minute
        severity: 'HIGH',
        score: 70
      }
    };

    /**
     * Rate limiting counters
     */
    this.rateLimits = new Map();

    /**
     * Monitoring enabled
     */
    this.enabled = true;

    /**
     * Interval ID for cleanup
     */
    this.rateLimitResetInterval = null;
  }

  /**
   * Start monitoring browser APIs
   */
  startMonitoring() {
    if (!this.enabled) return;

    this.monitorCredentialsAPI();
    this.monitorStorageAPI();
    this.monitorCookieAccess();
    this.monitorClipboardAPI();
    this.monitorGeolocationAPI();
    this.monitorMediaDevices();

    // Reset rate limits every minute
    this.rateLimitResetInterval = setInterval(() => {
      this.rateLimits.clear();
    }, 60000);
  }

  /**
   * Stop monitoring
   */
  stopMonitoring() {
    this.enabled = false;

    // Clear interval
    if (this.rateLimitResetInterval) {
      clearInterval(this.rateLimitResetInterval);
      this.rateLimitResetInterval = null;
    }
  }

  /**
   * Monitor Credentials API access
   */
  monitorCredentialsAPI() {
    if (!navigator.credentials) return;

    const originalGet = navigator.credentials.get;
    const originalStore = navigator.credentials.store;
    const originalCreate = navigator.credentials.create;

    const self = this;

    navigator.credentials.get = function(...args) {
      self.logAPIAccess('credentials', 'get', args);
      return originalGet.apply(this, args);
    };

    navigator.credentials.store = function(...args) {
      self.logAPIAccess('credentials', 'store', args);
      return originalStore.apply(this, args);
    };

    navigator.credentials.create = function(...args) {
      self.logAPIAccess('credentials', 'create', args);
      return originalCreate.apply(this, args);
    };
  }

  /**
   * Monitor Storage API access (localStorage, sessionStorage)
   */
  monitorStorageAPI() {
    const self = this;

    // Monitor localStorage
    const originalSetItem = Storage.prototype.setItem;
    const originalGetItem = Storage.prototype.getItem;
    const originalRemoveItem = Storage.prototype.removeItem;
    const originalClear = Storage.prototype.clear;

    Storage.prototype.setItem = function(key, value) {
      self.logAPIAccess('storage', 'setItem', { key, value, type: this === localStorage ? 'local' : 'session' });
      return originalSetItem.call(this, key, value);
    };

    Storage.prototype.getItem = function(key) {
      self.logAPIAccess('storage', 'getItem', { key, type: this === localStorage ? 'local' : 'session' });
      return originalGetItem.call(this, key);
    };

    Storage.prototype.removeItem = function(key) {
      self.logAPIAccess('storage', 'removeItem', { key, type: this === localStorage ? 'local' : 'session' });
      return originalRemoveItem.call(this, key);
    };

    Storage.prototype.clear = function() {
      self.logAPIAccess('storage', 'clear', { type: this === localStorage ? 'local' : 'session' });
      return originalClear.call(this);
    };
  }

  /**
   * Monitor Cookie access
   */
  monitorCookieAccess() {
    const self = this;
    let cookieValue = document.cookie;

    Object.defineProperty(document, 'cookie', {
      get() {
        self.logAPIAccess('cookie', 'read', {});
        return cookieValue;
      },
      set(value) {
        self.logAPIAccess('cookie', 'write', { value });
        cookieValue = value;
      }
    });
  }

  /**
   * Monitor Clipboard API access
   */
  monitorClipboardAPI() {
    if (!navigator.clipboard) return;

    const originalRead = navigator.clipboard.read;
    const originalReadText = navigator.clipboard.readText;
    const originalWrite = navigator.clipboard.write;
    const originalWriteText = navigator.clipboard.writeText;

    const self = this;

    if (originalRead) {
      navigator.clipboard.read = function(...args) {
        self.logAPIAccess('clipboard', 'read', args);
        return originalRead.apply(this, args);
      };
    }

    if (originalReadText) {
      navigator.clipboard.readText = function(...args) {
        self.logAPIAccess('clipboard', 'readText', args);
        return originalReadText.apply(this, args);
      };
    }

    if (originalWrite) {
      navigator.clipboard.write = function(...args) {
        self.logAPIAccess('clipboard', 'write', args);
        return originalWrite.apply(this, args);
      };
    }

    if (originalWriteText) {
      navigator.clipboard.writeText = function(...args) {
        self.logAPIAccess('clipboard', 'writeText', args);
        return originalWriteText.apply(this, args);
      };
    }
  }

  /**
   * Monitor Geolocation API access
   */
  monitorGeolocationAPI() {
    if (!navigator.geolocation) return;

    const originalGetCurrentPosition = navigator.geolocation.getCurrentPosition;
    const originalWatchPosition = navigator.geolocation.watchPosition;

    const self = this;

    navigator.geolocation.getCurrentPosition = function(...args) {
      self.logAPIAccess('geolocation', 'getCurrentPosition', args);
      return originalGetCurrentPosition.apply(this, args);
    };

    navigator.geolocation.watchPosition = function(...args) {
      self.logAPIAccess('geolocation', 'watchPosition', args);
      return originalWatchPosition.apply(this, args);
    };
  }

  /**
   * Monitor Media Devices API (camera/microphone)
   */
  monitorMediaDevices() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) return;

    const originalGetUserMedia = navigator.mediaDevices.getUserMedia;
    const self = this;

    navigator.mediaDevices.getUserMedia = function(...args) {
      self.logAPIAccess('media', 'getUserMedia', args);
      return originalGetUserMedia.apply(this, args);
    };
  }

  /**
   * Log API access and check for suspicious patterns
   * 
   * @param {string} api - API name
   * @param {string} method - Method called
   * @param {*} args - Arguments passed
   */
  logAPIAccess(api, method, args) {
    const timestamp = Date.now();
    
    // Log the access
    this.accessLog.push({
      api,
      method,
      args,
      timestamp,
      url: window.location.href
    });

    // Keep only last 100 entries
    if (this.accessLog.length > 100) {
      this.accessLog.shift();
    }

    // Check rate limits
    const key = `${api}:${method}`;
    const count = (this.rateLimits.get(key) || 0) + 1;
    this.rateLimits.set(key, count);

    // Check if threshold exceeded
    const pattern = this.suspiciousPatterns[api];
    if (pattern && count > pattern.threshold) {
      this.reportSuspiciousActivity(api, method, count, pattern);
    }
  }

  /**
   * Report suspicious API activity
   * 
   * @param {string} api - API name
   * @param {string} method - Method called
   * @param {number} count - Number of calls
   * @param {Object} pattern - Pattern configuration
   */
  reportSuspiciousActivity(api, method, count, pattern) {
    const threat = {
      type: 'SUSPICIOUS_API_ACCESS',
      api,
      method,
      count,
      severity: pattern.severity,
      score: pattern.score,
      description: `Excessive ${api} API access detected: ${count} calls in 1 minute (threshold: ${pattern.threshold})`,
      timestamp: Date.now(),
      url: window.location.href
    };

    // Send to background script
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({
        type: 'THREATS_DETECTED',
        threats: [threat],
        url: window.location.href,
        timestamp: Date.now()
      }).catch(err => {
        console.error('[Armorly] Error reporting API threat:', err);
      });
    }
  }

  /**
   * Get access log
   * 
   * @returns {Array} Access log entries
   */
  getAccessLog() {
    return this.accessLog;
  }

  /**
   * Clear access log
   */
  clearLog() {
    this.accessLog = [];
    this.rateLimits.clear();
  }

  /**
   * Stop monitoring
   */
  stopMonitoring() {
    this.enabled = false;
  }
}

// Export for use in content script
if (typeof window !== 'undefined') {
  window.BrowserAPIMonitor = BrowserAPIMonitor;
}

