/**
 * BrowserOS API Interceptor
 * 
 * Intercepts and validates all browserOS.* API calls made by the AI agent.
 * This is CRITICAL for preventing:
 * - Malicious JavaScript execution
 * - Unauthorized input injection
 * - Sensitive data extraction
 * - Preference manipulation
 * 
 * BrowserOS exposes powerful automation APIs that can be exploited via prompt injection.
 * This module acts as a security layer between the AI agent and the browser.
 */

export class BrowserOSAPIInterceptor {
  constructor() {
    this.enabled = true;
    this.auditLog = [];
    this.maxAuditLogSize = 1000;
    this.onThreatDetected = null;
    
    // Rate limiting
    this.apiCallCounts = new Map(); // API method -> count
    this.rateLimitWindow = 60000; // 1 minute
    this.rateLimits = {
      executeJavaScript: 10,
      captureScreenshot: 5,
      getAccessibilityTree: 30,
      inputText: 50,
      click: 100,
      setPref: 5
    };
    
    // Dangerous JavaScript patterns
    this.dangerousJSPatterns = [
      /document\.cookie/i,
      /localStorage\./i,
      /sessionStorage\./i,
      /fetch\s*\(/i,
      /XMLHttpRequest/i,
      /\.send\s*\(/i,
      /eval\s*\(/i,
      /Function\s*\(/i,
      /window\.location\s*=/i,
      /document\.location\s*=/i,
      /\.innerHTML\s*=/i,
      /\.outerHTML\s*=/i,
      /atob\s*\(/i,
      /btoa\s*\(/i,
      /crypto\./i,
      /navigator\.credentials/i,
      /password/i,
      /token/i,
      /api[_-]?key/i,
      /secret/i,
      /\.postMessage\s*\(/i
    ];
    
    // Suspicious input patterns (prompt injection)
    this.suspiciousInputPatterns = [
      /ignore\s+(previous|all)\s+instructions/i,
      /system\s*:/i,
      /you\s+are\s+now/i,
      /new\s+instructions/i,
      /disregard/i,
      /override/i,
      /<script/i,
      /javascript:/i,
      /on\w+\s*=/i, // event handlers
      /eval\s*\(/i,
      /\.\.\/\.\.\//i, // path traversal
      /\$\{.*\}/i, // template injection
      /{{.*}}/i // template injection
    ];
    
    console.log('[Armorly BrowserOS] API Interceptor initialized');
  }
  
  /**
   * Initialize interception of BrowserOS APIs
   * Note: This may not work if browserOS is not accessible from extension context
   * We'll need to inject this into the agent extension's context
   */
  initialize() {
    if (typeof chrome === 'undefined' || !chrome.browserOS) {
      console.warn('[Armorly BrowserOS] browserOS API not available - running in standard Chrome');
      return false;
    }
    
    try {
      this.interceptExecuteJavaScript();
      this.interceptInputText();
      this.interceptClick();
      this.interceptCaptureScreenshot();
      this.interceptGetAccessibilityTree();
      this.interceptSetPref();
      this.interceptTypeAtCoordinates();
      
      console.log('[Armorly BrowserOS] All API interceptors installed');
      return true;
    } catch (error) {
      console.error('[Armorly BrowserOS] Failed to install interceptors:', error);
      return false;
    }
  }
  
  /**
   * Set callback for threat detection
   */
  setThreatCallback(callback) {
    this.onThreatDetected = callback;
  }
  
  /**
   * Log API call to audit trail
   */
  logAPICall(method, params, blocked = false, reason = null) {
    const entry = {
      timestamp: Date.now(),
      method,
      params: this.sanitizeParams(params),
      blocked,
      reason
    };
    
    this.auditLog.push(entry);
    
    // Trim log if too large
    if (this.auditLog.length > this.maxAuditLogSize) {
      this.auditLog.shift();
    }
    
    // Report threat if blocked
    if (blocked && this.onThreatDetected) {
      this.onThreatDetected({
        type: 'BROWSEROS_API_ABUSE',
        method,
        reason,
        severity: this.getSeverity(method),
        timestamp: Date.now()
      });
    }
  }
  
  /**
   * Sanitize parameters for logging (remove sensitive data)
   */
  sanitizeParams(params) {
    if (typeof params === 'string' && params.length > 200) {
      return params.substring(0, 200) + '... (truncated)';
    }
    return params;
  }
  
  /**
   * Get severity level for API method
   */
  getSeverity(method) {
    const criticalMethods = ['executeJavaScript', 'setPref'];
    const highMethods = ['inputText', 'typeAtCoordinates', 'captureScreenshot'];
    
    if (criticalMethods.includes(method)) return 'critical';
    if (highMethods.includes(method)) return 'high';
    return 'medium';
  }
  
  /**
   * Check rate limit for API method
   */
  checkRateLimit(method) {
    const now = Date.now();
    const key = `${method}_${Math.floor(now / this.rateLimitWindow)}`;
    
    const count = this.apiCallCounts.get(key) || 0;
    const limit = this.rateLimits[method] || 100;
    
    if (count >= limit) {
      return false;
    }
    
    this.apiCallCounts.set(key, count + 1);
    
    // Clean up old entries
    for (const [k, v] of this.apiCallCounts.entries()) {
      const timestamp = parseInt(k.split('_')[1]);
      if (now - timestamp * this.rateLimitWindow > this.rateLimitWindow * 2) {
        this.apiCallCounts.delete(k);
      }
    }
    
    return true;
  }
  
  /**
   * Validate JavaScript code for malicious patterns
   */
  validateJavaScript(code) {
    for (const pattern of this.dangerousJSPatterns) {
      if (pattern.test(code)) {
        return {
          valid: false,
          reason: `Dangerous pattern detected: ${pattern.source}`
        };
      }
    }
    
    // Check for obfuscation attempts
    if (code.includes('\\x') || code.includes('\\u')) {
      return {
        valid: false,
        reason: 'Obfuscated code detected (hex/unicode escapes)'
      };
    }
    
    // Check for excessive length (possible obfuscation)
    if (code.length > 10000) {
      return {
        valid: false,
        reason: 'Code too long (possible obfuscation)'
      };
    }
    
    return { valid: true };
  }
  
  /**
   * Validate input text for prompt injection
   */
  validateInputText(text) {
    for (const pattern of this.suspiciousInputPatterns) {
      if (pattern.test(text)) {
        return {
          valid: false,
          reason: `Suspicious pattern detected: ${pattern.source}`
        };
      }
    }
    
    return { valid: true };
  }
  
  /**
   * Intercept browserOS.executeJavaScript
   */
  interceptExecuteJavaScript() {
    const original = chrome.browserOS.executeJavaScript;
    const self = this;
    
    chrome.browserOS.executeJavaScript = function(code, callback) {
      if (!self.enabled) {
        return original.call(this, code, callback);
      }
      
      // Rate limit check
      if (!self.checkRateLimit('executeJavaScript')) {
        self.logAPICall('executeJavaScript', code, true, 'Rate limit exceeded');
        if (callback) callback({ error: 'Rate limit exceeded' });
        return;
      }
      
      // Validate JavaScript
      const validation = self.validateJavaScript(code);
      if (!validation.valid) {
        self.logAPICall('executeJavaScript', code, true, validation.reason);
        console.error('[Armorly BrowserOS] Blocked executeJavaScript:', validation.reason);
        if (callback) callback({ error: validation.reason });
        return;
      }
      
      self.logAPICall('executeJavaScript', code, false);
      return original.call(this, code, callback);
    };
  }
  
  /**
   * Intercept browserOS.inputText
   */
  interceptInputText() {
    const original = chrome.browserOS.inputText;
    const self = this;
    
    chrome.browserOS.inputText = function(nodeId, text, callback) {
      if (!self.enabled) {
        return original.call(this, nodeId, text, callback);
      }
      
      // Rate limit check
      if (!self.checkRateLimit('inputText')) {
        self.logAPICall('inputText', { nodeId, text }, true, 'Rate limit exceeded');
        if (callback) callback({ error: 'Rate limit exceeded' });
        return;
      }
      
      // Validate input text
      const validation = self.validateInputText(text);
      if (!validation.valid) {
        self.logAPICall('inputText', { nodeId, text }, true, validation.reason);
        console.error('[Armorly BrowserOS] Blocked inputText:', validation.reason);
        if (callback) callback({ error: validation.reason });
        return;
      }
      
      self.logAPICall('inputText', { nodeId, text }, false);
      return original.call(this, nodeId, text, callback);
    };
  }
  
  /**
   * Intercept browserOS.click
   */
  interceptClick() {
    const original = chrome.browserOS.click;
    const self = this;
    
    chrome.browserOS.click = function(nodeId, callback) {
      if (!self.enabled) {
        return original.call(this, nodeId, callback);
      }
      
      // Rate limit check
      if (!self.checkRateLimit('click')) {
        self.logAPICall('click', { nodeId }, true, 'Rate limit exceeded');
        if (callback) callback({ error: 'Rate limit exceeded' });
        return;
      }
      
      self.logAPICall('click', { nodeId }, false);
      return original.call(this, nodeId, callback);
    };
  }
  
  /**
   * Intercept browserOS.captureScreenshot
   */
  interceptCaptureScreenshot() {
    const original = chrome.browserOS.captureScreenshot;
    const self = this;

    chrome.browserOS.captureScreenshot = function(callback) {
      if (!self.enabled) {
        return original.call(this, callback);
      }

      // Rate limit check (screenshots are sensitive)
      if (!self.checkRateLimit('captureScreenshot')) {
        self.logAPICall('captureScreenshot', {}, true, 'Rate limit exceeded - possible data exfiltration');
        if (callback) callback({ error: 'Rate limit exceeded' });
        return;
      }

      self.logAPICall('captureScreenshot', {}, false);
      console.warn('[Armorly BrowserOS] Screenshot captured by AI agent');
      return original.call(this, callback);
    };
  }

  /**
   * Intercept browserOS.getAccessibilityTree
   */
  interceptGetAccessibilityTree() {
    const original = chrome.browserOS.getAccessibilityTree;
    const self = this;

    chrome.browserOS.getAccessibilityTree = function(callback) {
      if (!self.enabled) {
        return original.call(this, callback);
      }

      // Rate limit check
      if (!self.checkRateLimit('getAccessibilityTree')) {
        self.logAPICall('getAccessibilityTree', {}, true, 'Rate limit exceeded');
        if (callback) callback({ error: 'Rate limit exceeded' });
        return;
      }

      self.logAPICall('getAccessibilityTree', {}, false);

      // Wrap callback to sanitize response
      const wrappedCallback = function(tree) {
        if (tree && tree.nodes) {
          // TODO: Sanitize tree to remove hidden prompt injections
          // This requires analyzing node visibility and filtering suspicious content
        }
        if (callback) callback(tree);
      };

      return original.call(this, wrappedCallback);
    };
  }

  /**
   * Intercept browserOS.setPref
   */
  interceptSetPref() {
    const original = chrome.browserOS.setPref;
    const self = this;

    chrome.browserOS.setPref = function(name, value, callback) {
      if (!self.enabled) {
        return original.call(this, name, value, callback);
      }

      // Rate limit check
      if (!self.checkRateLimit('setPref')) {
        self.logAPICall('setPref', { name, value }, true, 'Rate limit exceeded');
        if (callback) callback({ error: 'Rate limit exceeded' });
        return;
      }

      // Validate preference name (only allow browseros.* preferences)
      if (!name.startsWith('browseros.')) {
        self.logAPICall('setPref', { name, value }, true, 'Unauthorized preference modification');
        console.error('[Armorly BrowserOS] Blocked setPref for non-browseros preference:', name);
        if (callback) callback({ error: 'Unauthorized preference' });
        return;
      }

      self.logAPICall('setPref', { name, value }, false);
      return original.call(this, name, value, callback);
    };
  }

  /**
   * Intercept browserOS.typeAtCoordinates
   */
  interceptTypeAtCoordinates() {
    const original = chrome.browserOS.typeAtCoordinates;
    const self = this;

    chrome.browserOS.typeAtCoordinates = function(x, y, text, callback) {
      if (!self.enabled) {
        return original.call(this, x, y, text, callback);
      }

      // Rate limit check
      if (!self.checkRateLimit('inputText')) { // Use same limit as inputText
        self.logAPICall('typeAtCoordinates', { x, y, text }, true, 'Rate limit exceeded');
        if (callback) callback({ error: 'Rate limit exceeded' });
        return;
      }

      // Validate input text
      const validation = self.validateInputText(text);
      if (!validation.valid) {
        self.logAPICall('typeAtCoordinates', { x, y, text }, true, validation.reason);
        console.error('[Armorly BrowserOS] Blocked typeAtCoordinates:', validation.reason);
        if (callback) callback({ error: validation.reason });
        return;
      }

      self.logAPICall('typeAtCoordinates', { x, y, text }, false);
      return original.call(this, x, y, text, callback);
    };
  }

  /**
   * Get audit log
   */
  getAuditLog() {
    return [...this.auditLog];
  }

  /**
   * Clear audit log
   */
  clearAuditLog() {
    this.auditLog = [];
  }

  /**
   * Enable/disable interceptor
   */
  setEnabled(enabled) {
    this.enabled = enabled;
    console.log(`[Armorly BrowserOS] Interceptor ${enabled ? 'enabled' : 'disabled'}`);
  }

  /**
   * Get statistics
   */
  getStatistics() {
    const stats = {
      totalCalls: this.auditLog.length,
      blockedCalls: this.auditLog.filter(e => e.blocked).length,
      byMethod: {},
      recentThreats: []
    };

    // Count by method
    for (const entry of this.auditLog) {
      if (!stats.byMethod[entry.method]) {
        stats.byMethod[entry.method] = { total: 0, blocked: 0 };
      }
      stats.byMethod[entry.method].total++;
      if (entry.blocked) {
        stats.byMethod[entry.method].blocked++;
      }
    }

    // Get recent threats (last 10 blocked calls)
    stats.recentThreats = this.auditLog
      .filter(e => e.blocked)
      .slice(-10)
      .reverse();

    return stats;
  }
}


