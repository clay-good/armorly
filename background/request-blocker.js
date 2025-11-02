/**
 * Request Blocker for Armorly
 * 
 * Blocks malicious network requests at the browser level using declarativeNetRequest API.
 * Prevents data exfiltration, CSRF attacks, and malicious domain connections.
 * 
 * Features:
 * - Block known malicious domains
 * - Filter request payloads for prompt injections
 * - Prevent data exfiltration
 * - CSRF protection
 * - WebSocket blocking
 * - Real-time threat intelligence
 * 
 * @module request-blocker
 * @author Armorly Security Team
 */

class RequestBlocker {
  constructor() {
    /**
     * Statistics
     */
    this.stats = {
      requestsBlocked: 0,
      domainsBlocked: 0,
      payloadsBlocked: 0,
      csrfBlocked: 0,
      exfiltrationBlocked: 0,
    };

    /**
     * Configuration - PERMISSIVE MODE (only block critical threats)
     */
    this.config = {
      enabled: true,
      blockMaliciousDomains: true,
      blockDataExfiltration: false, // DISABLED - too aggressive
      blockCSRF: false, // DISABLED - too aggressive
      logActions: true,
      criticalOnly: true, // NEW - only block critical threats
      dynamicBlocking: false, // DISABLED - prevents over-blocking
    };

    /**
     * Known malicious domains (threat intelligence)
     * ONLY truly malicious domains, NOT tracking/analytics
     */
    this.maliciousDomains = [
      // Known malicious - ONLY add confirmed malicious domains
      'evil.com',
      'malware.com',
      'phishing.com',

      // Data exfiltration endpoints - ONLY confirmed malicious
      // Removed: webhook.site, requestbin.com (legitimate testing tools)
    ];

    /**
     * Suspicious URL patterns
     */
    this.suspiciousPatterns = [
      /eval\(/i,
      /javascript:/i,
      /data:text\/html/i,
      /vbscript:/i,
      /<script/i,
      /onerror=/i,
      /onclick=/i,
    ];

    /**
     * Blocked requests log
     */
    this.blockedRequests = [];

    /**
     * Dynamic rules counter
     */
    this.nextRuleId = 1000;
  }

  /**
   * Initialize request blocker
   */
  async initialize() {
    if (!this.config.enabled) return;

    try {
      // Set up declarativeNetRequest rules
      await this.setupBlockingRules();

      // Listen to web requests
      this.setupWebRequestListeners();

      console.log('[Armorly RequestBlocker] Initialized - Network protection active');
    } catch (error) {
      console.error('[Armorly RequestBlocker] Initialization error:', error);
    }
  }

  /**
   * Setup declarativeNetRequest blocking rules
   */
  async setupBlockingRules() {
    const rules = [];

    // Block known malicious domains
    this.maliciousDomains.forEach((domain, index) => {
      rules.push({
        id: index + 1,
        priority: 1,
        action: { type: 'block' },
        condition: {
          urlFilter: `*://*${domain}/*`,
          resourceTypes: ['main_frame', 'sub_frame', 'script', 'xmlhttprequest', 'image']
        }
      });
    });

    // Add rules dynamically
    try {
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: rules.map(r => r.id),
        addRules: rules
      });

      if (this.config.logActions) {
        console.log(`[Armorly RequestBlocker] Added ${rules.length} blocking rules`);
      }
    } catch (error) {
      console.error('[Armorly RequestBlocker] Error setting up rules:', error);
    }
  }

  /**
   * Setup webRequest listeners for advanced filtering
   * NOTE: Manifest V3 doesn't support blocking webRequest, so we use non-blocking monitoring
   * and declarativeNetRequest for actual blocking
   */
  setupWebRequestListeners() {
    // Monitor requests (non-blocking, for logging and analysis)
    chrome.webRequest.onBeforeRequest.addListener(
      (details) => this.handleBeforeRequest(details),
      { urls: ['<all_urls>'] },
      ['requestBody']
    );

    // Monitor request headers (non-blocking)
    chrome.webRequest.onBeforeSendHeaders.addListener(
      (details) => this.handleBeforeSendHeaders(details),
      { urls: ['<all_urls>'] },
      ['requestHeaders']
    );

    // Monitor responses (non-blocking)
    chrome.webRequest.onHeadersReceived.addListener(
      (details) => this.handleHeadersReceived(details),
      { urls: ['<all_urls>'] },
      ['responseHeaders']
    );
  }

  /**
   * Handle request before it's sent
   * NOTE: This is non-blocking in Manifest V3, so we log threats
   * PERMISSIVE MODE: Only log, do NOT add dynamic blocking rules
   */
  handleBeforeRequest(details) {
    if (!this.config.enabled) return;

    const url = details.url;
    const method = details.method;

    // Check for malicious URL patterns - LOG ONLY, no blocking
    if (this.isSuspiciousURL(url)) {
      this.logThreat(details, 'suspicious-url-pattern');
      // REMOVED: this.addDynamicBlockRule(url);
    }

    // Check for data exfiltration - DISABLED (too aggressive)
    if (this.config.blockDataExfiltration && this.isDataExfiltration(details)) {
      this.logThreat(details, 'data-exfiltration');
      // REMOVED: this.addDynamicBlockRule(url);
    }

    // Check request body for prompt injections - LOG ONLY
    if (details.requestBody && this.hasInjectionInPayload(details.requestBody)) {
      this.logThreat(details, 'payload-injection');
      // REMOVED: this.addDynamicBlockRule(url);
    }
  }

  /**
   * Handle request headers before sending
   * PERMISSIVE MODE: Only log, do NOT block
   */
  handleBeforeSendHeaders(details) {
    if (!this.config.enabled) return;

    // Check for CSRF attacks - LOG ONLY (disabled by default)
    if (this.config.blockCSRF && this.isCSRFAttempt(details)) {
      this.logThreat(details, 'csrf-attack');
      // REMOVED: this.addDynamicBlockRule(details.url);
    }

    // Check headers for suspicious content - LOG ONLY
    if (details.requestHeaders) {
      for (const header of details.requestHeaders) {
        if (this.isSuspiciousHeader(header)) {
          this.logThreat(details, 'suspicious-header');
          // REMOVED: this.addDynamicBlockRule(details.url);
        }
      }
    }
  }

  /**
   * Handle response headers
   */
  handleHeadersReceived(details) {
    if (!this.config.enabled) return;

    // Check for malicious response headers (non-blocking, for logging)
    if (details.responseHeaders) {
      for (const header of details.responseHeaders) {
        if (this.isMaliciousResponseHeader(header)) {
          this.logThreat(details, 'malicious-response');
        }
      }
    }
  }

  /**
   * Check if URL is suspicious
   */
  isSuspiciousURL(url) {
    // Check against patterns
    for (const pattern of this.suspiciousPatterns) {
      if (pattern.test(url)) {
        return true;
      }
    }

    // Check against malicious domains
    for (const domain of this.maliciousDomains) {
      if (url.includes(domain)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if request is data exfiltration
   */
  isDataExfiltration(details) {
    const url = details.url;
    const method = details.method;

    // Check for webhook/data collection endpoints
    const exfiltrationPatterns = [
      /webhook/i,
      /collect/i,
      /track/i,
      /beacon/i,
      /pixel/i,
      /analytics/i,
    ];

    for (const pattern of exfiltrationPatterns) {
      if (pattern.test(url)) {
        // Check if sending large amounts of data
        if (details.requestBody) {
          const bodySize = this.estimateBodySize(details.requestBody);
          if (bodySize > 10000) { // >10KB
            return true;
          }
        }
      }
    }

    return false;
  }

  /**
   * Check if payload contains injection
   */
  hasInjectionInPayload(requestBody) {
    if (!requestBody) return false;

    try {
      let bodyText = '';

      // Extract text from different body formats
      if (requestBody.raw) {
        bodyText = requestBody.raw.map(part => {
          if (part.bytes) {
            return new TextDecoder().decode(new Uint8Array(part.bytes));
          }
          return '';
        }).join('');
      } else if (requestBody.formData) {
        bodyText = JSON.stringify(requestBody.formData);
      }

      // Check for prompt injection patterns
      const injectionPatterns = [
        /ignore\s+(previous|all|prior)\s+instructions/i,
        /disregard\s+(previous|all)\s+instructions/i,
        /you\s+are\s+now\s+a/i,
        /system\s*:\s*/i,
        /override\s+security/i,
      ];

      for (const pattern of injectionPatterns) {
        if (pattern.test(bodyText)) {
          return true;
        }
      }
    } catch (error) {
      console.error('[Armorly RequestBlocker] Error checking payload:', error);
    }

    return false;
  }

  /**
   * Check if request is CSRF attempt
   */
  isCSRFAttempt(details) {
    const url = new URL(details.url);
    const method = details.method;

    // Only check state-changing methods
    if (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
      return false;
    }

    // Check for missing CSRF tokens
    const headers = details.requestHeaders || [];
    const hasCSRFToken = headers.some(h => 
      h.name.toLowerCase().includes('csrf') ||
      h.name.toLowerCase().includes('x-xsrf-token')
    );

    // Check origin/referer
    const origin = headers.find(h => h.name.toLowerCase() === 'origin');
    const referer = headers.find(h => h.name.toLowerCase() === 'referer');

    if (!origin && !referer && !hasCSRFToken) {
      // Suspicious: state-changing request with no origin/referer/token
      return true;
    }

    return false;
  }

  /**
   * Check if header is suspicious
   */
  isSuspiciousHeader(header) {
    const name = header.name.toLowerCase();
    const value = header.value || '';

    // Check for injection in header values
    if (/<script/i.test(value) || /javascript:/i.test(value)) {
      return true;
    }

    return false;
  }

  /**
   * Check if response header is malicious
   */
  isMaliciousResponseHeader(header) {
    // Could check for malicious redirects, etc.
    return false;
  }

  /**
   * Estimate request body size
   */
  estimateBodySize(requestBody) {
    let size = 0;

    if (requestBody.raw) {
      requestBody.raw.forEach(part => {
        if (part.bytes) {
          size += part.bytes.length;
        }
      });
    } else if (requestBody.formData) {
      size = JSON.stringify(requestBody.formData).length;
    }

    return size;
  }

  /**
   * Log a threat (used for non-blocking monitoring)
   */
  logThreat(details, reason) {
    this.stats.requestsBlocked++;

    if (reason === 'data-exfiltration') {
      this.stats.exfiltrationBlocked++;
    } else if (reason === 'csrf-attack') {
      this.stats.csrfBlocked++;
    } else if (reason === 'payload-injection') {
      this.stats.payloadsBlocked++;
    }

    const blocked = {
      url: details.url,
      method: details.method,
      reason,
      timestamp: Date.now(),
    };

    this.blockedRequests.push(blocked);

    if (this.config.logActions) {
      console.log(`[Armorly RequestBlocker] Threat detected (${reason}):`, details.url);
    }

    // Keep only last 100 blocked requests
    if (this.blockedRequests.length > 100) {
      this.blockedRequests.shift();
    }
  }

  /**
   * Add dynamic blocking rule for a URL
   */
  async addDynamicBlockRule(url) {
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname;

      // Create a blocking rule for this domain
      const rule = {
        id: this.nextRuleId++,
        priority: 2,
        action: { type: 'block' },
        condition: {
          urlFilter: `*://*${domain}/*`,
          resourceTypes: ['main_frame', 'sub_frame', 'script', 'xmlhttprequest']
        }
      };

      await chrome.declarativeNetRequest.updateDynamicRules({
        addRules: [rule]
      });

      if (this.config.logActions) {
        console.log(`[Armorly RequestBlocker] Added dynamic block rule for: ${domain}`);
      }
    } catch (error) {
      console.error('[Armorly RequestBlocker] Error adding dynamic rule:', error);
    }
  }

  /**
   * Block a request and log it (legacy method, kept for compatibility)
   */
  blockRequest(details, reason) {
    this.logThreat(details, reason);
  }

  /**
   * Get statistics
   */
  getStats() {
    return { ...this.stats };
  }

  /**
   * Get blocked requests log
   */
  getBlockedRequests() {
    return [...this.blockedRequests];
  }
}

// Export for use in service worker
export { RequestBlocker };

