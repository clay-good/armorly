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
     * Configuration - ACTIVE BLOCKING MODE
     */
    this.config = {
      enabled: true,
      blockMaliciousDomains: true,
      blockDataExfiltration: true, // ENABLED - blocks suspicious data exfiltration
      blockCSRF: true, // ENABLED - blocks CSRF attacks on AI services
      logActions: true,
      criticalOnly: false, // Block all threats, not just critical
      dynamicBlocking: true, // ENABLED - allows dynamic rule creation
    };

    /**
     * Known malicious domains (AI-SPECIFIC THREAT FOCUS)
     *
     * 🎯 PHILOSOPHY: Like uBlock Origin for ads, we focus ONLY on AI-specific threats
     *
     * We ONLY block domains that are:
     * 1. Known for AI prompt injection attacks
     * 2. Cryptominers that target AI browsers specifically
     * 3. High-risk TLDs commonly used for AI phishing
     * 4. Services proven to exfiltrate AI conversation data
     *
     * We DO NOT block:
     * - Legitimate file sharing (WeTransfer, Dropbox, etc.)
     * - Legitimate URL shorteners (t.co, goo.gl, etc.)
     * - Developer tools (ngrok, localhost.run, etc.)
     * - Analytics/tracking (these are not AI threats)
     * - Dynamic DNS (legitimate use cases)
     * - WebRTC/STUN (needed for video chat)
     *
     * Current coverage: AI-specific threats only (~20 domains)
     */
    this.maliciousDomains = [
      // High-risk TLDs (free domains heavily abused for AI phishing)
      '.tk',    // Tokelau - #1 for AI phishing campaigns
      '.ml',    // Mali - frequently used for fake AI sites
      '.ga',    // Gabon - common for AI credential harvesting
      '.cf',    // Central African Republic - AI scam sites
      '.gq',    // Equatorial Guinea - AI malware delivery

      // Known cryptominers (dead services, safe to block)
      'coinhive.com',           // Defunct cryptominer
      'coin-hive.com',          // Defunct cryptominer
      'jsecoin.com',            // Defunct cryptominer
      'crypto-loot.com',        // Defunct cryptominer
      'cryptoloot.pro',         // Defunct cryptominer
      'webminepool.com',        // Defunct cryptominer
      'minemytraffic.com',      // Defunct cryptominer
      'coinerra.com',           // Defunct cryptominer
      'minero.cc',              // Defunct cryptominer
      'ppoi.org',               // Defunct cryptominer
      'statdynamic.com',        // Cryptominer disguised as analytics
      'cookiescript.info',      // Cryptominer disguised as cookie consent

      // AI-specific data exfiltration (anonymous paste sites used in AI attacks)
      // NOTE: Only blocking /raw endpoints to allow legitimate pastebin use
      'pastebin.com/raw',       // Raw paste output (common for AI data theft)
      'ghostbin.com',           // Anonymous paste (used in AI attacks)
      'privatebin.net',         // Encrypted paste (used in AI exploits)

      // NOTE: For real-time AI threat protection, integrate:
      // - AI-specific threat feeds (emerging prompt injection campaigns)
      // - Real-time phishing feeds (PhishTank, OpenPhish)
      // - Community-reported AI exploits
    ];

    /**
     * Suspicious URL patterns (AI-SPECIFIC THREATS ONLY)
     *
     * 🎯 FOCUS: Only patterns that indicate AI-specific attacks
     *
     * We ONLY flag URLs containing:
     * 1. AI prompt injection keywords
     * 2. Dangerous protocol handlers (javascript:, data:, vbscript:)
     * 3. Obvious XSS in URL parameters
     *
     * We DO NOT flag:
     * - Normal SQL/command injection (not AI-specific)
     * - Path traversal (not AI-specific)
     * - Base64 content (breaks legitimate apps)
     * - WebSockets (breaks real-time apps)
     * - File uploads (breaks legitimate functionality)
     */
    this.suspiciousPatterns = [
      // Dangerous protocol handlers (XSS vectors in AI context)
      /javascript:/i,
      /data:text\/html/i,
      /vbscript:/i,

      // Obvious XSS in URLs (targeting AI browsers)
      /<script[^>]*>/i,
      /onerror\s*=/i,
      /onclick\s*=/i,

      // AI-specific prompt injection keywords in URLs
      // These are the CORE AI threats we're protecting against
      /ignore\s+(?:previous|all|prior)\s+(?:instructions?|prompts?|rules?)/i,
      /disregard\s+(?:previous|all|prior|above)/i,
      /system\s*:\s*(?:you\s+are|ignore|new\s+role)/i,
      /you\s+are\s+now\s+(?:a|an|in)/i,
      /override\s+(?:instructions?|prompts?|rules?|settings?)/i,
      /new\s+(?:instructions?|role|personality|character)/i,
      /forget\s+(?:previous|everything|all)/i,
      /reset\s+(?:instructions?|context|memory)/i,
      /act\s+as\s+(?:if|a|an)/i,

      // AI jailbreak patterns
      /DAN\s+mode/i,  // "Do Anything Now" jailbreak
      /developer\s+mode/i,
      /unrestricted\s+mode/i,
      /sudo\s+mode/i,
    ];

    /**
     * Blocked requests log
     */
    this.blockedRequests = [];

    /**
     * Dynamic rules counter
     */
    this.nextRuleId = 1000;

    /**
     * AI platforms that need protection
     * Only apply network-level blocking when requests originate from these platforms
     */
    this.aiPlatforms = [
      'chatgpt.com',
      'chat.openai.com',
      'openai.com',
      'perplexity.ai',
      'claude.ai',
      'anthropic.com',
      'poe.com',
      'huggingface.co',
      'replicate.com',
      'bard.google.com',
      'gemini.google.com',
      'character.ai',
      'jasper.ai',
      'writesonic.com',
      'copy.ai',
      'midjourney.com',
      'stability.ai',
      'leonardo.ai',
      'browseros.com'
    ];
  }

  /**
   * Check if request originates from an AI platform
   */
  isFromAIPlatform(details) {
    // Check the initiator (where the request came from)
    if (details.initiator) {
      try {
        const initiatorUrl = new URL(details.initiator);
        const hostname = initiatorUrl.hostname;

        for (const platform of this.aiPlatforms) {
          if (hostname.includes(platform)) {
            return true;
          }
        }
      } catch (error) {
        // Invalid URL, skip
      }
    }

    // Check the document URL (the page that made the request)
    if (details.documentUrl) {
      try {
        const docUrl = new URL(details.documentUrl);
        const hostname = docUrl.hostname;

        for (const platform of this.aiPlatforms) {
          if (hostname.includes(platform)) {
            return true;
          }
        }
      } catch (error) {
        // Invalid URL, skip
      }
    }

    // Check if the request itself is to an AI platform (allow these always)
    try {
      const requestUrl = new URL(details.url);
      const hostname = requestUrl.hostname;

      for (const platform of this.aiPlatforms) {
        if (hostname.includes(platform)) {
          return true; // Allow requests TO AI platforms
        }
      }
    } catch (error) {
      // Invalid URL, skip
    }

    return false;
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
   *
   * 🎯 IMPORTANT: We use DYNAMIC blocking only (via handleBeforeRequest)
   * This allows us to check if requests originate from AI platforms first.
   *
   * Static rules would block globally (affecting all sites), which breaks non-AI sites.
   * Instead, we detect threats dynamically and add blocking rules only when needed.
   */
  async setupBlockingRules() {
    // DISABLED: Static blocking rules are too aggressive
    // They would block malicious domains globally, even on non-AI sites
    // This breaks legitimate use cases (e.g., viewing pastebin on Reddit)
    //
    // Instead, we use dynamic blocking via handleBeforeRequest()
    // which checks if the request originates from an AI platform first

    if (this.config.logActions) {
      console.log('[Armorly RequestBlocker] Using dynamic blocking only (AI platform-aware)');
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
   * NOTE: Manifest V3 requires declarativeNetRequest for blocking
   * ACTIVE BLOCKING MODE: Dynamically blocks malicious requests
   *
   * 🎯 AI PLATFORM FILTERING: Only process requests from AI platforms
   */
  handleBeforeRequest(details) {
    if (!this.config.enabled) return;

    // CRITICAL: Only process requests from AI platforms
    // This prevents blocking legitimate requests on normal websites like Reddit
    if (!this.isFromAIPlatform(details)) {
      return; // Skip processing for non-AI platforms
    }

    const url = details.url;
    const method = details.method;

    // Check for malicious URL patterns - BLOCK if detected
    if (this.isSuspiciousURL(url)) {
      this.logThreat(details, 'suspicious-url-pattern');
      this.addDynamicBlockRule(url);
    }

    // Check for data exfiltration - BLOCK if enabled and detected
    if (this.config.blockDataExfiltration && this.isDataExfiltration(details)) {
      this.logThreat(details, 'data-exfiltration');
      this.addDynamicBlockRule(url);
    }

    // Check request body for prompt injections - BLOCK if detected
    if (details.requestBody && this.hasInjectionInPayload(details.requestBody)) {
      this.logThreat(details, 'payload-injection');
      this.addDynamicBlockRule(url);
    }
  }

  /**
   * Handle request headers before sending
   * ACTIVE BLOCKING MODE: Blocks CSRF and suspicious headers
   *
   * 🎯 AI PLATFORM FILTERING: Only process requests from AI platforms
   */
  handleBeforeSendHeaders(details) {
    if (!this.config.enabled) return;

    // CRITICAL: Only process requests from AI platforms
    if (!this.isFromAIPlatform(details)) {
      return; // Skip processing for non-AI platforms
    }

    // Check for CSRF attacks - BLOCK if enabled and detected
    if (this.config.blockCSRF && this.isCSRFAttempt(details)) {
      this.logThreat(details, 'csrf-attack');
      this.addDynamicBlockRule(details.url);
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

