/**
 * Armorly - Advanced Network Interceptor
 *
 * Deep packet inspection for data exfiltration and credential theft detection
 * across all chromium-based agentic browsers.
 *
 * IMPORTANT - Manifest V3 Limitation:
 * This module performs DETECTION ONLY. Chrome Manifest V3 does not support
 * blocking requests via webRequest API. Actual blocking must be implemented
 * using declarativeNetRequest rules (see rules/csrf-rules.json).
 *
 * Features:
 * - Request/response monitoring (detection only)
 * - Data exfiltration detection
 * - Credential leak detection
 * - Suspicious domain detection
 * - Payload analysis
 * - Rate limiting detection
 *
 * For actual blocking, use:
 * - chrome.declarativeNetRequest.updateDynamicRules() for runtime blocking
 * - rules/csrf-rules.json for static blocking rules
 */

export class NetworkInterceptor {
  constructor() {
    // Suspicious domains and patterns
    this.suspiciousDomains = [
      // Suspicious TLDs
      '.tk', '.ml', '.ga', '.cf', '.gq',
      // High-risk countries
      '.ru', '.cn', '.kp',
      // Known malicious patterns
      'evil', 'hack', 'phish', 'steal', 'malware', 'attacker',
    ];

    // Credential patterns
    this.credentialPatterns = [
      /password["\s:=]+[^"\s&]{6,}/gi,
      /passwd["\s:=]+[^"\s&]{6,}/gi,
      /api[_-]?key["\s:=]+[^"\s&]{10,}/gi,
      /access[_-]?token["\s:=]+[^"\s&]{10,}/gi,
      /bearer\s+[a-zA-Z0-9\-._~+/]+=*/gi,
      /authorization["\s:]+[^"\s&]{10,}/gi,
      /secret["\s:=]+[^"\s&]{10,}/gi,
      /private[_-]?key["\s:=]+[^"\s&]{10,}/gi,
    ];

    // Sensitive data patterns
    this.sensitiveDataPatterns = [
      /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, // Credit card
      /\b\d{3}-\d{2}-\d{4}\b/g, // SSN
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, // Email
    ];

    // Request tracking
    this.requests = new Map();
    this.blockedRequests = [];
    this.suspiciousRequests = [];

    // Rate limiting
    this.rateLimits = new Map(); // domain -> [timestamps]

    // Statistics
    // NOTE: "blockedRequests" is a misnomer - these are DETECTED threats
    // that would be blocked if MV3 allowed it. Actual blocking requires
    // declarativeNetRequest rules.
    this.statistics = {
      totalRequests: 0,
      blockedRequests: 0, // Actually "detectedThreats" - naming kept for compatibility
      suspiciousRequests: 0,
      credentialLeaks: 0,
      dataExfiltration: 0,
    };

    // Callback for threats
    this.threatCallback = null;

    // Initialize listeners
    this.initializeListeners();
  }

  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }

  /**
   * Initialize network listeners
   */
  initializeListeners() {
    // Listen to requests before they're sent
    chrome.webRequest.onBeforeRequest.addListener(
      (details) => this.handleBeforeRequest(details),
      { urls: ['<all_urls>'] },
      ['requestBody']
    );

    // Listen to request headers
    chrome.webRequest.onBeforeSendHeaders.addListener(
      (details) => this.handleBeforeSendHeaders(details),
      { urls: ['<all_urls>'] },
      ['requestHeaders']
    );

    // Listen to responses
    chrome.webRequest.onCompleted.addListener(
      (details) => this.handleCompleted(details),
      { urls: ['<all_urls>'] },
      ['responseHeaders']
    );

    // Listen to errors
    chrome.webRequest.onErrorOccurred.addListener(
      (details) => this.handleError(details),
      { urls: ['<all_urls>'] }
    );
  }

  /**
   * Handle request before it's sent
   *
   * NOTE: This function CANNOT block requests in Manifest V3.
   * It only detects threats and reports them. The `return` statements
   * are kept for compatibility but have no blocking effect.
   *
   * To actually block requests, add rules to declarativeNetRequest.
   */
  handleBeforeRequest(details) {
    this.statistics.totalRequests++;

    const { url, method, requestBody, tabId, type } = details;

    // Parse URL
    let domain;
    try {
      domain = new URL(url).hostname;
    } catch {
      return; // Invalid URL
    }

    // Detect rate limiting (detection only - cannot block)
    if (this.isRateLimited(domain)) {
      this.detectThreat(details, 'RATE_LIMITED');
      // Note: In MV3, we cannot block here. Consider adding dynamic
      // declarativeNetRequest rules for persistent rate limit violations.
    }

    // Detect suspicious domain (detection only - cannot block)
    if (this.isSuspiciousDomain(domain)) {
      this.detectThreat(details, 'SUSPICIOUS_DOMAIN');
      // Note: For blocking, add domain to declarativeNetRequest rules
    }

    // Analyze request body for sensitive data
    if (requestBody && method === 'POST') {
      const threat = this.analyzeRequestBody(requestBody, url);
      if (threat) {
        this.reportThreat(threat);

        if (threat.severity === 'CRITICAL') {
          this.detectThreat(details, threat.type);
          // Note: Cannot block in MV3 via webRequest API
          // Consider implementing dynamic declarativeNetRequest rules
        }
      }
    }

    // Track request
    this.requests.set(details.requestId, {
      url,
      method,
      domain,
      timestamp: Date.now(),
      tabId,
      type,
    });

    // MV3: No blocking capability via return value
    return {};
  }

  /**
   * Handle request headers
   */
  handleBeforeSendHeaders(details) {
    const { requestHeaders, url } = details;

    // Check for credential leaks in headers
    for (const header of requestHeaders || []) {
      if (this.containsCredentials(header.value)) {
        const threat = {
          type: 'CREDENTIAL_LEAK_HEADER',
          severity: 'CRITICAL',
          url,
          header: header.name,
          timestamp: Date.now(),
          description: `Credentials detected in ${header.name} header`,
        };

        this.reportThreat(threat);
        this.statistics.credentialLeaks++;
      }
    }

    return {};
  }

  /**
   * Handle completed request
   */
  handleCompleted(details) {
    const request = this.requests.get(details.requestId);
    if (request) {
      request.completed = true;
      request.statusCode = details.statusCode;
      request.responseHeaders = details.responseHeaders;
    }

    // Clean up old requests
    this.cleanupOldRequests();
  }

  /**
   * Handle request error
   */
  handleError(details) {
    const request = this.requests.get(details.requestId);
    if (request) {
      request.error = details.error;
    }
  }

  /**
   * Check if domain is rate limited
   */
  isRateLimited(domain) {
    const now = Date.now();
    const timestamps = this.rateLimits.get(domain) || [];

    // Remove timestamps older than 1 minute
    const recentTimestamps = timestamps.filter(t => now - t < 60000);

    // Update rate limit tracking
    recentTimestamps.push(now);
    this.rateLimits.set(domain, recentTimestamps);

    // Check if rate limit exceeded (100 requests per minute)
    return recentTimestamps.length > 100;
  }

  /**
   * Check if domain is suspicious
   */
  isSuspiciousDomain(domain) {
    return this.suspiciousDomains.some(pattern => domain.includes(pattern));
  }

  /**
   * Analyze request body for sensitive data
   */
  analyzeRequestBody(requestBody, url) {
    let bodyText = '';

    // Extract text from request body
    if (requestBody.formData) {
      bodyText = JSON.stringify(requestBody.formData);
    } else if (requestBody.raw) {
      try {
        const decoder = new TextDecoder();
        bodyText = requestBody.raw.map(r => decoder.decode(r.bytes)).join('');
      } catch {
        return null;
      }
    }

    // Check for credentials
    if (this.containsCredentials(bodyText)) {
      this.statistics.credentialLeaks++;
      return {
        type: 'CREDENTIAL_LEAK_BODY',
        severity: 'CRITICAL',
        url,
        timestamp: Date.now(),
        description: 'Credentials detected in request body',
        bodySize: bodyText.length,
      };
    }

    // Check for sensitive data
    if (this.containsSensitiveData(bodyText)) {
      return {
        type: 'SENSITIVE_DATA_TRANSFER',
        severity: 'HIGH',
        url,
        timestamp: Date.now(),
        description: 'Sensitive data detected in request body',
        bodySize: bodyText.length,
      };
    }

    // Check for large data transfer to suspicious domain
    if (bodyText.length > 10000) {
      let domain;
      try {
        domain = new URL(url).hostname;
      } catch {
        return null;
      }

      if (this.isSuspiciousDomain(domain)) {
        this.statistics.dataExfiltration++;
        return {
          type: 'DATA_EXFILTRATION',
          severity: 'CRITICAL',
          url,
          domain,
          timestamp: Date.now(),
          description: `Large data transfer (${bodyText.length} bytes) to suspicious domain`,
          bodySize: bodyText.length,
        };
      }
    }

    return null;
  }

  /**
   * Check if text contains credentials
   */
  containsCredentials(text) {
    if (!text) return false;
    return this.credentialPatterns.some(pattern => pattern.test(text));
  }

  /**
   * Check if text contains sensitive data
   */
  containsSensitiveData(text) {
    if (!text) return false;
    return this.sensitiveDataPatterns.some(pattern => pattern.test(text));
  }

  /**
   * Detect threat in request
   *
   * NOTE: Despite the name "blockedRequests", this method ONLY DETECTS threats
   * in Manifest V3. It cannot actually block the request. The statistics and
   * naming are preserved for backwards compatibility, but understand that
   * "blocked" means "detected and would be blocked if browser API allowed it".
   *
   * For actual blocking, implement declarativeNetRequest dynamic rules.
   */
  detectThreat(details, reason) {
    this.statistics.blockedRequests++; // Misleading name, actually "detected threats"

    const detected = {
      ...details,
      reason,
      timestamp: Date.now(),
    };

    this.blockedRequests.push(detected); // Misleading name, actually "detected threats"

    // Report as threat
    this.reportThreat({
      type: 'DETECTED_THREAT',
      severity: 'HIGH',
      url: details.url,
      reason,
      timestamp: Date.now(),
      description: `Threat detected (MV3 cannot block): ${reason}`,
    });

    // Limit detected requests history
    if (this.blockedRequests.length > 1000) {
      this.blockedRequests = this.blockedRequests.slice(-1000);
    }
  }

  /**
   * Report threat
   */
  reportThreat(threat) {
    this.suspiciousRequests.push(threat);

    if (this.threatCallback) {
      this.threatCallback(threat);
    }

    // Limit suspicious requests history
    if (this.suspiciousRequests.length > 1000) {
      this.suspiciousRequests = this.suspiciousRequests.slice(-1000);
    }
  }

  /**
   * Clean up old requests
   */
  cleanupOldRequests() {
    const now = Date.now();
    const maxAge = 300000; // 5 minutes

    for (const [requestId, request] of this.requests.entries()) {
      if (now - request.timestamp > maxAge) {
        this.requests.delete(requestId);
      }
    }
  }

  /**
   * Add suspicious domain
   */
  addSuspiciousDomain(domain) {
    if (!this.suspiciousDomains.includes(domain)) {
      this.suspiciousDomains.push(domain);
    }
  }

  /**
   * Remove suspicious domain
   */
  removeSuspiciousDomain(domain) {
    this.suspiciousDomains = this.suspiciousDomains.filter(d => d !== domain);
  }

  /**
   * Get statistics
   *
   * NOTE: "blockedRequests" actually means "detected threats that would be
   * blocked if the browser API supported it". In Manifest V3, webRequest
   * cannot block - only detect.
   */
  getStatistics() {
    return {
      ...this.statistics,
      activeRequests: this.requests.size,
      recentBlocked: this.blockedRequests.slice(-10), // Actually "detected threats"
      recentSuspicious: this.suspiciousRequests.slice(-10),
    };
  }

  /**
   * Get detected threats (misleadingly named "blocked requests")
   *
   * NOTE: These are threats that were DETECTED, not actually blocked.
   * Manifest V3 does not allow webRequest API to block requests.
   */
  getBlockedRequests(limit = 50) {
    return this.blockedRequests.slice(-limit).reverse();
  }

  /**
   * Get suspicious requests
   */
  getSuspiciousRequests(limit = 50) {
    return this.suspiciousRequests.slice(-limit).reverse();
  }

  /**
   * Reset statistics
   */
  resetStatistics() {
    this.statistics = {
      totalRequests: 0,
      blockedRequests: 0,
      suspiciousRequests: 0,
      credentialLeaks: 0,
      dataExfiltration: 0,
    };
    this.blockedRequests = [];
    this.suspiciousRequests = [];
  }
}

