/**
 * CSRF Detector for Armorly
 * 
 * This module prevents the "ChatGPT Tainted Memories" attack documented by LayerX Security.
 * 
 * ATTACK VECTOR:
 * Attackers use Cross-Site Request Forgery (CSRF) to inject malicious instructions into
 * ChatGPT's memory system. The attack works as follows:
 * 
 * 1. User visits a malicious webpage while logged into ChatGPT
 * 2. The page triggers a POST request to ChatGPT's memory API endpoints
 * 3. The browser automatically includes the user's authentication cookies
 * 4. Malicious instructions get stored in ChatGPT's memory
 * 5. These "tainted memories" persist across all devices
 * 6. When the user asks ChatGPT for help, the malicious instructions execute
 * 
 * This is especially dangerous for "vibe coding" where developers trust AI-generated code.
 * 
 * DEFENSE STRATEGY:
 * This detector monitors all outgoing HTTP requests and flags those that:
 * - Target known AI service memory/preference endpoints
 * - Originate from third-party domains (cross-origin)
 * - Contain instruction-like patterns in the payload
 * - Lack proper CSRF tokens or same-site protections
 * 
 * @module csrf-detector
 * @author Armorly Security Team
 * @license MIT
 */

export class CSRFDetector {
  constructor() {
    /**
     * Known AI service endpoints that are vulnerable to memory poisoning
     * These patterns match ChatGPT, Claude, and other AI assistant APIs
     */
    this.vulnerableEndpoints = [
      // ChatGPT memory endpoints
      /chat\.openai\.com\/backend-api\/memories/i,
      /chatgpt\.com\/backend-api\/memories/i,
      /chat\.openai\.com\/backend-api\/user_system_messages/i,
      /chatgpt\.com\/backend-api\/user_system_messages/i,
      /chat\.openai\.com\/backend-api\/settings/i,
      /chatgpt\.com\/backend-api\/settings/i,

      // Perplexity endpoints
      /perplexity\.ai\/api\/preferences/i,
      /perplexity\.ai\/api\/memory/i,

      // Generic AI assistant patterns
      /\/api\/.*memory/i,
      /\/api\/.*preferences/i,
      /\/api\/.*custom[-_]instructions/i,
      /\/backend-api\/.*memory/i
    ];

    /**
     * Request timing tracker for detecting rapid-fire attacks
     * Maps domain -> array of timestamps
     */
    this.requestTimings = new Map();

    /**
     * Timing analysis configuration
     */
    this.timingConfig = {
      windowMs: 10000,        // 10 second window
      maxRequests: 5,         // Max 5 requests per window
      rapidFireThreshold: 3   // 3+ requests in 1 second = suspicious
    };

    /**
     * Trusted domains that are allowed to make requests to AI endpoints
     * Requests from these domains are not flagged as CSRF
     */
    this.trustedDomains = [
      'chat.openai.com',
      'chatgpt.com',
      'openai.com',
      'perplexity.ai',
      'anthropic.com',
      'claude.ai'
    ];

    /**
     * Patterns that indicate instruction injection in request payloads
     * These are common phrases used in prompt injection attacks
     */
    this.instructionPatterns = [
      /ignore\s+(all\s+)?(previous|prior|earlier)\s+instructions/gi,
      /disregard\s+(your\s+)?programming/gi,
      /you\s+are\s+now\s+a/gi,
      /your\s+new\s+(primary\s+)?(objective|goal|directive)/gi,
      /always\s+(fetch|import|include|use)\s+(from|dependencies)/gi,
      /when\s+(writing|generating|creating)\s+code/gi,
      /remember\s+this\s+for\s+all\s+future/gi,
      /system\s*:\s*new\s+directive/gi,
      /admin\s+override/gi,
      /secret\s+(instruction|mission|task)/gi
    ];

    /**
     * Threat score thresholds for decision making
     */
    this.thresholds = {
      CRITICAL: 90,  // Block immediately
      HIGH: 70,      // Show warning overlay
      MEDIUM: 40,    // Log and notify
      LOW: 0         // Log silently
    };
  }

  /**
   * Main analysis function for incoming request details
   * 
   * @param {Object} details - Chrome webRequest details object
   * @param {string} details.url - The target URL
   * @param {string} details.method - HTTP method (POST, PUT, PATCH, etc.)
   * @param {string} details.initiator - Origin of the request
   * @param {Object} details.requestBody - Request payload (if available)
   * @param {Array} details.requestHeaders - HTTP headers
   * @returns {Object} Analysis result with threat score and indicators
   */
  analyzeRequest(details) {
    const result = {
      isThreat: false,
      score: 0,
      indicators: [],
      endpoint: details.url,
      origin: details.initiator || 'unknown',
      shouldBlock: false,
      threatType: 'CSRF',
      confidence: 0
    };

    // Only analyze state-changing requests
    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(details.method)) {
      return result;
    }

    // Check if request targets a vulnerable endpoint
    const targetsVulnerableEndpoint = this.isVulnerableEndpoint(details.url);
    if (!targetsVulnerableEndpoint) {
      return result;
    }

    result.indicators.push('Targets AI memory/preference endpoint');
    result.score += 35;

    // Check for origin mismatch (cross-origin request)
    const originMismatch = this.checkOriginMismatch(details);
    if (originMismatch.isMismatch) {
      result.indicators.push(`Cross-origin request from: ${originMismatch.origin}`);
      result.score += 50;
    }

    // Analyze request payload for malicious patterns
    if (details.requestBody) {
      const payloadAnalysis = this.scanPayload(details.requestBody);
      if (payloadAnalysis.suspicious) {
        result.indicators.push(...payloadAnalysis.patterns);
        result.score += payloadAnalysis.score;
      }
    }

    // Check for missing CSRF protections
    const csrfProtection = this.checkCSRFProtection(details.requestHeaders);
    if (!csrfProtection.hasProtection) {
      result.indicators.push('Missing CSRF token or same-site protection');
      result.score += 30;
    } else {
      // Has CSRF protection - significantly reduce threat score
      result.indicators.push('Has CSRF protection (token or SameSite cookie)');
      result.score = Math.max(0, result.score - 40);
    }

    // Analyze request timing for rapid-fire attacks
    const timingAnalysis = this.analyzeRequestTiming(details.url);
    if (timingAnalysis.isRapidFire) {
      result.indicators.push(`Rapid-fire attack detected: ${timingAnalysis.requestCount} requests in ${timingAnalysis.timeWindow}ms`);
      result.score += 40;
    } else if (timingAnalysis.isSuspicious) {
      result.indicators.push(`Suspicious request frequency: ${timingAnalysis.requestCount} requests in ${timingAnalysis.timeWindow}ms`);
      result.score += 20;
    }

    // Calculate final threat assessment
    result.isThreat = result.score >= this.thresholds.MEDIUM;
    result.shouldBlock = result.score >= this.thresholds.CRITICAL;
    result.confidence = Math.min(100, result.score);

    return result;
  }

  /**
   * Check if URL matches known vulnerable endpoints
   * 
   * @param {string} url - The request URL
   * @returns {boolean} True if endpoint is vulnerable
   */
  isVulnerableEndpoint(url) {
    return this.vulnerableEndpoints.some(pattern => pattern.test(url));
  }

  /**
   * Validate request origin against target domain
   * 
   * @param {Object} details - Request details
   * @returns {Object} Origin mismatch analysis
   */
  checkOriginMismatch(details) {
    const result = {
      isMismatch: false,
      origin: details.initiator || 'unknown',
      target: new URL(details.url).hostname
    };

    // If no initiator, assume suspicious
    if (!details.initiator || details.initiator === 'null') {
      result.isMismatch = true;
      return result;
    }

    try {
      const originHost = new URL(details.initiator).hostname;
      const targetHost = new URL(details.url).hostname;

      // Check if origin is trusted
      const isTrustedOrigin = this.trustedDomains.some(domain => 
        originHost === domain || originHost.endsWith('.' + domain)
      );

      // Check if target is trusted
      const isTrustedTarget = this.trustedDomains.some(domain =>
        targetHost === domain || targetHost.endsWith('.' + domain)
      );

      // Mismatch if origin is not trusted but target is
      if (!isTrustedOrigin && isTrustedTarget) {
        result.isMismatch = true;
      }

      // Also flag if origins don't match at all
      if (originHost !== targetHost && !isTrustedOrigin) {
        result.isMismatch = true;
      }

    } catch (error) {
      // If URL parsing fails, assume suspicious
      result.isMismatch = true;
    }

    return result;
  }

  /**
   * Scan request payload for malicious instruction patterns
   * 
   * @param {Object} requestBody - Chrome webRequest body object
   * @returns {Object} Payload analysis results
   */
  scanPayload(requestBody) {
    const result = {
      suspicious: false,
      patterns: [],
      score: 0
    };

    try {
      // Extract text from various request body formats
      let bodyText = '';

      if (requestBody.raw) {
        // Binary data - decode to text
        bodyText = requestBody.raw.map(part => {
          if (part.bytes) {
            return new TextDecoder().decode(new Uint8Array(part.bytes));
          }
          return '';
        }).join('');
      } else if (requestBody.formData) {
        // Form data - stringify
        bodyText = JSON.stringify(requestBody.formData);
      }

      // Check for Base64 encoding (common obfuscation technique)
      if (this.containsBase64(bodyText)) {
        result.patterns.push('Contains Base64-encoded content');
        result.score += 25;

        // Try to decode and scan
        const decoded = this.decodeBase64Safely(bodyText);
        if (decoded) {
          bodyText += ' ' + decoded;
        }
      }

      // Analyze JSON structure for memory poisoning patterns
      try {
        const jsonData = JSON.parse(bodyText);
        const jsonAnalysis = this.analyzeJSONPayload(jsonData);
        if (jsonAnalysis.suspicious) {
          result.suspicious = true;
          result.patterns.push(...jsonAnalysis.patterns);
          result.score += jsonAnalysis.score;
        }
      } catch (e) {
        // Not JSON or invalid JSON, continue with text analysis
      }

      // Scan for instruction patterns
      for (const pattern of this.instructionPatterns) {
        const matches = bodyText.match(pattern);
        if (matches) {
          result.suspicious = true;
          result.patterns.push(`Detected pattern: "${matches[0]}"`);
          result.score += 40;
        }
      }

      // Check for URL patterns in payload (data exfiltration)
      const urlPattern = /https?:\/\/[^\s"']+/gi;
      const urls = bodyText.match(urlPattern);
      if (urls && urls.length > 0) {
        // Check if URLs point to suspicious domains
        const suspiciousUrls = urls.filter(url => {
          const domain = new URL(url).hostname;
          return !this.trustedDomains.some(trusted =>
            domain === trusted || domain.endsWith('.' + trusted)
          );
        });

        if (suspiciousUrls.length > 0) {
          result.suspicious = true;
          result.patterns.push(`Contains ${suspiciousUrls.length} external URL(s)`);
          result.score += 30;
        }
      }

    } catch (error) {
      console.error('[Armorly] Error scanning payload:', error);
    }

    return result;
  }

  /**
   * Analyze JSON payload for memory poisoning patterns
   *
   * @param {Object} jsonData - Parsed JSON data
   * @returns {Object} Analysis result
   */
  analyzeJSONPayload(jsonData) {
    const result = {
      suspicious: false,
      patterns: [],
      score: 0
    };

    // Recursively scan JSON for suspicious content
    const scanObject = (obj, path = '') => {
      if (typeof obj === 'string') {
        // Check string values for instruction patterns
        for (const pattern of this.instructionPatterns) {
          if (pattern.test(obj)) {
            result.suspicious = true;
            result.patterns.push(`Suspicious instruction in ${path || 'payload'}`);
            result.score += 35;
          }
        }

        // Check for code injection patterns
        if (obj.includes('eval(') || obj.includes('Function(') || obj.includes('require(')) {
          result.suspicious = true;
          result.patterns.push(`Code injection pattern in ${path || 'payload'}`);
          result.score += 40;
        }
      } else if (Array.isArray(obj)) {
        obj.forEach((item, index) => scanObject(item, `${path}[${index}]`));
      } else if (obj && typeof obj === 'object') {
        // Check for suspicious field names
        const suspiciousFields = ['instruction', 'command', 'directive', 'system_message', 'override'];
        for (const field of suspiciousFields) {
          if (field in obj) {
            result.suspicious = true;
            result.patterns.push(`Suspicious field: "${field}"`);
            result.score += 25;
          }
        }

        // Recursively scan nested objects
        Object.entries(obj).forEach(([key, value]) => {
          scanObject(value, path ? `${path}.${key}` : key);
        });
      }
    };

    scanObject(jsonData);
    return result;
  }

  /**
   * Check for CSRF protection mechanisms in request headers
   *
   * @param {Array} headers - Request headers
   * @returns {Object} CSRF protection status
   */
  checkCSRFProtection(headers) {
    const result = {
      hasProtection: false,
      mechanisms: []
    };

    if (!headers) return result;

    for (const header of headers) {
      const name = header.name.toLowerCase();
      
      // Check for CSRF tokens
      if (name.includes('csrf') || name.includes('xsrf')) {
        result.hasProtection = true;
        result.mechanisms.push('CSRF token present');
      }

      // Check for same-site cookie attribute (via cookie header analysis)
      if (name === 'cookie' && header.value.includes('SameSite')) {
        result.hasProtection = true;
        result.mechanisms.push('SameSite cookie protection');
      }
    }

    return result;
  }

  /**
   * Check if text contains Base64-encoded content
   * 
   * @param {string} text - Text to check
   * @returns {boolean} True if Base64 detected
   */
  containsBase64(text) {
    // Look for Base64 patterns (at least 20 chars of valid Base64)
    const base64Pattern = /[A-Za-z0-9+/]{20,}={0,2}/;
    return base64Pattern.test(text);
  }

  /**
   * Safely attempt to decode Base64 content
   * 
   * @param {string} text - Text potentially containing Base64
   * @returns {string|null} Decoded text or null if invalid
   */
  decodeBase64Safely(text) {
    try {
      const base64Match = text.match(/[A-Za-z0-9+/]{20,}={0,2}/);
      if (base64Match) {
        return atob(base64Match[0]);
      }
    } catch (error) {
      // Invalid Base64, ignore
    }
    return null;
  }

  /**
   * Analyze request timing to detect rapid-fire attacks
   *
   * @param {string} url - Request URL
   * @returns {Object} Timing analysis result
   */
  analyzeRequestTiming(url) {
    const now = Date.now();
    const domain = new URL(url).hostname;

    // Get or create timing array for this domain
    if (!this.requestTimings.has(domain)) {
      this.requestTimings.set(domain, []);
    }

    const timings = this.requestTimings.get(domain);

    // Add current request timestamp
    timings.push(now);

    // Clean up old timestamps outside the window
    const windowStart = now - this.timingConfig.windowMs;
    const recentTimings = timings.filter(t => t >= windowStart);
    this.requestTimings.set(domain, recentTimings);

    // Analyze timing patterns
    const result = {
      isRapidFire: false,
      isSuspicious: false,
      requestCount: recentTimings.length,
      timeWindow: this.timingConfig.windowMs
    };

    // Check for rapid-fire (3+ requests in 1 second)
    const oneSecondAgo = now - 1000;
    const rapidFireCount = recentTimings.filter(t => t >= oneSecondAgo).length;
    if (rapidFireCount >= this.timingConfig.rapidFireThreshold) {
      result.isRapidFire = true;
      result.timeWindow = 1000;
      result.requestCount = rapidFireCount;
      return result;
    }

    // Check for suspicious frequency (5+ requests in 10 seconds)
    if (recentTimings.length >= this.timingConfig.maxRequests) {
      result.isSuspicious = true;
      return result;
    }

    return result;
  }

  /**
   * Clear timing data for a domain (useful for cleanup)
   *
   * @param {string} domain - Domain to clear
   */
  clearTimingData(domain) {
    this.requestTimings.delete(domain);
  }

  /**
   * Clear all timing data (useful for testing)
   */
  clearAllTimingData() {
    this.requestTimings.clear();
  }

  /**
   * Calculate threat score and determine action
   *
   * @param {Object} analysis - Analysis result from analyzeRequest
   * @returns {string} Recommended action: 'BLOCK', 'WARN', 'LOG', or 'ALLOW'
   */
  getRecommendedAction(analysis) {
    if (analysis.score >= this.thresholds.CRITICAL) {
      return 'BLOCK';
    } else if (analysis.score >= this.thresholds.HIGH) {
      return 'WARN';
    } else if (analysis.score >= this.thresholds.MEDIUM) {
      return 'LOG';
    }
    return 'ALLOW';
  }
}
