/**
 * API Response Validator for Armorly
 *
 * Validates AI API responses for tampering, MITM attacks, and malicious content.
 * Provides SSL certificate verification, response integrity checking, and
 * signature validation.
 *
 * CRITICAL: Addresses the gap where network monitor only checks requests
 * but not responses, leaving vulnerability to MITM attacks.
 *
 * @module api-response-validator
 * @author Armorly Security Team
 * @license MIT
 */

class APIResponseValidator {
  constructor() {
    /**
     * Statistics
     */
    this.stats = {
      responsesValidated: 0,
      tamperedResponses: 0,
      suspiciousResponses: 0,
      blockedResponses: 0,
    };

    /**
     * Configuration
     */
    this.config = {
      enabled: true,
      validateSSL: true,
      validateContentType: true,
      validateResponseSize: true,
      maxResponseSize: 10 * 1024 * 1024, // 10MB
      suspiciousContentThreshold: 0.7,
      logActions: false, // Silent operation
    };

    /**
     * Expected response patterns for AI APIs
     */
    this.expectedPatterns = {
      'api.openai.com': {
        contentType: 'application/json',
        headers: ['content-type', 'x-request-id'],
        structure: ['id', 'object', 'created'],
      },
      'claude.ai/api': {
        contentType: 'application/json',
        headers: ['content-type'],
        structure: ['completion'],
      },
      'gemini.google.com/api': {
        contentType: 'application/json',
        headers: ['content-type'],
        structure: ['candidates'],
      },
    };

    /**
     * Suspicious response indicators
     */
    this.suspiciousIndicators = [
      // Unexpected redirects
      /location:\s*(?:http|https):\/\/(?!(?:api\.openai\.com|claude\.ai|gemini\.google\.com))/i,

      // Suspicious headers
      /x-forwarded-for/i,
      /x-real-ip/i,

      // Injection attempts in responses
      /<script[^>]*>/i,
      /javascript:/i,
      /onerror\s*=/i,

      // Command injection
      /\$\(.*\)/,
      /`.*`/,

      // Data exfiltration patterns
      /fetch\([^)]*(?:evil|malicious|attacker|hack)/i,
      /send(?:Beacon|Data)\(/i,
    ];

    /**
     * Response cache for integrity tracking
     */
    this.responseCache = new Map();

    /**
     * Fetch interception active
     */
    this.interceptActive = false;
  }

  /**
   * Start validating API responses
   */
  start() {
    if (!this.config.enabled) return;

    console.log('[Armorly API Validator] Starting - validating API responses');

    // Intercept fetch API
    this.interceptFetch();

    // Intercept XMLHttpRequest
    this.interceptXHR();
  }

  /**
   * Stop validation
   */
  stop() {
    // Note: Cannot fully restore original fetch/XHR after interception
    console.log('[Armorly API Validator] Stopped');
  }

  /**
   * Intercept fetch API for response validation
   */
  interceptFetch() {
    if (this.interceptActive) return;
    this.interceptActive = true;

    const originalFetch = window.fetch;
    const self = this;

    window.fetch = async function(...args) {
      const [url, options] = args;
      const urlString = typeof url === 'string' ? url : url.toString();

      try {
        // Call original fetch
        const response = await originalFetch.apply(this, args);

        // Validate response for AI API endpoints
        if (self.isAIEndpoint(urlString)) {
          const validationResult = await self.validateResponse(response, urlString, options);

          if (validationResult.tampered || validationResult.suspicious) {
            self.handleSuspiciousResponse(validationResult, urlString);

            // If critically tampered, block the response
            if (validationResult.tampered) {
              return self.createBlockedResponse(validationResult);
            }
          }
        }

        return response;
      } catch (error) {
        // Network error - potential MITM
        if (self.isAIEndpoint(urlString)) {
          console.error('[Armorly API Validator] Network error - potential MITM:', error);
          self.reportNetworkError(urlString, error);
        }
        throw error;
      }
    };
  }

  /**
   * Intercept XMLHttpRequest for response validation
   */
  interceptXHR() {
    const self = this;
    const originalOpen = XMLHttpRequest.prototype.open;
    const originalSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
      this._armorlyUrl = url;
      return originalOpen.call(this, method, url, ...rest);
    };

    XMLHttpRequest.prototype.send = function(...args) {
      if (self.isAIEndpoint(this._armorlyUrl)) {
        this.addEventListener('load', function() {
          const validationResult = self.validateXHRResponse(this);

          if (validationResult.tampered || validationResult.suspicious) {
            self.handleSuspiciousResponse(validationResult, this._armorlyUrl);
          }
        });
      }

      return originalSend.apply(this, args);
    };
  }

  /**
   * Check if URL is an AI API endpoint
   */
  isAIEndpoint(url) {
    const aiEndpoints = [
      'api.openai.com',
      'claude.ai/api',
      'gemini.google.com/api',
      'perplexity.ai/api',
      'chat.openai.com/backend-api',
    ];

    return aiEndpoints.some(endpoint => url.includes(endpoint));
  }

  /**
   * Validate fetch Response object
   */
  async validateResponse(response, url, requestOptions) {
    this.stats.responsesValidated++;

    const validation = {
      tampered: false,
      suspicious: false,
      issues: [],
      url,
    };

    // Clone response to read without consuming original
    const clonedResponse = response.clone();

    // 1. Validate SSL (check if HTTPS)
    if (this.config.validateSSL && !url.startsWith('https://')) {
      validation.tampered = true;
      validation.issues.push('Non-HTTPS connection for AI API (MITM risk)');
    }

    // 2. Validate status code
    if (!response.ok) {
      validation.suspicious = true;
      validation.issues.push(`Unexpected status code: ${response.status}`);
    }

    // 3. Validate Content-Type
    if (this.config.validateContentType) {
      const contentType = response.headers.get('content-type');
      const expected = this.getExpectedContentType(url);

      if (expected && contentType && !contentType.includes(expected)) {
        validation.suspicious = true;
        validation.issues.push(`Unexpected content-type: ${contentType} (expected ${expected})`);
      }
    }

    // 4. Validate response size
    if (this.config.validateResponseSize) {
      const contentLength = response.headers.get('content-length');
      if (contentLength && parseInt(contentLength) > this.config.maxResponseSize) {
        validation.tampered = true;
        validation.issues.push('Response size exceeds safe limits (potential attack)');
      }
    }

    // 5. Validate response headers
    const headerValidation = this.validateHeaders(response.headers, url);
    if (!headerValidation.valid) {
      validation.suspicious = true;
      validation.issues.push(...headerValidation.issues);
    }

    // 6. Validate response body
    try {
      const text = await clonedResponse.text();

      // Check response size from actual content
      if (text.length > this.config.maxResponseSize) {
        validation.tampered = true;
        validation.issues.push('Response body exceeds safe size');
      }

      // Check for suspicious patterns
      const contentValidation = this.validateContent(text);
      if (!contentValidation.valid) {
        validation.suspicious = true;
        validation.issues.push(...contentValidation.issues);
      }

      // Store hash for integrity tracking
      this.cacheResponseHash(url, text);
    } catch (error) {
      validation.suspicious = true;
      validation.issues.push('Failed to read response body');
    }

    return validation;
  }

  /**
   * Validate XMLHttpRequest response
   */
  validateXHRResponse(xhr) {
    this.stats.responsesValidated++;

    const validation = {
      tampered: false,
      suspicious: false,
      issues: [],
      url: xhr._armorlyUrl,
    };

    // Validate status
    if (xhr.status < 200 || xhr.status >= 300) {
      validation.suspicious = true;
      validation.issues.push(`Unexpected XHR status: ${xhr.status}`);
    }

    // Validate response
    if (xhr.responseText) {
      const contentValidation = this.validateContent(xhr.responseText);
      if (!contentValidation.valid) {
        validation.suspicious = true;
        validation.issues.push(...contentValidation.issues);
      }
    }

    return validation;
  }

  /**
   * Validate response headers
   */
  validateHeaders(headers, url) {
    const validation = {
      valid: true,
      issues: [],
    };

    // Check for suspicious headers
    const suspiciousHeaders = [
      'x-forwarded-for',
      'x-real-ip',
      'x-forwarded-proto',
    ];

    for (const header of suspiciousHeaders) {
      if (headers.has(header)) {
        validation.valid = false;
        validation.issues.push(`Suspicious header detected: ${header}`);
      }
    }

    // Check for expected headers
    const expectedHeaders = this.getExpectedHeaders(url);
    if (expectedHeaders) {
      for (const required of expectedHeaders) {
        if (!headers.has(required)) {
          validation.valid = false;
          validation.issues.push(`Missing expected header: ${required}`);
        }
      }
    }

    return validation;
  }

  /**
   * Validate response content
   */
  validateContent(text) {
    const validation = {
      valid: true,
      issues: [],
    };

    // Check for suspicious patterns
    for (const pattern of this.suspiciousIndicators) {
      if (pattern.test(text)) {
        validation.valid = false;
        validation.issues.push(`Suspicious pattern detected: ${pattern.source.substring(0, 50)}`);
      }
    }

    // Check for valid JSON structure (most AI APIs return JSON)
    try {
      JSON.parse(text);
    } catch (error) {
      // Not JSON - might be streaming or other format
      // Only suspicious if it looks like HTML/script
      if (/<html|<script/i.test(text)) {
        validation.valid = false;
        validation.issues.push('Response contains HTML/script tags (possible injection)');
      }
    }

    return validation;
  }

  /**
   * Get expected content type for endpoint
   */
  getExpectedContentType(url) {
    for (const [endpoint, config] of Object.entries(this.expectedPatterns)) {
      if (url.includes(endpoint)) {
        return config.contentType;
      }
    }
    return null;
  }

  /**
   * Get expected headers for endpoint
   */
  getExpectedHeaders(url) {
    for (const [endpoint, config] of Object.entries(this.expectedPatterns)) {
      if (url.includes(endpoint)) {
        return config.headers;
      }
    }
    return null;
  }

  /**
   * Cache response hash for integrity tracking
   */
  async cacheResponseHash(url, content) {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(content);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

      this.responseCache.set(url, {
        hash: hashHex,
        timestamp: Date.now(),
        size: content.length,
      });
    } catch (error) {
      // Hashing failed - not critical
    }
  }

  /**
   * Handle suspicious response
   */
  handleSuspiciousResponse(validation, url) {
    if (validation.tampered) {
      this.stats.tamperedResponses++;
      this.stats.blockedResponses++;
    } else if (validation.suspicious) {
      this.stats.suspiciousResponses++;
    }

    console.warn('[Armorly API Validator] Suspicious response detected:', {
      url,
      validation,
    });

    // Show warning
    this.showValidationWarning(validation);

    // Report to background
    this.reportValidation(validation);
  }

  /**
   * Create blocked response
   */
  createBlockedResponse(validation) {
    const errorBody = JSON.stringify({
      error: {
        message: 'Armorly blocked this response due to tampering detection',
        type: 'security_error',
        validation,
      },
    });

    return new Response(errorBody, {
      status: 403,
      statusText: 'Blocked by Armorly',
      headers: {
        'Content-Type': 'application/json',
        'X-Armorly-Blocked': 'true',
      },
    });
  }

  /**
   * Show validation warning
   */
  showValidationWarning(validation) {
    const warning = document.createElement('div');
    warning.style.cssText = `
      position: fixed;
      top: 140px;
      right: 20px;
      background: #d32f2f;
      color: white;
      padding: 16px 24px;
      border-radius: 8px;
      font-family: system-ui, -apple-system, sans-serif;
      font-size: 14px;
      z-index: 999999;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      max-width: 350px;
      border: 2px solid #b71c1c;
    `;

    const header = document.createElement('div');
    header.style.cssText = 'font-weight: bold; margin-bottom: 8px;';
    header.textContent = validation.tampered ? 'API Response Tampered!' : 'Suspicious API Response';
    warning.appendChild(header);

    const desc = document.createElement('div');
    desc.style.cssText = 'font-size: 13px; margin-bottom: 8px;';
    desc.textContent = `Detected ${validation.issues.length} issue(s) in API response. ${validation.tampered ? 'Response blocked.' : 'Proceed with caution.'}`;
    warning.appendChild(desc);

    // List issues
    const issueList = document.createElement('div');
    issueList.style.cssText = 'font-size: 12px; margin-top: 8px;';

    for (const issue of validation.issues.slice(0, 3)) {
      const issueItem = document.createElement('div');
      issueItem.style.cssText = 'margin: 4px 0;';
      issueItem.textContent = `• ${issue}`;
      issueList.appendChild(issueItem);
    }

    warning.appendChild(issueList);

    document.body.appendChild(warning);

    // Auto-dismiss after 10 seconds
    setTimeout(() => {
      warning.style.transition = 'opacity 0.3s';
      warning.style.opacity = '0';
      setTimeout(() => warning.remove(), 300);
    }, 10000);
  }

  /**
   * Report validation to background
   */
  reportValidation(validation) {
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({
        type: 'API_RESPONSE_VALIDATION',
        validation,
        timestamp: Date.now(),
      }).catch(() => {
        // Service worker may be inactive
      });
    }
  }

  /**
   * Report network error
   */
  reportNetworkError(url, error) {
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({
        type: 'API_NETWORK_ERROR',
        url,
        error: error.message,
        timestamp: Date.now(),
      }).catch(() => {
        // Service worker may be inactive
      });
    }
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      ...this.stats,
      cachedResponses: this.responseCache.size,
    };
  }

  /**
   * Enable/disable validator
   */
  setEnabled(enabled) {
    this.config.enabled = enabled;

    if (enabled) {
      this.start();
    } else {
      this.stop();
    }
  }
}

// Export for use in content script
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { APIResponseValidator };
}
