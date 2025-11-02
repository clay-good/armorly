/**
 * Token Consumption Monitor for Armorly
 * 
 * Monitors API usage and token consumption to detect and prevent DoS attacks.
 * Addresses OWASP LLM04: Model Denial of Service
 * 
 * Features:
 * - Track token usage per request
 * - Detect excessive consumption patterns
 * - Rate limiting per domain/user
 * - Alert on suspicious usage
 * - Prevent resource exhaustion
 * - Cost tracking and budgeting
 * 
 * @module token-consumption-monitor
 * @author Armorly Security Team
 */

export class TokenConsumptionMonitor {
  constructor() {
    /**
     * Statistics
     */
    this.stats = {
      totalRequests: 0,
      totalTokens: 0,
      blockedRequests: 0,
      suspiciousPatterns: 0,
      rateLimitHits: 0,
    };

    /**
     * Configuration
     */
    this.config = {
      enabled: true,
      maxTokensPerRequest: 4000,
      maxTokensPerMinute: 10000,
      maxTokensPerHour: 100000,
      maxRequestsPerMinute: 60,
      alertThreshold: 0.8, // Alert at 80% of limit
      blockOnExceed: true,
      logActions: true,
    };

    /**
     * Token tracking per domain
     */
    this.domainUsage = new Map();

    /**
     * Request history (for rate limiting)
     */
    this.requestHistory = [];

    /**
     * Blocked requests log
     */
    this.blockedRequests = [];

    /**
     * Token estimation patterns
     */
    this.tokenEstimationRules = {
      // Rough estimation: 1 token ≈ 4 characters
      charsPerToken: 4,
      // Common API endpoints and their typical token usage
      endpoints: {
        'chat/completions': { input: 1, output: 1 },
        'completions': { input: 1, output: 1 },
        'embeddings': { input: 1, output: 0 },
      }
    };
  }

  /**
   * Initialize monitor
   */
  async initialize() {
    if (!this.config.enabled) return;

    try {
      // Load saved usage data
      await this.loadUsageData();

      // Set up periodic cleanup
      this.startCleanupTimer();

      // Monitor network requests
      this.monitorNetworkRequests();

      console.log('[Armorly TokenMonitor] Initialized - Token tracking active');
    } catch (error) {
      console.error('[Armorly TokenMonitor] Initialization error:', error);
    }
  }

  /**
   * Monitor network requests for API calls
   */
  monitorNetworkRequests() {
    // Monitor requests to AI APIs
    chrome.webRequest.onBeforeRequest.addListener(
      (details) => this.handleRequest(details),
      { 
        urls: [
          '*://api.openai.com/*',
          '*://api.anthropic.com/*',
          '*://api.cohere.ai/*',
          '*://generativelanguage.googleapis.com/*',
          '*://*.perplexity.ai/*',
        ]
      },
      ['requestBody']
    );

    // Monitor responses to track actual token usage
    chrome.webRequest.onCompleted.addListener(
      (details) => this.handleResponse(details),
      {
        urls: [
          '*://api.openai.com/*',
          '*://api.anthropic.com/*',
          '*://api.cohere.ai/*',
          '*://generativelanguage.googleapis.com/*',
          '*://*.perplexity.ai/*',
        ]
      },
      ['responseHeaders']
    );
  }

  /**
   * Handle API request
   */
  handleRequest(details) {
    if (!this.config.enabled) return;

    const url = new URL(details.url);
    const domain = url.hostname;

    // Estimate token usage from request
    const estimatedTokens = this.estimateRequestTokens(details);

    // Check rate limits
    if (this.isRateLimitExceeded(domain, estimatedTokens)) {
      this.blockRequest(details, 'rate-limit-exceeded', estimatedTokens);
      return { cancel: true };
    }

    // Check if single request is too large
    if (estimatedTokens > this.config.maxTokensPerRequest) {
      this.blockRequest(details, 'request-too-large', estimatedTokens);
      return { cancel: true };
    }

    // Track the request
    this.trackRequest(domain, estimatedTokens, details);

    // Check for suspicious patterns
    if (this.detectSuspiciousPattern(domain)) {
      this.stats.suspiciousPatterns++;
      
      if (this.config.logActions) {
        console.warn('[Armorly TokenMonitor] Suspicious usage pattern detected:', domain);
      }
    }
  }

  /**
   * Handle API response
   */
  handleResponse(details) {
    if (!this.config.enabled) return;

    // Try to extract actual token usage from response headers
    const actualTokens = this.extractTokenUsage(details.responseHeaders);

    if (actualTokens) {
      const url = new URL(details.url);
      const domain = url.hostname;

      // Update tracking with actual usage
      this.updateActualUsage(domain, actualTokens);
    }
  }

  /**
   * Estimate token usage from request
   */
  estimateRequestTokens(details) {
    let tokens = 0;

    try {
      // Parse request body
      if (details.requestBody) {
        let bodyText = '';

        if (details.requestBody.raw) {
          const decoder = new TextDecoder('utf-8');
          details.requestBody.raw.forEach(part => {
            if (part.bytes) {
              bodyText += decoder.decode(part.bytes);
            }
          });
        } else if (details.requestBody.formData) {
          bodyText = JSON.stringify(details.requestBody.formData);
        }

        // Parse JSON to extract prompt/messages
        try {
          const body = JSON.parse(bodyText);
          
          // Extract text content
          let textContent = '';
          
          if (body.prompt) {
            textContent = body.prompt;
          } else if (body.messages) {
            textContent = body.messages.map(m => m.content || '').join(' ');
          } else if (body.input) {
            textContent = body.input;
          }

          // Estimate tokens (rough: 1 token ≈ 4 characters)
          tokens = Math.ceil(textContent.length / this.tokenEstimationRules.charsPerToken);

          // Add estimated output tokens (usually max_tokens parameter)
          if (body.max_tokens) {
            tokens += body.max_tokens;
          } else {
            // Default estimate for output
            tokens += 500;
          }
        } catch (e) {
          // Fallback: estimate from body length
          tokens = Math.ceil(bodyText.length / this.tokenEstimationRules.charsPerToken);
        }
      }
    } catch (error) {
      console.error('[Armorly TokenMonitor] Error estimating tokens:', error);
      // Conservative estimate
      tokens = 1000;
    }

    return tokens;
  }

  /**
   * Extract actual token usage from response headers
   */
  extractTokenUsage(headers) {
    if (!headers) return null;

    // OpenAI includes usage in response body, not headers
    // We'll need to intercept response body for accurate tracking
    // For now, return null and rely on estimates

    // Check for rate limit headers
    for (const header of headers) {
      if (header.name.toLowerCase() === 'x-ratelimit-remaining-tokens') {
        // Could use this to track remaining quota
      }
    }

    return null;
  }

  /**
   * Check if rate limit is exceeded
   */
  isRateLimitExceeded(domain, estimatedTokens) {
    const now = Date.now();
    const oneMinuteAgo = now - 60000;
    const oneHourAgo = now - 3600000;

    // Get domain usage
    const usage = this.domainUsage.get(domain) || {
      requests: [],
      totalTokens: 0,
    };

    // Count recent requests
    const recentRequests = usage.requests.filter(r => r.timestamp > oneMinuteAgo);
    const recentTokens = recentRequests.reduce((sum, r) => sum + r.tokens, 0);

    // Count hourly tokens
    const hourlyRequests = usage.requests.filter(r => r.timestamp > oneHourAgo);
    const hourlyTokens = hourlyRequests.reduce((sum, r) => sum + r.tokens, 0);

    // Check limits
    if (recentRequests.length >= this.config.maxRequestsPerMinute) {
      return true;
    }

    if (recentTokens + estimatedTokens > this.config.maxTokensPerMinute) {
      return true;
    }

    if (hourlyTokens + estimatedTokens > this.config.maxTokensPerHour) {
      return true;
    }

    // Check alert threshold
    const minuteUsagePercent = (recentTokens + estimatedTokens) / this.config.maxTokensPerMinute;
    if (minuteUsagePercent > this.config.alertThreshold) {
      this.sendAlert('token-limit-warning', domain, minuteUsagePercent);
    }

    return false;
  }

  /**
   * Track a request
   */
  trackRequest(domain, tokens, details) {
    this.stats.totalRequests++;
    this.stats.totalTokens += tokens;

    // Get or create domain usage
    let usage = this.domainUsage.get(domain);
    if (!usage) {
      usage = { requests: [], totalTokens: 0 };
      this.domainUsage.set(domain, usage);
    }

    // Add request
    usage.requests.push({
      timestamp: Date.now(),
      tokens: tokens,
      url: details.url,
      method: details.method,
    });

    usage.totalTokens += tokens;

    // Add to history
    this.requestHistory.push({
      domain,
      tokens,
      timestamp: Date.now(),
    });
  }

  /**
   * Update with actual token usage
   */
  updateActualUsage(domain, actualTokens) {
    const usage = this.domainUsage.get(domain);
    if (usage && usage.requests.length > 0) {
      // Update the most recent request
      const lastRequest = usage.requests[usage.requests.length - 1];
      const diff = actualTokens - lastRequest.tokens;
      
      lastRequest.tokens = actualTokens;
      usage.totalTokens += diff;
      this.stats.totalTokens += diff;
    }
  }

  /**
   * Detect suspicious patterns
   */
  detectSuspiciousPattern(domain) {
    const usage = this.domainUsage.get(domain);
    if (!usage) return false;

    const now = Date.now();
    const recentRequests = usage.requests.filter(r => r.timestamp > now - 60000);

    // Pattern 1: Rapid fire requests (>30 per minute)
    if (recentRequests.length > 30) {
      return true;
    }

    // Pattern 2: Consistent large requests
    const avgTokens = recentRequests.reduce((sum, r) => sum + r.tokens, 0) / recentRequests.length;
    if (avgTokens > 3000 && recentRequests.length > 5) {
      return true;
    }

    return false;
  }

  /**
   * Block a request
   */
  blockRequest(details, reason, tokens) {
    this.stats.blockedRequests++;
    
    if (reason === 'rate-limit-exceeded') {
      this.stats.rateLimitHits++;
    }

    this.blockedRequests.push({
      url: details.url,
      reason,
      tokens,
      timestamp: Date.now(),
    });

    if (this.config.logActions) {
      console.warn(`[Armorly TokenMonitor] Blocked request (${reason}):`, details.url, `${tokens} tokens`);
    }

    // Send alert
    this.sendAlert('request-blocked', details.url, { reason, tokens });
  }

  /**
   * Send alert
   */
  sendAlert(type, data, extra) {
    // Send message to popup/background
    chrome.runtime.sendMessage({
      type: 'TOKEN_ALERT',
      alertType: type,
      data,
      extra,
      timestamp: Date.now(),
    }).catch(() => {});
  }

  /**
   * Start cleanup timer
   */
  startCleanupTimer() {
    // Clean up old data every 5 minutes
    setInterval(() => {
      this.cleanup();
    }, 300000);
  }

  /**
   * Cleanup old data
   */
  cleanup() {
    const now = Date.now();
    const oneHourAgo = now - 3600000;

    // Clean up domain usage
    for (const [domain, usage] of this.domainUsage.entries()) {
      usage.requests = usage.requests.filter(r => r.timestamp > oneHourAgo);
      
      if (usage.requests.length === 0) {
        this.domainUsage.delete(domain);
      }
    }

    // Clean up request history
    this.requestHistory = this.requestHistory.filter(r => r.timestamp > oneHourAgo);

    // Clean up blocked requests (keep last 100)
    if (this.blockedRequests.length > 100) {
      this.blockedRequests = this.blockedRequests.slice(-100);
    }
  }

  /**
   * Load usage data from storage
   */
  async loadUsageData() {
    try {
      const data = await chrome.storage.local.get(['tokenUsage']);
      if (data.tokenUsage) {
        this.stats = data.tokenUsage.stats || this.stats;
      }
    } catch (error) {
      console.error('[Armorly TokenMonitor] Error loading data:', error);
    }
  }

  /**
   * Save usage data to storage
   */
  async saveUsageData() {
    try {
      await chrome.storage.local.set({
        tokenUsage: {
          stats: this.stats,
          timestamp: Date.now(),
        }
      });
    } catch (error) {
      console.error('[Armorly TokenMonitor] Error saving data:', error);
    }
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      ...this.stats,
      domainCount: this.domainUsage.size,
      recentRequests: this.requestHistory.length,
    };
  }

  /**
   * Get domain usage
   */
  getDomainUsage() {
    const usage = {};
    for (const [domain, data] of this.domainUsage.entries()) {
      usage[domain] = {
        totalTokens: data.totalTokens,
        requestCount: data.requests.length,
      };
    }
    return usage;
  }
}

