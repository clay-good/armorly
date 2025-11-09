/**
 * Armorly - API Security Monitor
 * 
 * Monitors API calls, detects API abuse, prevents unauthorized API access,
 * tracks API rate limits, and provides API security across all chromium-based
 * agentic browsers.
 * 
 * Features:
 * - API call monitoring
 * - API key leakage detection
 * - Rate limit enforcement
 * - Unauthorized API access detection
 * - API response validation
 */

export class APISecurityMonitor {
  constructor() {
    // API tracking
    this.apiCalls = new Map(); // endpoint -> calls
    this.suspiciousApiCalls = [];
    this.apiKeys = new Set();
    
    // Known AI API endpoints
    this.aiApiEndpoints = [
      'api.openai.com',
      'api.anthropic.com',
      'api.cohere.ai',
      'generativelanguage.googleapis.com',
      'api.perplexity.ai',
      'api.together.xyz',
      'api.replicate.com',
    ];
    
    // Sensitive API patterns
    this.sensitiveApiPatterns = [
      /\/auth\//gi,
      /\/login/gi,
      /\/password/gi,
      /\/token/gi,
      /\/api\/key/gi,
      /\/credentials/gi,
      /\/payment/gi,
      /\/billing/gi,
    ];
    
    // API key patterns
    this.apiKeyPatterns = [
      /sk-[A-Za-z0-9]{48}/g, // OpenAI
      /sk-ant-[A-Za-z0-9-]{95}/g, // Anthropic
      /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi, // Bearer tokens
      /api[_-]?key["\s:=]+[A-Za-z0-9]{20,}/gi, // Generic API keys
    ];
    
    // Rate limits (requests per minute)
    this.rateLimits = {
      default: 60,
      ai: 20,
      auth: 10,
      payment: 5,
    };
    
    // Statistics
    this.statistics = {
      totalApiCalls: 0,
      suspiciousApiCalls: 0,
      apiKeyLeaks: 0,
      rateLimitViolations: 0,
      unauthorizedAccess: 0,
    };
    
    // Threat callback
    this.threatCallback = null;
    
    // Settings
    this.settings = {
      monitorApiCalls: true,
      enforceRateLimits: true,
      detectApiKeyLeaks: true,
      blockSuspiciousApis: true,
    };
  }
  
  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }
  
  /**
   * Monitor API call
   */
  async monitorApiCall(request) {
    if (!this.settings.monitorApiCalls) return { allowed: true };
    
    this.statistics.totalApiCalls++;
    
    const { url, method, headers, body } = request;
    const endpoint = this.extractEndpoint(url);
    
    // Analyze API call
    const analysis = this.analyzeApiCall(request);
    
    // Record API call
    this.recordApiCall({
      endpoint,
      url,
      method,
      timestamp: Date.now(),
      analysis,
    });
    
    // Check for threats
    if (analysis.threats.length > 0) {
      console.warn('[APISecurityMonitor] Threats detected in API call:', analysis.threats);
      
      // Report threats
      if (this.threatCallback) {
        analysis.threats.forEach(threat => this.threatCallback(threat));
      }
      
      // Block if critical
      if (analysis.severity === 'CRITICAL' && this.settings.blockSuspiciousApis) {
        return {
          allowed: false,
          reason: 'Suspicious API call blocked',
          threats: analysis.threats,
        };
      }
    }
    
    // Check rate limits
    if (this.settings.enforceRateLimits) {
      const rateLimitCheck = this.checkRateLimit(endpoint);
      if (!rateLimitCheck.allowed) {
        this.statistics.rateLimitViolations++;
        
        if (this.threatCallback) {
          this.threatCallback({
            type: 'RATE_LIMIT_VIOLATION',
            severity: 'MEDIUM',
            score: 50,
            description: `Rate limit exceeded for ${endpoint}`,
            context: { endpoint, callCount: rateLimitCheck.callCount },
          });
        }
        
        return {
          allowed: false,
          reason: 'Rate limit exceeded',
          retryAfter: 60,
        };
      }
    }
    
    return { allowed: true };
  }
  
  /**
   * Analyze API call
   */
  analyzeApiCall(request) {
    const threats = [];
    let maxSeverity = 'LOW';
    let totalScore = 0;
    
    const { url, method, headers, body } = request;
    
    // Check for API key leakage in URL
    if (this.settings.detectApiKeyLeaks) {
      for (const pattern of this.apiKeyPatterns) {
        const matches = url.match(pattern);
        if (matches) {
          threats.push({
            type: 'API_KEY_LEAK',
            severity: 'CRITICAL',
            score: 90,
            description: 'API key detected in URL',
            context: { url: url.substring(0, 100) },
          });
          
          this.statistics.apiKeyLeaks++;
          maxSeverity = 'CRITICAL';
          totalScore += 90;
          
          // Store API key (redacted)
          matches.forEach(key => this.apiKeys.add(key.substring(0, 10) + '...'));
        }
      }
    }
    
    // Check for API key leakage in headers
    if (headers) {
      const authHeader = headers['Authorization'] || headers['authorization'];
      if (authHeader) {
        for (const pattern of this.apiKeyPatterns) {
          if (pattern.test(authHeader)) {
            // This is expected for auth headers, but log it
            console.log('[APISecurityMonitor] API key in Authorization header (expected)');
          }
        }
      }
    }
    
    // Check for API key leakage in body
    if (body && this.settings.detectApiKeyLeaks) {
      const bodyStr = typeof body === 'string' ? body : JSON.stringify(body);
      
      for (const pattern of this.apiKeyPatterns) {
        const matches = bodyStr.match(pattern);
        if (matches) {
          threats.push({
            type: 'API_KEY_LEAK',
            severity: 'HIGH',
            score: 70,
            description: 'API key detected in request body',
            context: { bodyPreview: bodyStr.substring(0, 100) },
          });
          
          this.statistics.apiKeyLeaks++;
          
          if (this.compareSeverity('HIGH', maxSeverity) > 0) {
            maxSeverity = 'HIGH';
          }
          
          totalScore += 70;
        }
      }
    }
    
    // Check for sensitive API endpoints
    for (const pattern of this.sensitiveApiPatterns) {
      if (pattern.test(url)) {
        threats.push({
          type: 'SENSITIVE_API_ACCESS',
          severity: 'MEDIUM',
          score: 40,
          description: 'Access to sensitive API endpoint',
          context: { url: url.substring(0, 100), method },
        });
        
        if (this.compareSeverity('MEDIUM', maxSeverity) > 0) {
          maxSeverity = 'MEDIUM';
        }
        
        totalScore += 40;
        break;
      }
    }
    
    // Check for AI API access
    const endpoint = this.extractEndpoint(url);
    if (this.aiApiEndpoints.some(aiEndpoint => endpoint.includes(aiEndpoint))) {
      // Log AI API access (not necessarily a threat)
      console.log(`[APISecurityMonitor] AI API access detected: ${endpoint}`);
    }
    
    return {
      threats,
      severity: maxSeverity,
      totalScore,
      hasSuspiciousActivity: threats.length > 0,
    };
  }
  
  /**
   * Check rate limit
   */
  checkRateLimit(endpoint) {
    const now = Date.now();
    const oneMinuteAgo = now - 60000;
    
    // Get or create call history for endpoint
    if (!this.apiCalls.has(endpoint)) {
      this.apiCalls.set(endpoint, []);
    }
    
    const calls = this.apiCalls.get(endpoint);
    
    // Remove old calls
    const recentCalls = calls.filter(time => time > oneMinuteAgo);
    this.apiCalls.set(endpoint, recentCalls);
    
    // Determine rate limit
    let limit = this.rateLimits.default;
    
    if (this.aiApiEndpoints.some(aiEndpoint => endpoint.includes(aiEndpoint))) {
      limit = this.rateLimits.ai;
    } else if (this.sensitiveApiPatterns.some(pattern => pattern.test(endpoint))) {
      limit = this.rateLimits.auth;
    }
    
    // Check if limit exceeded
    if (recentCalls.length >= limit) {
      return {
        allowed: false,
        callCount: recentCalls.length,
        limit,
      };
    }
    
    // Add current call
    recentCalls.push(now);
    
    return {
      allowed: true,
      callCount: recentCalls.length,
      limit,
    };
  }
  
  /**
   * Extract endpoint from URL
   */
  extractEndpoint(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname + urlObj.pathname;
    } catch {
      return url;
    }
  }
  
  /**
   * Record API call
   */
  recordApiCall(entry) {
    if (entry.analysis.hasSuspiciousActivity) {
      this.suspiciousApiCalls.push(entry);
      this.statistics.suspiciousApiCalls++;
      
      // Limit history size
      if (this.suspiciousApiCalls.length > 100) {
        this.suspiciousApiCalls.shift();
      }
    }
  }
  
  /**
   * Compare severity levels
   */
  compareSeverity(severity1, severity2) {
    const levels = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    return (levels[severity1] || 0) - (levels[severity2] || 0);
  }
  
  /**
   * Get statistics
   */
  getStatistics() {
    return {
      ...this.statistics,
      trackedEndpoints: this.apiCalls.size,
      detectedApiKeys: this.apiKeys.size,
    };
  }
  
  /**
   * Get suspicious API calls
   */
  getSuspiciousApiCalls() {
    return this.suspiciousApiCalls;
  }
  
  /**
   * Update settings
   */
  updateSettings(newSettings) {
    this.settings = { ...this.settings, ...newSettings };
  }
}

