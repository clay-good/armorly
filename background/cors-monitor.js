/**
 * Armorly - CORS (Cross-Origin Resource Sharing) Monitor
 * 
 * Monitors CORS policy violations, detects cross-origin attacks,
 * prevents unauthorized data access, and provides CORS security
 * across all chromium-based agentic browsers.
 * 
 * Features:
 * - Real-time CORS violation detection
 * - Cross-origin request monitoring
 * - Wildcard origin detection
 * - Credential leakage prevention
 * - CORS misconfiguration detection
 */

export class CORSMonitor {
  constructor() {
    // CORS tracking
    this.corsViolations = [];
    this.suspiciousOrigins = new Map(); // origin -> count
    
    // Dangerous CORS patterns
    this.dangerousPatterns = {
      wildcardOrigin: /\*/,
      nullOrigin: /null/,
      fileOrigin: /file:\/\//,
      dataOrigin: /data:/,
    };
    
    // Sensitive headers
    this.sensitiveHeaders = [
      'authorization',
      'cookie',
      'x-api-key',
      'x-auth-token',
      'x-csrf-token',
      'x-session-id',
    ];
    
    // Statistics
    this.statistics = {
      totalChecks: 0,
      violationsDetected: 0,
      wildcardOrigins: 0,
      credentialLeaks: 0,
      misconfigurations: 0,
      blockedRequests: 0,
    };
    
    // Threat callback
    this.threatCallback = null;
    
    // Settings
    this.settings = {
      monitorCORS: true,
      blockViolations: true,
      checkCredentials: true,
      checkWildcards: true,
      strictMode: false,
    };
    
    // Whitelist of trusted origins
    this.trustedOrigins = new Set([
      'https://chatgpt.com',
      'https://www.perplexity.ai',
      'https://claude.ai',
    ]);
  }
  
  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }
  
  /**
   * Check CORS request
   */
  checkRequest(request) {
    if (!this.settings.monitorCORS) return { allowed: true };
    
    this.statistics.totalChecks++;
    
    const { url, origin, method, headers, tabId } = request;
    const targetOrigin = this.extractOrigin(url);
    
    // Skip same-origin requests
    if (origin === targetOrigin) {
      return { allowed: true };
    }
    
    // Check if origin is trusted
    if (this.trustedOrigins.has(origin)) {
      return { allowed: true };
    }
    
    // Analyze CORS request
    const analysis = this.analyzeRequest({
      url,
      origin,
      targetOrigin,
      method,
      headers,
      tabId,
    });
    
    // Record violation
    if (analysis.threats.length > 0) {
      this.recordViolation({
        url,
        origin,
        targetOrigin,
        method,
        timestamp: Date.now(),
        analysis,
      });
    }
    
    // Check for threats
    if (analysis.threats.length > 0) {
      console.warn('[CORSMonitor] Threats detected:', analysis.threats);
      
      if (this.threatCallback) {
        analysis.threats.forEach(threat => this.threatCallback(threat));
      }
      
      if (analysis.severity === 'CRITICAL' && this.settings.blockViolations) {
        this.statistics.blockedRequests++;
        return {
          allowed: false,
          reason: 'CORS violation blocked',
          threats: analysis.threats,
        };
      }
    }
    
    return { allowed: true };
  }
  
  /**
   * Analyze CORS request
   */
  analyzeRequest(request) {
    const threats = [];
    let maxSeverity = 'LOW';
    
    const { origin, targetOrigin, headers } = request;
    
    // Check for wildcard origin
    if (this.settings.checkWildcards && this.dangerousPatterns.wildcardOrigin.test(origin)) {
      threats.push({
        type: 'WILDCARD_ORIGIN',
        severity: 'HIGH',
        score: 85,
        description: 'Wildcard origin detected in CORS request',
        context: { origin, targetOrigin },
      });
      
      this.statistics.violationsDetected++;
      this.statistics.wildcardOrigins++;
      maxSeverity = 'HIGH';
    }
    
    // Check for null origin
    if (this.dangerousPatterns.nullOrigin.test(origin)) {
      threats.push({
        type: 'NULL_ORIGIN',
        severity: 'HIGH',
        score: 80,
        description: 'Null origin detected in CORS request',
        context: { origin, targetOrigin },
      });
      
      this.statistics.violationsDetected++;
      maxSeverity = 'HIGH';
    }
    
    // Check for file:// or data: origin
    if (this.dangerousPatterns.fileOrigin.test(origin) || this.dangerousPatterns.dataOrigin.test(origin)) {
      threats.push({
        type: 'DANGEROUS_ORIGIN_SCHEME',
        severity: 'HIGH',
        score: 85,
        description: 'Dangerous origin scheme detected (file:// or data:)',
        context: { origin, targetOrigin },
      });
      
      this.statistics.violationsDetected++;
      maxSeverity = 'HIGH';
    }
    
    // Check for credentials with wildcard
    if (this.settings.checkCredentials && headers) {
      const hasCredentials = this.checkCredentials(headers);
      
      if (hasCredentials && this.dangerousPatterns.wildcardOrigin.test(origin)) {
        threats.push({
          type: 'CREDENTIAL_LEAK',
          severity: 'CRITICAL',
          score: 95,
          description: 'Credentials sent with wildcard CORS origin',
          context: { origin, targetOrigin },
        });
        
        this.statistics.violationsDetected++;
        this.statistics.credentialLeaks++;
        maxSeverity = 'CRITICAL';
      }
    }
    
    // Check for CORS misconfiguration
    if (this.checkMisconfiguration(origin, targetOrigin)) {
      threats.push({
        type: 'CORS_MISCONFIGURATION',
        severity: 'MEDIUM',
        score: 60,
        description: 'Potential CORS misconfiguration detected',
        context: { origin, targetOrigin },
      });
      
      this.statistics.misconfigurations++;
    }
    
    // Track suspicious origins
    if (threats.length > 0) {
      const count = this.suspiciousOrigins.get(origin) || 0;
      this.suspiciousOrigins.set(origin, count + 1);
    }
    
    return {
      threats,
      severity: maxSeverity,
      hasSuspiciousActivity: threats.length > 0,
    };
  }
  
  /**
   * Check for credentials in headers
   */
  checkCredentials(headers) {
    for (const sensitiveHeader of this.sensitiveHeaders) {
      if (headers[sensitiveHeader] || headers[sensitiveHeader.toLowerCase()]) {
        return true;
      }
    }
    return false;
  }
  
  /**
   * Check for CORS misconfiguration
   */
  checkMisconfiguration(origin, targetOrigin) {
    // Check if origins are from different security contexts
    try {
      const originUrl = new URL(origin);
      const targetUrl = new URL(targetOrigin);
      
      // HTTP to HTTPS or vice versa
      if (originUrl.protocol !== targetUrl.protocol) {
        return true;
      }
      
      // Different ports (potential misconfiguration)
      if (originUrl.port !== targetUrl.port && (originUrl.port || targetUrl.port)) {
        return true;
      }
    } catch {
      return false;
    }
    
    return false;
  }
  
  /**
   * Record CORS violation
   */
  recordViolation(entry) {
    this.corsViolations.push(entry);
    
    // Limit violation history
    if (this.corsViolations.length > 1000) {
      this.corsViolations.shift();
    }
  }
  
  /**
   * Extract origin from URL
   */
  extractOrigin(url) {
    try {
      const urlObj = new URL(url);
      return `${urlObj.protocol}//${urlObj.hostname}${urlObj.port ? ':' + urlObj.port : ''}`;
    } catch {
      return url;
    }
  }
  
  /**
   * Add trusted origin
   */
  addTrustedOrigin(origin) {
    this.trustedOrigins.add(origin);
  }
  
  /**
   * Remove trusted origin
   */
  removeTrustedOrigin(origin) {
    this.trustedOrigins.delete(origin);
  }
  
  /**
   * Get statistics
   */
  getStatistics() {
    return this.statistics;
  }
  
  /**
   * Get CORS violations
   */
  getCORSViolations() {
    return this.corsViolations;
  }
  
  /**
   * Get suspicious origins
   */
  getSuspiciousOrigins() {
    return Array.from(this.suspiciousOrigins.entries()).map(([origin, count]) => ({
      origin,
      count,
    }));
  }
  
  /**
   * Update settings
   */
  updateSettings(newSettings) {
    this.settings = { ...this.settings, ...newSettings };
  }
}

