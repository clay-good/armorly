/**
 * Armorly - CSP (Content Security Policy) Monitor
 * 
 * Monitors CSP violations, detects policy bypasses,
 * prevents unsafe inline scripts, and provides CSP security
 * across all chromium-based agentic browsers.
 * 
 * Features:
 * - Real-time CSP violation detection
 * - Unsafe inline script detection
 * - Unsafe eval detection
 * - CSP bypass detection
 * - Policy weakness analysis
 */

export class CSPMonitor {
  constructor() {
    // CSP tracking
    this.cspViolations = [];
    this.policyWeaknesses = new Map(); // domain -> weaknesses[]
    
    // Unsafe CSP directives
    this.unsafeDirectives = [
      'unsafe-inline',
      'unsafe-eval',
      'unsafe-hashes',
    ];
    
    // Critical CSP directives
    this.criticalDirectives = [
      'default-src',
      'script-src',
      'object-src',
      'base-uri',
      'frame-ancestors',
    ];
    
    // Statistics
    this.statistics = {
      totalChecks: 0,
      violationsDetected: 0,
      unsafeInline: 0,
      unsafeEval: 0,
      bypassAttempts: 0,
      weakPolicies: 0,
      blockedScripts: 0,
    };
    
    // Threat callback
    this.threatCallback = null;
    
    // Settings
    this.settings = {
      monitorCSP: true,
      blockViolations: true,
      checkInlineScripts: true,
      checkEval: true,
      strictMode: false,
    };
  }
  
  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }
  
  /**
   * Check CSP violation
   */
  checkViolation(violation) {
    if (!this.settings.monitorCSP) return { allowed: true };
    
    this.statistics.totalChecks++;
    
    const {
      documentURL,
      violatedDirective,
      effectiveDirective,
      blockedURL,
      sourceFile,
      lineNumber,
      columnNumber,
    } = violation;
    
    const domain = this.extractDomain(documentURL);
    
    // Analyze violation
    const analysis = this.analyzeViolation({
      domain,
      documentURL,
      violatedDirective,
      effectiveDirective,
      blockedURL,
      sourceFile,
      lineNumber,
      columnNumber,
    });
    
    // Record violation
    if (analysis.threats.length > 0) {
      this.recordViolation({
        domain,
        documentURL,
        violatedDirective,
        effectiveDirective,
        blockedURL,
        timestamp: Date.now(),
        analysis,
      });
    }
    
    // Check for threats
    if (analysis.threats.length > 0) {
      console.warn('[CSPMonitor] Threats detected:', analysis.threats);
      
      if (this.threatCallback) {
        analysis.threats.forEach(threat => this.threatCallback(threat));
      }
      
      if (analysis.severity === 'CRITICAL' && this.settings.blockViolations) {
        this.statistics.blockedScripts++;
        return {
          allowed: false,
          reason: 'CSP violation blocked',
          threats: analysis.threats,
        };
      }
    }
    
    return { allowed: true };
  }
  
  /**
   * Analyze CSP violation
   */
  analyzeViolation(violation) {
    const threats = [];
    let maxSeverity = 'LOW';
    
    const { violatedDirective, effectiveDirective, blockedURL, domain } = violation;
    
    // Check for unsafe-inline violation
    if (this.settings.checkInlineScripts && violatedDirective.includes('script-src')) {
      if (blockedURL === 'inline' || blockedURL.startsWith('data:')) {
        threats.push({
          type: 'UNSAFE_INLINE_SCRIPT',
          severity: 'HIGH',
          score: 85,
          description: 'Unsafe inline script detected',
          context: { domain, violatedDirective, blockedURL },
        });
        
        this.statistics.violationsDetected++;
        this.statistics.unsafeInline++;
        maxSeverity = 'HIGH';
      }
    }
    
    // Check for unsafe-eval violation
    if (this.settings.checkEval && violatedDirective.includes('script-src')) {
      if (blockedURL === 'eval' || effectiveDirective.includes('eval')) {
        threats.push({
          type: 'UNSAFE_EVAL',
          severity: 'HIGH',
          score: 80,
          description: 'Unsafe eval detected',
          context: { domain, violatedDirective, blockedURL },
        });
        
        this.statistics.violationsDetected++;
        this.statistics.unsafeEval++;
        maxSeverity = 'HIGH';
      }
    }
    
    // Check for CSP bypass attempt
    if (this.checkBypassAttempt(blockedURL)) {
      threats.push({
        type: 'CSP_BYPASS_ATTEMPT',
        severity: 'CRITICAL',
        score: 95,
        description: 'CSP bypass attempt detected',
        context: { domain, violatedDirective, blockedURL },
      });
      
      this.statistics.violationsDetected++;
      this.statistics.bypassAttempts++;
      maxSeverity = 'CRITICAL';
    }
    
    // Check for base-uri violation (dangerous)
    if (violatedDirective.includes('base-uri')) {
      threats.push({
        type: 'BASE_URI_VIOLATION',
        severity: 'HIGH',
        score: 85,
        description: 'Base URI violation detected (potential XSS)',
        context: { domain, violatedDirective, blockedURL },
      });
      
      this.statistics.violationsDetected++;
      maxSeverity = 'HIGH';
    }
    
    return {
      threats,
      severity: maxSeverity,
      hasSuspiciousActivity: threats.length > 0,
    };
  }
  
  /**
   * Check for CSP bypass attempt
   */
  checkBypassAttempt(blockedURL) {
    // Common CSP bypass patterns
    const bypassPatterns = [
      /jsonp/gi,
      /callback=/gi,
      /angular/gi,
      /jquery/gi,
      /\.googleapis\.com/gi,
      /cdnjs\.cloudflare\.com/gi,
    ];
    
    for (const pattern of bypassPatterns) {
      if (pattern.test(blockedURL)) {
        return true;
      }
    }
    
    return false;
  }
  
  /**
   * Analyze CSP policy
   */
  analyzePolicy(policy, domain) {
    const weaknesses = [];
    
    // Check for missing critical directives
    for (const directive of this.criticalDirectives) {
      if (!policy.includes(directive)) {
        weaknesses.push({
          type: 'MISSING_DIRECTIVE',
          directive,
          severity: 'MEDIUM',
          description: `Missing critical CSP directive: ${directive}`,
        });
      }
    }
    
    // Check for unsafe directives
    for (const unsafeDirective of this.unsafeDirectives) {
      if (policy.includes(unsafeDirective)) {
        weaknesses.push({
          type: 'UNSAFE_DIRECTIVE',
          directive: unsafeDirective,
          severity: 'HIGH',
          description: `Unsafe CSP directive detected: ${unsafeDirective}`,
        });
      }
    }
    
    // Check for wildcard sources
    if (policy.includes('*')) {
      weaknesses.push({
        type: 'WILDCARD_SOURCE',
        severity: 'HIGH',
        description: 'Wildcard source detected in CSP policy',
      });
    }
    
    // Store weaknesses
    if (weaknesses.length > 0) {
      this.policyWeaknesses.set(domain, weaknesses);
      this.statistics.weakPolicies++;
      
      if (this.threatCallback) {
        this.threatCallback({
          type: 'WEAK_CSP_POLICY',
          severity: 'MEDIUM',
          score: 60,
          description: `Weak CSP policy detected for ${domain}`,
          context: { domain, weaknesses },
        });
      }
    }
    
    return weaknesses;
  }
  
  /**
   * Record CSP violation
   */
  recordViolation(entry) {
    this.cspViolations.push(entry);
    
    // Limit violation history
    if (this.cspViolations.length > 1000) {
      this.cspViolations.shift();
    }
  }
  
  /**
   * Extract domain from URL
   */
  extractDomain(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname;
    } catch {
      return url;
    }
  }
  
  /**
   * Get statistics
   */
  getStatistics() {
    return this.statistics;
  }
  
  /**
   * Get CSP violations
   */
  getCSPViolations() {
    return this.cspViolations;
  }
  
  /**
   * Get policy weaknesses
   */
  getPolicyWeaknesses() {
    return Array.from(this.policyWeaknesses.entries()).map(([domain, weaknesses]) => ({
      domain,
      weaknesses,
    }));
  }
  
  /**
   * Update settings
   */
  updateSettings(newSettings) {
    this.settings = { ...this.settings, ...newSettings };
  }
}

