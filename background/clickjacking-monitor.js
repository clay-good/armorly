/**
 * Armorly - Clickjacking Monitor
 * 
 * Monitors clickjacking attacks, detects UI redressing,
 * prevents frame-based attacks, and provides clickjacking security
 * across all chromium-based agentic browsers.
 * 
 * Features:
 * - Real-time clickjacking detection
 * - Frame busting detection
 * - X-Frame-Options monitoring
 * - Transparent overlay detection
 * - UI redressing prevention
 */

export class ClickjackingMonitor {
  constructor() {
    // Clickjacking tracking
    this.clickjackingAttempts = [];
    this.suspiciousFrames = new Map(); // frameUrl -> data
    
    // Statistics
    this.statistics = {
      totalChecks: 0,
      attacksDetected: 0,
      framingAttempts: 0,
      overlayDetections: 0,
      bustingAttempts: 0,
      blockedFrames: 0,
    };
    
    // Threat callback
    this.threatCallback = null;
    
    // Settings
    this.settings = {
      monitorClickjacking: true,
      blockFraming: true,
      checkOverlays: true,
      checkFrameBusting: true,
      strictMode: false,
    };
    
    // Sensitive domains (should never be framed)
    this.sensitiveDomains = new Set([
      'accounts.google.com',
      'login.microsoftonline.com',
      'github.com',
      'paypal.com',
      'amazon.com',
      'facebook.com',
      'twitter.com',
    ]);
  }
  
  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }
  
  /**
   * Check frame request
   */
  checkFrame(request) {
    if (!this.settings.monitorClickjacking) return { allowed: true };
    
    this.statistics.totalChecks++;
    
    const { url, parentUrl, frameType, tabId } = request;
    const domain = this.extractDomain(url);
    const parentDomain = this.extractDomain(parentUrl);
    
    // Skip same-origin frames
    if (domain === parentDomain) {
      return { allowed: true };
    }
    
    // Analyze frame request
    const analysis = this.analyzeFrame({
      url,
      domain,
      parentUrl,
      parentDomain,
      frameType,
      tabId,
    });
    
    // Record attempt
    if (analysis.threats.length > 0) {
      this.recordAttempt({
        url,
        domain,
        parentUrl,
        parentDomain,
        frameType,
        timestamp: Date.now(),
        analysis,
      });
    }
    
    // Check for threats
    if (analysis.threats.length > 0) {
      console.warn('[ClickjackingMonitor] Threats detected:', analysis.threats);
      
      if (this.threatCallback) {
        analysis.threats.forEach(threat => this.threatCallback(threat));
      }
      
      if (analysis.severity === 'CRITICAL' && this.settings.blockFraming) {
        this.statistics.blockedFrames++;
        return {
          allowed: false,
          reason: 'Clickjacking attempt blocked',
          threats: analysis.threats,
        };
      }
    }
    
    return { allowed: true };
  }
  
  /**
   * Analyze frame request
   */
  analyzeFrame(request) {
    const threats = [];
    let maxSeverity = 'LOW';
    
    const { domain, parentDomain, url, parentUrl } = request;
    
    // Check if sensitive domain is being framed
    if (this.sensitiveDomains.has(domain)) {
      threats.push({
        type: 'SENSITIVE_DOMAIN_FRAMING',
        severity: 'CRITICAL',
        score: 95,
        description: `Sensitive domain ${domain} is being framed`,
        context: { domain, parentDomain, url, parentUrl },
      });
      
      this.statistics.attacksDetected++;
      this.statistics.framingAttempts++;
      maxSeverity = 'CRITICAL';
    }
    
    // Check for cross-origin framing
    if (domain !== parentDomain) {
      threats.push({
        type: 'CROSS_ORIGIN_FRAMING',
        severity: 'HIGH',
        score: 75,
        description: `Cross-origin framing detected: ${domain} framed by ${parentDomain}`,
        context: { domain, parentDomain, url, parentUrl },
      });
      
      this.statistics.framingAttempts++;
      
      if (maxSeverity !== 'CRITICAL') {
        maxSeverity = 'HIGH';
      }
    }
    
    // Track suspicious frames
    if (threats.length > 0) {
      this.suspiciousFrames.set(url, {
        domain,
        parentDomain,
        timestamp: Date.now(),
        threatCount: threats.length,
      });
    }
    
    return {
      threats,
      severity: maxSeverity,
      hasSuspiciousActivity: threats.length > 0,
    };
  }
  
  /**
   * Check X-Frame-Options header
   */
  checkXFrameOptions(headers, url) {
    const xFrameOptions = headers['x-frame-options'] || headers['X-Frame-Options'];
    
    if (!xFrameOptions) {
      // Missing X-Frame-Options header
      if (this.threatCallback) {
        this.threatCallback({
          type: 'MISSING_X_FRAME_OPTIONS',
          severity: 'MEDIUM',
          score: 60,
          description: `Missing X-Frame-Options header for ${url}`,
          context: { url },
        });
      }
      return { protected: false };
    }
    
    // Check for weak X-Frame-Options
    const value = xFrameOptions.toLowerCase();
    if (value === 'allow-from') {
      if (this.threatCallback) {
        this.threatCallback({
          type: 'WEAK_X_FRAME_OPTIONS',
          severity: 'MEDIUM',
          score: 55,
          description: `Weak X-Frame-Options header (ALLOW-FROM is deprecated)`,
          context: { url, value: xFrameOptions },
        });
      }
      return { protected: false };
    }
    
    return { protected: true };
  }
  
  /**
   * Check for transparent overlay
   */
  checkOverlay(element) {
    if (!this.settings.checkOverlays) return { suspicious: false };
    
    const { opacity, zIndex, position, pointerEvents } = element;
    
    // Check for suspicious overlay characteristics
    const isSuspicious =
      (opacity < 0.1 || opacity === 0) &&
      zIndex > 1000 &&
      position === 'absolute' &&
      pointerEvents !== 'none';
    
    if (isSuspicious) {
      this.statistics.attacksDetected++;
      this.statistics.overlayDetections++;
      
      if (this.threatCallback) {
        this.threatCallback({
          type: 'TRANSPARENT_OVERLAY_DETECTED',
          severity: 'HIGH',
          score: 85,
          description: 'Transparent overlay detected (potential clickjacking)',
          context: { opacity, zIndex, position, pointerEvents },
        });
      }
      
      return { suspicious: true };
    }
    
    return { suspicious: false };
  }
  
  /**
   * Check for frame busting
   */
  checkFrameBusting(script) {
    if (!this.settings.checkFrameBusting) return { detected: false };
    
    // Frame busting patterns
    const bustingPatterns = [
      /top\.location/gi,
      /parent\.location/gi,
      /window\.top/gi,
      /self\s*!==\s*top/gi,
      /top\s*!==\s*self/gi,
      /frameElement/gi,
    ];
    
    for (const pattern of bustingPatterns) {
      if (pattern.test(script)) {
        this.statistics.bustingAttempts++;
        
        if (this.threatCallback) {
          this.threatCallback({
            type: 'FRAME_BUSTING_DETECTED',
            severity: 'MEDIUM',
            score: 50,
            description: 'Frame busting code detected',
            context: { pattern: pattern.source },
          });
        }
        
        return { detected: true };
      }
    }
    
    return { detected: false };
  }
  
  /**
   * Record clickjacking attempt
   */
  recordAttempt(entry) {
    this.clickjackingAttempts.push(entry);
    
    // Limit attempt history
    if (this.clickjackingAttempts.length > 1000) {
      this.clickjackingAttempts.shift();
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
   * Add sensitive domain
   */
  addSensitiveDomain(domain) {
    this.sensitiveDomains.add(domain);
  }
  
  /**
   * Remove sensitive domain
   */
  removeSensitiveDomain(domain) {
    this.sensitiveDomains.delete(domain);
  }
  
  /**
   * Get statistics
   */
  getStatistics() {
    return this.statistics;
  }
  
  /**
   * Get clickjacking attempts
   */
  getClickjackingAttempts() {
    return this.clickjackingAttempts;
  }
  
  /**
   * Get suspicious frames
   */
  getSuspiciousFrames() {
    return Array.from(this.suspiciousFrames.entries()).map(([url, data]) => ({
      url,
      ...data,
    }));
  }
  
  /**
   * Update settings
   */
  updateSettings(newSettings) {
    this.settings = { ...this.settings, ...newSettings };
  }
}

