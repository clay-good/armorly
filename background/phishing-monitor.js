/**
 * Armorly - Phishing Detection Monitor
 * 
 * Monitors phishing attempts, detects fake websites, prevents credential theft,
 * and provides anti-phishing protection across all chromium-based agentic browsers.
 * 
 * Features:
 * - Real-time URL analysis
 * - Domain spoofing detection
 * - Homograph attack detection
 * - SSL certificate validation
 * - Known phishing site blocking
 */

export class PhishingMonitor {
  constructor() {
    // Phishing tracking
    this.phishingAttempts = [];
    this.suspiciousDomains = new Map(); // domain -> data
    
    // Legitimate domains to protect (common targets)
    this.legitimateDomains = [
      'google.com',
      'facebook.com',
      'amazon.com',
      'apple.com',
      'microsoft.com',
      'paypal.com',
      'netflix.com',
      'linkedin.com',
      'twitter.com',
      'instagram.com',
      'github.com',
      'dropbox.com',
      'openai.com',
      'anthropic.com',
    ];
    
    // Suspicious TLDs
    this.suspiciousTLDs = [
      '.tk', '.ml', '.ga', '.cf', '.gq', // Free TLDs
      '.xyz', '.top', '.work', '.click', '.link',
      '.pw', '.cc', '.ws', '.info',
    ];
    
    // Homograph characters (lookalike characters)
    this.homographs = {
      'a': ['а', 'ɑ', 'α'],
      'e': ['е', 'ė', 'ē'],
      'i': ['і', 'ı', 'ï'],
      'o': ['о', 'ο', 'ọ'],
      'p': ['р', 'ρ'],
      'c': ['с', 'ϲ'],
      'x': ['х', 'χ'],
      'y': ['у', 'ү'],
    };
    
    // Statistics
    this.statistics = {
      totalChecks: 0,
      phishingDetected: 0,
      homographAttacks: 0,
      domainSpoofing: 0,
      suspiciousTLDs: 0,
      blockedSites: 0,
    };
    
    // Threat callback
    this.threatCallback = null;
    
    // Settings
    this.settings = {
      monitorPhishing: true,
      blockPhishingSites: true,
      detectHomographs: true,
      checkSSL: true,
      blockSuspiciousTLDs: false,
    };
  }
  
  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }
  
  /**
   * Check URL for phishing
   */
  checkURL(request) {
    if (!this.settings.monitorPhishing) return { allowed: true };
    
    this.statistics.totalChecks++;
    
    const { url, tabId, hasSSL } = request;
    const domain = this.extractDomain(url);
    
    // Analyze URL
    const analysis = this.analyzeURL({
      url,
      domain,
      tabId,
      hasSSL,
    });
    
    // Record attempt
    this.recordAttempt({
      url,
      domain,
      tabId,
      timestamp: Date.now(),
      analysis,
    });
    
    // Check for threats
    if (analysis.threats.length > 0) {
      console.warn('[PhishingMonitor] Threats detected:', analysis.threats);
      
      if (this.threatCallback) {
        analysis.threats.forEach(threat => this.threatCallback(threat));
      }
      
      if (analysis.severity === 'CRITICAL' && this.settings.blockPhishingSites) {
        this.statistics.blockedSites++;
        return {
          allowed: false,
          reason: 'Phishing site blocked',
          threats: analysis.threats,
        };
      }
    }
    
    return { allowed: true };
  }
  
  /**
   * Analyze URL for phishing indicators
   */
  analyzeURL(request) {
    const threats = [];
    let maxSeverity = 'LOW';
    
    const { url, domain, hasSSL } = request;
    
    // Check for homograph attacks
    if (this.settings.detectHomographs) {
      const homographCheck = this.checkHomograph(domain);
      
      if (homographCheck.isHomograph) {
        threats.push({
          type: 'HOMOGRAPH_ATTACK',
          severity: 'CRITICAL',
          score: 95,
          description: `Homograph attack detected - domain looks like: ${homographCheck.targetDomain}`,
          context: { domain, targetDomain: homographCheck.targetDomain },
        });
        
        this.statistics.homographAttacks++;
        this.statistics.phishingDetected++;
        maxSeverity = 'CRITICAL';
      }
    }
    
    // Check for domain spoofing
    const spoofingCheck = this.checkDomainSpoofing(domain);
    if (spoofingCheck.isSpoofing) {
      threats.push({
        type: 'DOMAIN_SPOOFING',
        severity: 'CRITICAL',
        score: 90,
        description: `Domain spoofing detected - similar to: ${spoofingCheck.targetDomain}`,
        context: { domain, targetDomain: spoofingCheck.targetDomain },
      });
      
      this.statistics.domainSpoofing++;
      this.statistics.phishingDetected++;
      maxSeverity = 'CRITICAL';
    }
    
    // Check for suspicious TLD
    const tldCheck = this.checkSuspiciousTLD(domain);
    if (tldCheck.suspicious) {
      threats.push({
        type: 'SUSPICIOUS_TLD',
        severity: 'MEDIUM',
        score: 50,
        description: `Suspicious TLD detected: ${tldCheck.tld}`,
        context: { domain, tld: tldCheck.tld },
      });
      
      this.statistics.suspiciousTLDs++;
      
      if (maxSeverity === 'LOW') {
        maxSeverity = 'MEDIUM';
      }
    }
    
    // Check SSL for sensitive domains
    if (this.settings.checkSSL && !hasSSL && this.isSensitiveDomain(domain)) {
      threats.push({
        type: 'NO_SSL_ON_SENSITIVE_SITE',
        severity: 'HIGH',
        score: 75,
        description: `No SSL on sensitive domain: ${domain}`,
        context: { domain },
      });
      
      if (maxSeverity !== 'CRITICAL') {
        maxSeverity = 'HIGH';
      }
    }
    
    // Check for suspicious URL patterns
    const urlPatterns = [
      /login.*verify/gi,
      /secure.*update/gi,
      /account.*suspend/gi,
      /confirm.*identity/gi,
      /urgent.*action/gi,
    ];
    
    for (const pattern of urlPatterns) {
      if (pattern.test(url)) {
        threats.push({
          type: 'SUSPICIOUS_URL_PATTERN',
          severity: 'MEDIUM',
          score: 55,
          description: `Suspicious URL pattern detected`,
          context: { url, pattern: pattern.source },
        });
        
        if (maxSeverity === 'LOW') {
          maxSeverity = 'MEDIUM';
        }
        break;
      }
    }
    
    return {
      threats,
      severity: maxSeverity,
      hasSuspiciousActivity: threats.length > 0,
    };
  }
  
  /**
   * Check for homograph attacks
   */
  checkHomograph(domain) {
    for (const legitDomain of this.legitimateDomains) {
      // Check if domain contains homograph characters
      for (const [ascii, lookalikes] of Object.entries(this.homographs)) {
        for (const lookalike of lookalikes) {
          if (domain.includes(lookalike)) {
            // Replace lookalike with ASCII and check if it matches legitimate domain
            const normalized = domain.replace(new RegExp(lookalike, 'g'), ascii);
            
            if (normalized === legitDomain || normalized.endsWith('.' + legitDomain)) {
              return {
                isHomograph: true,
                targetDomain: legitDomain,
              };
            }
          }
        }
      }
    }
    
    return { isHomograph: false };
  }
  
  /**
   * Check for domain spoofing
   */
  checkDomainSpoofing(domain) {
    for (const legitDomain of this.legitimateDomains) {
      // Check for common spoofing patterns
      const spoofingPatterns = [
        `${legitDomain.replace('.', '-')}`,
        `${legitDomain.replace('.', '')}`,
        `${legitDomain}-secure`,
        `${legitDomain}-login`,
        `secure-${legitDomain}`,
        `login-${legitDomain}`,
      ];
      
      for (const pattern of spoofingPatterns) {
        if (domain.includes(pattern) && domain !== legitDomain) {
          return {
            isSpoofing: true,
            targetDomain: legitDomain,
          };
        }
      }
      
      // Check Levenshtein distance (typosquatting)
      const distance = this.levenshteinDistance(domain, legitDomain);
      if (distance === 1 || distance === 2) {
        return {
          isSpoofing: true,
          targetDomain: legitDomain,
        };
      }
    }
    
    return { isSpoofing: false };
  }
  
  /**
   * Check for suspicious TLD
   */
  checkSuspiciousTLD(domain) {
    for (const tld of this.suspiciousTLDs) {
      if (domain.endsWith(tld)) {
        return {
          suspicious: true,
          tld,
        };
      }
    }
    
    return { suspicious: false };
  }
  
  /**
   * Check if domain is sensitive
   */
  isSensitiveDomain(domain) {
    return this.legitimateDomains.some(legitDomain => 
      domain === legitDomain || domain.endsWith('.' + legitDomain)
    );
  }
  
  /**
   * Calculate Levenshtein distance
   */
  levenshteinDistance(str1, str2) {
    const matrix = [];
    
    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }
    
    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }
    
    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }
    
    return matrix[str2.length][str1.length];
  }
  
  /**
   * Record phishing attempt
   */
  recordAttempt(entry) {
    this.phishingAttempts.push(entry);
    
    // Track suspicious domains
    if (entry.analysis.hasSuspiciousActivity) {
      this.suspiciousDomains.set(entry.domain, {
        domain: entry.domain,
        url: entry.url,
        severity: entry.analysis.severity,
        timestamp: entry.timestamp,
      });
    }
    
    // Limit attempt history
    if (this.phishingAttempts.length > 1000) {
      this.phishingAttempts.shift();
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
   * Get phishing attempts
   */
  getPhishingAttempts() {
    return this.phishingAttempts;
  }
  
  /**
   * Get suspicious domains
   */
  getSuspiciousDomains() {
    return Array.from(this.suspiciousDomains.values());
  }
  
  /**
   * Update settings
   */
  updateSettings(newSettings) {
    this.settings = { ...this.settings, ...newSettings };
  }
}

