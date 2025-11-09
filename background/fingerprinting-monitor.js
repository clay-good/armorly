/**
 * Armorly - Browser Fingerprinting Monitor
 * 
 * Monitors browser fingerprinting attempts, detects tracking scripts,
 * prevents device fingerprinting, and provides privacy protection across
 * all chromium-based agentic browsers.
 * 
 * Features:
 * - Real-time fingerprinting detection
 * - Canvas fingerprinting detection
 * - WebGL fingerprinting detection
 * - Audio fingerprinting detection
 * - Font enumeration detection
 */

export class FingerprintingMonitor {
  constructor() {
    // Fingerprinting tracking
    this.fingerprintingAttempts = [];
    this.suspiciousScripts = new Map(); // scriptUrl -> attempts
    
    // Fingerprinting techniques
    this.techniques = {
      canvas: 0,
      webgl: 0,
      audio: 0,
      fonts: 0,
      plugins: 0,
      battery: 0,
      deviceMemory: 0,
      hardwareConcurrency: 0,
      screenResolution: 0,
      timezone: 0,
    };
    
    // Known fingerprinting libraries
    this.fingerprintingLibraries = [
      'fingerprintjs',
      'clientjs',
      'evercookie',
      'canvas-fingerprint',
      'audio-fingerprint',
      'webgl-fingerprint',
    ];
    
    // Statistics
    this.statistics = {
      totalAttempts: 0,
      canvasFingerprinting: 0,
      webglFingerprinting: 0,
      audioFingerprinting: 0,
      fontEnumeration: 0,
      deviceFingerprinting: 0,
      blockedAttempts: 0,
    };
    
    // Threat callback
    this.threatCallback = null;
    
    // Settings
    this.settings = {
      monitorFingerprinting: true,
      blockCanvasFingerprinting: false,
      blockWebGLFingerprinting: false,
      blockAudioFingerprinting: false,
      detectFingerprintingLibraries: true,
      maxAttemptsPerMinute: 10,
    };
    
    // Attempt rate tracking
    this.attemptRates = new Map(); // domain -> timestamps[]
  }
  
  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }
  
  /**
   * Monitor fingerprinting attempt
   */
  monitorAttempt(attempt) {
    if (!this.settings.monitorFingerprinting) return { allowed: true };
    
    this.statistics.totalAttempts++;
    
    const { type, url, scriptUrl, tabId, data } = attempt;
    const domain = this.extractDomain(url);
    
    // Track technique
    if (Object.prototype.hasOwnProperty.call(this.techniques, type)) {
      this.techniques[type]++;
    }
    
    // Update statistics
    switch (type) {
      case 'canvas':
        this.statistics.canvasFingerprinting++;
        break;
      case 'webgl':
        this.statistics.webglFingerprinting++;
        break;
      case 'audio':
        this.statistics.audioFingerprinting++;
        break;
      case 'fonts':
        this.statistics.fontEnumeration++;
        break;
      default:
        this.statistics.deviceFingerprinting++;
    }
    
    // Analyze attempt
    const analysis = this.analyzeAttempt({
      type,
      url,
      domain,
      scriptUrl,
      tabId,
      data,
    });
    
    // Record attempt
    this.recordAttempt({
      type,
      url,
      domain,
      scriptUrl,
      tabId,
      timestamp: Date.now(),
      analysis,
    });
    
    // Check for threats
    if (analysis.threats.length > 0) {
      console.warn('[FingerprintingMonitor] Threats detected:', analysis.threats);
      
      if (this.threatCallback) {
        analysis.threats.forEach(threat => this.threatCallback(threat));
      }
      
      // Check if should block
      const shouldBlock = this.shouldBlockAttempt(type, analysis.severity);
      
      if (shouldBlock) {
        this.statistics.blockedAttempts++;
        return {
          allowed: false,
          reason: `${type} fingerprinting blocked`,
          threats: analysis.threats,
        };
      }
    }
    
    return { allowed: true };
  }
  
  /**
   * Analyze fingerprinting attempt
   */
  analyzeAttempt(attempt) {
    const threats = [];
    let maxSeverity = 'LOW';
    
    const { type, domain, scriptUrl } = attempt;
    
    // Check for known fingerprinting libraries
    if (this.settings.detectFingerprintingLibraries && scriptUrl) {
      for (const lib of this.fingerprintingLibraries) {
        if (scriptUrl.toLowerCase().includes(lib)) {
          threats.push({
            type: 'FINGERPRINTING_LIBRARY_DETECTED',
            severity: 'HIGH',
            score: 80,
            description: `Known fingerprinting library detected: ${lib}`,
            context: { library: lib, scriptUrl, domain },
          });
          
          maxSeverity = 'HIGH';
          break;
        }
      }
    }
    
    // Check for canvas fingerprinting
    if (type === 'canvas') {
      threats.push({
        type: 'CANVAS_FINGERPRINTING',
        severity: 'MEDIUM',
        score: 60,
        description: `Canvas fingerprinting attempt detected`,
        context: { domain, scriptUrl },
      });
      
      if (maxSeverity === 'LOW') {
        maxSeverity = 'MEDIUM';
      }
    }
    
    // Check for WebGL fingerprinting
    if (type === 'webgl') {
      threats.push({
        type: 'WEBGL_FINGERPRINTING',
        severity: 'MEDIUM',
        score: 60,
        description: `WebGL fingerprinting attempt detected`,
        context: { domain, scriptUrl },
      });
      
      if (maxSeverity === 'LOW') {
        maxSeverity = 'MEDIUM';
      }
    }
    
    // Check for audio fingerprinting
    if (type === 'audio') {
      threats.push({
        type: 'AUDIO_FINGERPRINTING',
        severity: 'MEDIUM',
        score: 60,
        description: `Audio fingerprinting attempt detected`,
        context: { domain, scriptUrl },
      });
      
      if (maxSeverity === 'LOW') {
        maxSeverity = 'MEDIUM';
      }
    }
    
    // Check for font enumeration
    if (type === 'fonts') {
      threats.push({
        type: 'FONT_ENUMERATION',
        severity: 'MEDIUM',
        score: 55,
        description: `Font enumeration attempt detected`,
        context: { domain, scriptUrl },
      });
      
      if (maxSeverity === 'LOW') {
        maxSeverity = 'MEDIUM';
      }
    }
    
    // Check attempt rate
    const rateCheck = this.checkAttemptRate(domain);
    if (!rateCheck.allowed) {
      threats.push({
        type: 'EXCESSIVE_FINGERPRINTING',
        severity: 'HIGH',
        score: 70,
        description: `Excessive fingerprinting attempts from ${domain} (${rateCheck.rate}/min)`,
        context: { domain, rate: rateCheck.rate },
      });
      
      maxSeverity = 'HIGH';
    }
    
    return {
      threats,
      severity: maxSeverity,
      hasSuspiciousActivity: threats.length > 0,
    };
  }
  
  /**
   * Check if should block attempt
   */
  shouldBlockAttempt(type, severity) {
    if (severity === 'CRITICAL') return true;
    
    switch (type) {
      case 'canvas':
        return this.settings.blockCanvasFingerprinting;
      case 'webgl':
        return this.settings.blockWebGLFingerprinting;
      case 'audio':
        return this.settings.blockAudioFingerprinting;
      default:
        return false;
    }
  }
  
  /**
   * Check attempt rate
   */
  checkAttemptRate(domain) {
    const now = Date.now();
    const oneMinuteAgo = now - 60000;
    
    if (!this.attemptRates.has(domain)) {
      this.attemptRates.set(domain, []);
    }
    
    const rates = this.attemptRates.get(domain);
    
    // Remove old timestamps
    const recentRates = rates.filter(time => time > oneMinuteAgo);
    this.attemptRates.set(domain, recentRates);
    
    // Check if rate exceeded
    if (recentRates.length >= this.settings.maxAttemptsPerMinute) {
      return {
        allowed: false,
        rate: recentRates.length,
      };
    }
    
    // Add current timestamp
    recentRates.push(now);
    
    return {
      allowed: true,
      rate: recentRates.length,
    };
  }
  
  /**
   * Record attempt
   */
  recordAttempt(entry) {
    this.fingerprintingAttempts.push(entry);
    
    // Track suspicious scripts
    if (entry.scriptUrl && entry.analysis.hasSuspiciousActivity) {
      const count = this.suspiciousScripts.get(entry.scriptUrl) || 0;
      this.suspiciousScripts.set(entry.scriptUrl, count + 1);
    }
    
    // Limit attempt history
    if (this.fingerprintingAttempts.length > 1000) {
      this.fingerprintingAttempts.shift();
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
    return {
      ...this.statistics,
      techniques: this.techniques,
    };
  }
  
  /**
   * Get fingerprinting attempts
   */
  getFingerprintingAttempts() {
    return this.fingerprintingAttempts;
  }
  
  /**
   * Get suspicious scripts
   */
  getSuspiciousScripts() {
    return Array.from(this.suspiciousScripts.entries()).map(([url, count]) => ({
      url,
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

