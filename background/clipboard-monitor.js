/**
 * Armorly - Clipboard Monitor
 * 
 * Monitors clipboard access, detects data exfiltration via clipboard,
 * prevents sensitive data leakage, and provides clipboard security across
 * all chromium-based agentic browsers.
 * 
 * Features:
 * - Clipboard access monitoring
 * - Sensitive data detection in clipboard
 * - Clipboard hijacking prevention
 * - Automatic clipboard sanitization
 * - Clipboard history tracking
 */

export class ClipboardMonitor {
  constructor() {
    // Clipboard tracking
    this.clipboardHistory = [];
    this.suspiciousClipboardAccess = [];
    this.lastClipboardContent = null;
    
    // Sensitive data patterns
    this.sensitivePatterns = [
      { name: 'Credit Card', pattern: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, severity: 'CRITICAL' },
      { name: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/g, severity: 'CRITICAL' },
      { name: 'Email', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, severity: 'MEDIUM' },
      { name: 'Phone', pattern: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, severity: 'MEDIUM' },
      { name: 'API Key', pattern: /\b[A-Za-z0-9]{32,}\b/g, severity: 'HIGH' },
      { name: 'Password', pattern: /password\s*[:=]\s*\S+/gi, severity: 'CRITICAL' },
      { name: 'Token', pattern: /token\s*[:=]\s*\S+/gi, severity: 'HIGH' },
      { name: 'Private Key', pattern: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/g, severity: 'CRITICAL' },
    ];
    
    // Prompt injection patterns
    this.promptInjectionPatterns = [
      /ignore\s+(all\s+)?previous\s+instructions/gi,
      /you\s+are\s+now/gi,
      /system\s*:/gi,
      /disregard/gi,
    ];
    
    // Statistics
    this.statistics = {
      totalClipboardAccess: 0,
      sensitiveDataDetected: 0,
      clipboardHijackingAttempts: 0,
      sanitizationCount: 0,
      blockedAccess: 0,
    };
    
    // Threat callback
    this.threatCallback = null;
    
    // Settings
    this.settings = {
      monitorClipboard: true,
      sanitizeClipboard: true,
      blockSensitiveData: true,
      maxHistorySize: 100,
    };
  }
  
  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }
  
  /**
   * Monitor clipboard write
   */
  async monitorClipboardWrite(text, source = {}) {
    if (!this.settings.monitorClipboard) return { allowed: true };
    
    this.statistics.totalClipboardAccess++;
    
    // Analyze clipboard content
    const analysis = this.analyzeClipboardContent(text);
    
    // Record in history
    this.recordClipboardAccess({
      type: 'WRITE',
      content: text.substring(0, 100), // Store first 100 chars
      timestamp: Date.now(),
      source,
      analysis,
    });
    
    // Check for threats
    if (analysis.threats.length > 0) {
      console.warn('[ClipboardMonitor] Threats detected in clipboard:', analysis.threats);
      
      // Report threats
      if (this.threatCallback) {
        analysis.threats.forEach(threat => this.threatCallback(threat));
      }
      
      // Block if critical
      if (analysis.severity === 'CRITICAL' && this.settings.blockSensitiveData) {
        this.statistics.blockedAccess++;
        return {
          allowed: false,
          reason: 'Sensitive data detected in clipboard',
          threats: analysis.threats,
        };
      }
      
      // Sanitize if enabled
      if (this.settings.sanitizeClipboard) {
        const sanitized = this.sanitizeClipboard(text, analysis);
        this.statistics.sanitizationCount++;
        return {
          allowed: true,
          sanitized: true,
          content: sanitized,
        };
      }
    }
    
    return { allowed: true };
  }
  
  /**
   * Monitor clipboard read
   */
  async monitorClipboardRead(source = {}) {
    if (!this.settings.monitorClipboard) return { allowed: true };
    
    this.statistics.totalClipboardAccess++;
    
    // Record in history
    this.recordClipboardAccess({
      type: 'READ',
      timestamp: Date.now(),
      source,
    });
    
    // Check for suspicious patterns (e.g., rapid reads)
    const recentReads = this.clipboardHistory
      .filter(entry => entry.type === 'READ' && Date.now() - entry.timestamp < 5000)
      .length;
    
    if (recentReads > 10) {
      console.warn('[ClipboardMonitor] Suspicious clipboard read pattern detected');
      
      this.statistics.clipboardHijackingAttempts++;
      
      if (this.threatCallback) {
        this.threatCallback({
          type: 'CLIPBOARD_HIJACKING',
          severity: 'HIGH',
          score: 70,
          description: `Suspicious clipboard read pattern (${recentReads} reads in 5 seconds)`,
          context: { source, recentReads },
        });
      }
    }
    
    return { allowed: true };
  }
  
  /**
   * Analyze clipboard content
   */
  analyzeClipboardContent(text) {
    const threats = [];
    let maxSeverity = 'LOW';
    let totalScore = 0;
    
    // Check for sensitive data
    for (const pattern of this.sensitivePatterns) {
      const matches = text.match(pattern.pattern);
      if (matches) {
        threats.push({
          type: 'SENSITIVE_DATA_IN_CLIPBOARD',
          severity: pattern.severity,
          score: this.getSeverityScore(pattern.severity),
          description: `${pattern.name} detected in clipboard`,
          context: { dataType: pattern.name, matchCount: matches.length },
        });
        
        this.statistics.sensitiveDataDetected++;
        
        if (this.compareSeverity(pattern.severity, maxSeverity) > 0) {
          maxSeverity = pattern.severity;
        }
        
        totalScore += this.getSeverityScore(pattern.severity);
      }
    }
    
    // Check for prompt injection
    for (const pattern of this.promptInjectionPatterns) {
      const matches = text.match(pattern);
      if (matches) {
        threats.push({
          type: 'PROMPT_INJECTION_IN_CLIPBOARD',
          severity: 'HIGH',
          score: 70,
          description: 'Prompt injection pattern detected in clipboard',
          context: { matchCount: matches.length },
        });
        
        if (this.compareSeverity('HIGH', maxSeverity) > 0) {
          maxSeverity = 'HIGH';
        }
        
        totalScore += 70;
      }
    }
    
    return {
      threats,
      severity: maxSeverity,
      totalScore,
      hasSensitiveData: threats.length > 0,
    };
  }
  
  /**
   * Sanitize clipboard content
   */
  sanitizeClipboard(text, analysis) {
    let sanitized = text;
    
    // Remove sensitive data patterns
    for (const pattern of this.sensitivePatterns) {
      sanitized = sanitized.replace(pattern.pattern, `[${pattern.name} REDACTED]`);
    }
    
    // Remove prompt injection patterns
    for (const pattern of this.promptInjectionPatterns) {
      sanitized = sanitized.replace(pattern, '[SUSPICIOUS CONTENT REMOVED]');
    }
    
    return sanitized;
  }
  
  /**
   * Record clipboard access
   */
  recordClipboardAccess(entry) {
    this.clipboardHistory.push(entry);
    
    // Limit history size
    if (this.clipboardHistory.length > this.settings.maxHistorySize) {
      this.clipboardHistory.shift();
    }
  }
  
  /**
   * Get severity score
   */
  getSeverityScore(severity) {
    const scores = {
      CRITICAL: 90,
      HIGH: 70,
      MEDIUM: 40,
      LOW: 20,
    };
    return scores[severity] || 0;
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
      historySize: this.clipboardHistory.length,
    };
  }
  
  /**
   * Get clipboard history
   */
  getClipboardHistory() {
    return this.clipboardHistory;
  }
  
  /**
   * Clear clipboard history
   */
  clearHistory() {
    this.clipboardHistory = [];
  }
  
  /**
   * Update settings
   */
  updateSettings(newSettings) {
    this.settings = { ...this.settings, ...newSettings };
  }
}

