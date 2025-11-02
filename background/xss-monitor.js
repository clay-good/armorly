/**
 * Armorly - XSS (Cross-Site Scripting) Monitor
 * 
 * Monitors XSS attacks, detects malicious script injection,
 * prevents DOM-based XSS, and provides XSS protection across
 * all chromium-based agentic browsers.
 * 
 * Features:
 * - Real-time XSS detection
 * - Reflected XSS detection
 * - Stored XSS detection
 * - DOM-based XSS detection
 * - Script injection prevention
 */

export class XSSMonitor {
  constructor() {
    // XSS tracking
    this.xssAttempts = [];
    this.suspiciousScripts = new Map(); // scriptUrl -> data
    
    // XSS patterns (common attack vectors)
    this.xssPatterns = [
      // Script tags
      /<script[^>]*>[\s\S]*?<\/script>/gi,
      /<script[^>]*>/gi,
      
      // Event handlers
      /on\w+\s*=\s*["'][^"']*["']/gi,
      /on\w+\s*=\s*[^\s>]*/gi,
      
      // JavaScript protocol
      /javascript:/gi,
      /vbscript:/gi,
      
      // Data URIs with scripts
      /data:text\/html[^,]*,[\s\S]*<script/gi,
      
      // Common XSS payloads
      /<img[^>]+src[^>]*onerror/gi,
      /<svg[^>]*onload/gi,
      /<iframe[^>]*src/gi,
      /<embed[^>]*src/gi,
      /<object[^>]*data/gi,
      
      // Expression evaluation
      /eval\s*\(/gi,
      /setTimeout\s*\(/gi,
      /setInterval\s*\(/gi,
      /Function\s*\(/gi,
      
      // DOM manipulation
      /document\.write/gi,
      /document\.writeln/gi,
      /innerHTML\s*=/gi,
      /outerHTML\s*=/gi,
    ];
    
    // Dangerous HTML attributes
    this.dangerousAttributes = [
      'onerror', 'onload', 'onclick', 'onmouseover', 'onmouseout',
      'onfocus', 'onblur', 'onchange', 'onsubmit', 'onkeydown',
      'onkeyup', 'onkeypress', 'ondblclick', 'oncontextmenu',
    ];
    
    // Statistics
    this.statistics = {
      totalChecks: 0,
      xssDetected: 0,
      reflectedXSS: 0,
      storedXSS: 0,
      domBasedXSS: 0,
      scriptInjection: 0,
      blockedAttempts: 0,
    };
    
    // Threat callback
    this.threatCallback = null;
    
    // Settings
    this.settings = {
      monitorXSS: true,
      blockXSSAttempts: true,
      sanitizeInput: true,
      checkURLParameters: true,
      checkPostData: true,
    };
    
    // Input tracking
    this.inputHistory = new Map(); // inputId -> values[]
  }
  
  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }
  
  /**
   * Check content for XSS
   */
  checkContent(request) {
    if (!this.settings.monitorXSS) return { allowed: true };
    
    this.statistics.totalChecks++;
    
    const { content, url, source, tabId } = request;
    const domain = this.extractDomain(url);
    
    // Analyze content
    const analysis = this.analyzeContent({
      content,
      url,
      domain,
      source,
      tabId,
    });
    
    // Record attempt
    if (analysis.threats.length > 0) {
      this.recordAttempt({
        content: content.substring(0, 200), // Store first 200 chars only
        url,
        domain,
        source,
        tabId,
        timestamp: Date.now(),
        analysis,
      });
    }
    
    // Check for threats
    if (analysis.threats.length > 0) {
      console.warn('[XSSMonitor] Threats detected:', analysis.threats);
      
      if (this.threatCallback) {
        analysis.threats.forEach(threat => this.threatCallback(threat));
      }
      
      if (analysis.severity === 'CRITICAL' && this.settings.blockXSSAttempts) {
        this.statistics.blockedAttempts++;
        return {
          allowed: false,
          reason: 'XSS attack blocked',
          threats: analysis.threats,
          sanitized: this.settings.sanitizeInput ? this.sanitizeContent(content) : null,
        };
      }
    }
    
    return { allowed: true };
  }
  
  /**
   * Analyze content for XSS
   */
  analyzeContent(request) {
    const threats = [];
    let maxSeverity = 'LOW';
    
    const { content, source, domain } = request;
    
    if (!content) {
      return { threats, severity: maxSeverity, hasSuspiciousActivity: false };
    }
    
    // Check for XSS patterns
    for (const pattern of this.xssPatterns) {
      const matches = content.match(pattern);
      
      if (matches) {
        const threatType = this.classifyXSSType(pattern, source);
        
        threats.push({
          type: threatType,
          severity: 'CRITICAL',
          score: 95,
          description: `XSS attack detected: ${matches[0].substring(0, 50)}...`,
          context: {
            domain,
            source,
            pattern: pattern.source,
            match: matches[0].substring(0, 100),
          },
        });
        
        this.statistics.xssDetected++;
        this.updateXSSTypeStats(threatType);
        maxSeverity = 'CRITICAL';
        break;
      }
    }
    
    // Check for dangerous attributes
    for (const attr of this.dangerousAttributes) {
      const attrPattern = new RegExp(attr + '\\s*=', 'gi');
      
      if (attrPattern.test(content)) {
        threats.push({
          type: 'DANGEROUS_ATTRIBUTE_XSS',
          severity: 'HIGH',
          score: 85,
          description: `Dangerous HTML attribute detected: ${attr}`,
          context: { domain, source, attribute: attr },
        });
        
        this.statistics.xssDetected++;
        
        if (maxSeverity !== 'CRITICAL') {
          maxSeverity = 'HIGH';
        }
        break;
      }
    }
    
    // Check for encoded XSS attempts
    if (this.checkEncodedXSS(content)) {
      threats.push({
        type: 'ENCODED_XSS',
        severity: 'HIGH',
        score: 80,
        description: `Encoded XSS attempt detected`,
        context: { domain, source },
      });
      
      this.statistics.xssDetected++;
      
      if (maxSeverity !== 'CRITICAL') {
        maxSeverity = 'HIGH';
      }
    }
    
    return {
      threats,
      severity: maxSeverity,
      hasSuspiciousActivity: threats.length > 0,
    };
  }
  
  /**
   * Classify XSS type based on pattern and source
   */
  classifyXSSType(pattern, source) {
    const patternStr = pattern.source.toLowerCase();
    
    if (source === 'url' || source === 'parameter') {
      return 'REFLECTED_XSS';
    } else if (source === 'storage' || source === 'database') {
      return 'STORED_XSS';
    } else if (patternStr.includes('innerhtml') || patternStr.includes('outerhtml')) {
      return 'DOM_BASED_XSS';
    } else if (patternStr.includes('script')) {
      return 'SCRIPT_INJECTION';
    }
    
    return 'XSS_ATTACK';
  }
  
  /**
   * Update XSS type statistics
   */
  updateXSSTypeStats(type) {
    switch (type) {
      case 'REFLECTED_XSS':
        this.statistics.reflectedXSS++;
        break;
      case 'STORED_XSS':
        this.statistics.storedXSS++;
        break;
      case 'DOM_BASED_XSS':
        this.statistics.domBasedXSS++;
        break;
      case 'SCRIPT_INJECTION':
        this.statistics.scriptInjection++;
        break;
    }
  }
  
  /**
   * Check for encoded XSS
   */
  checkEncodedXSS(content) {
    // Check for HTML entity encoding
    const htmlEntityPattern = /&#x?[0-9a-f]+;/gi;
    const entities = content.match(htmlEntityPattern);
    
    if (entities && entities.length > 10) {
      // Decode and check for XSS patterns
      const decoded = this.decodeHTMLEntities(content);
      
      for (const pattern of this.xssPatterns) {
        if (pattern.test(decoded)) {
          return true;
        }
      }
    }
    
    // Check for URL encoding
    if (content.includes('%3C') || content.includes('%3E')) {
      const decoded = decodeURIComponent(content);
      
      for (const pattern of this.xssPatterns) {
        if (pattern.test(decoded)) {
          return true;
        }
      }
    }
    
    return false;
  }
  
  /**
   * Decode HTML entities
   */
  decodeHTMLEntities(text) {
    const entities = {
      '&lt;': '<',
      '&gt;': '>',
      '&amp;': '&',
      '&quot;': '"',
      '&#x27;': "'",
      '&#x2F;': '/',
    };
    
    let decoded = text;
    for (const [entity, char] of Object.entries(entities)) {
      decoded = decoded.replace(new RegExp(entity, 'g'), char);
    }
    
    return decoded;
  }
  
  /**
   * Sanitize content
   */
  sanitizeContent(content) {
    let sanitized = content;
    
    // Remove script tags
    sanitized = sanitized.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '');
    
    // Remove event handlers
    sanitized = sanitized.replace(/on\w+\s*=\s*["'][^"']*["']/gi, '');
    
    // Remove javascript: protocol
    sanitized = sanitized.replace(/javascript:/gi, '');
    
    // Remove dangerous tags
    sanitized = sanitized.replace(/<(iframe|embed|object)[^>]*>/gi, '');
    
    return sanitized;
  }
  
  /**
   * Record XSS attempt
   */
  recordAttempt(entry) {
    this.xssAttempts.push(entry);
    
    // Limit attempt history
    if (this.xssAttempts.length > 1000) {
      this.xssAttempts.shift();
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
   * Get XSS attempts
   */
  getXSSAttempts() {
    return this.xssAttempts;
  }
  
  /**
   * Update settings
   */
  updateSettings(newSettings) {
    this.settings = { ...this.settings, ...newSettings };
  }
}

