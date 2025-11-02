/**
 * Armorly - SQL Injection Monitor
 * 
 * Monitors SQL injection attacks, detects malicious database queries,
 * prevents data exfiltration via SQL, and provides database security
 * across all chromium-based agentic browsers.
 * 
 * Features:
 * - Real-time SQL injection detection
 * - Union-based injection detection
 * - Boolean-based blind injection detection
 * - Time-based blind injection detection
 * - Error-based injection detection
 */

export class SQLInjectionMonitor {
  constructor() {
    // SQL injection tracking
    this.injectionAttempts = [];
    this.suspiciousQueries = new Map(); // query -> count
    
    // SQL injection patterns
    this.sqlPatterns = [
      // Union-based injection
      /union\s+select/gi,
      /union\s+all\s+select/gi,
      
      // Boolean-based blind injection
      /'\s*or\s*'1'\s*=\s*'1/gi,
      /'\s*or\s*1\s*=\s*1/gi,
      /"\s*or\s*"1"\s*=\s*"1/gi,
      /"\s*or\s*1\s*=\s*1/gi,
      /'\s*or\s*'a'\s*=\s*'a/gi,
      
      // Time-based blind injection
      /sleep\s*\(/gi,
      /benchmark\s*\(/gi,
      /waitfor\s+delay/gi,
      /pg_sleep\s*\(/gi,
      
      // Error-based injection
      /convert\s*\(/gi,
      /cast\s*\(/gi,
      /extractvalue\s*\(/gi,
      /updatexml\s*\(/gi,
      
      // Stacked queries
      /;\s*drop\s+table/gi,
      /;\s*delete\s+from/gi,
      /;\s*update\s+/gi,
      /;\s*insert\s+into/gi,
      
      // Comment injection
      /--\s*$/gm,
      /#\s*$/gm,
      /\/\*.*\*\//gi,
      
      // Information schema
      /information_schema/gi,
      /sys\.tables/gi,
      /sys\.columns/gi,
      
      // Database functions
      /database\s*\(\s*\)/gi,
      /version\s*\(\s*\)/gi,
      /user\s*\(\s*\)/gi,
      /current_user/gi,
      
      // Hex encoding
      /0x[0-9a-f]+/gi,
      
      // Concatenation
      /concat\s*\(/gi,
      /group_concat\s*\(/gi,
    ];
    
    // SQL keywords
    this.sqlKeywords = [
      'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE',
      'ALTER', 'TRUNCATE', 'UNION', 'WHERE', 'FROM', 'JOIN',
      'EXEC', 'EXECUTE', 'DECLARE', 'CAST', 'CONVERT',
    ];
    
    // Statistics
    this.statistics = {
      totalChecks: 0,
      injectionDetected: 0,
      unionBased: 0,
      booleanBased: 0,
      timeBased: 0,
      errorBased: 0,
      stackedQueries: 0,
      blockedAttempts: 0,
    };
    
    // Threat callback
    this.threatCallback = null;
    
    // Settings
    this.settings = {
      monitorSQLInjection: true,
      blockInjectionAttempts: true,
      checkURLParameters: true,
      checkPostData: true,
      checkHeaders: true,
    };
  }
  
  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }
  
  /**
   * Check input for SQL injection
   */
  checkInput(request) {
    if (!this.settings.monitorSQLInjection) return { allowed: true };
    
    this.statistics.totalChecks++;
    
    const { input, url, source, tabId } = request;
    const domain = this.extractDomain(url);
    
    // Analyze input
    const analysis = this.analyzeInput({
      input,
      url,
      domain,
      source,
      tabId,
    });
    
    // Record attempt
    if (analysis.threats.length > 0) {
      this.recordAttempt({
        input: input.substring(0, 200), // Store first 200 chars only
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
      console.warn('[SQLInjectionMonitor] Threats detected:', analysis.threats);
      
      if (this.threatCallback) {
        analysis.threats.forEach(threat => this.threatCallback(threat));
      }
      
      if (analysis.severity === 'CRITICAL' && this.settings.blockInjectionAttempts) {
        this.statistics.blockedAttempts++;
        return {
          allowed: false,
          reason: 'SQL injection attack blocked',
          threats: analysis.threats,
        };
      }
    }
    
    return { allowed: true };
  }
  
  /**
   * Analyze input for SQL injection
   */
  analyzeInput(request) {
    const threats = [];
    let maxSeverity = 'LOW';
    
    const { input, source, domain } = request;
    
    if (!input) {
      return { threats, severity: maxSeverity, hasSuspiciousActivity: false };
    }
    
    // Check for SQL injection patterns
    for (const pattern of this.sqlPatterns) {
      const matches = input.match(pattern);
      
      if (matches) {
        const injectionType = this.classifyInjectionType(pattern);
        
        threats.push({
          type: injectionType,
          severity: 'CRITICAL',
          score: 95,
          description: `SQL injection detected: ${matches[0].substring(0, 50)}...`,
          context: {
            domain,
            source,
            pattern: pattern.source,
            match: matches[0].substring(0, 100),
          },
        });
        
        this.statistics.injectionDetected++;
        this.updateInjectionTypeStats(injectionType);
        maxSeverity = 'CRITICAL';
        break;
      }
    }
    
    // Check for multiple SQL keywords (suspicious)
    const keywordCount = this.countSQLKeywords(input);
    if (keywordCount >= 3) {
      threats.push({
        type: 'MULTIPLE_SQL_KEYWORDS',
        severity: 'HIGH',
        score: 80,
        description: `Multiple SQL keywords detected (${keywordCount})`,
        context: { domain, source, keywordCount },
      });
      
      if (maxSeverity !== 'CRITICAL') {
        maxSeverity = 'HIGH';
      }
    }
    
    // Check for encoded SQL injection
    if (this.checkEncodedSQL(input)) {
      threats.push({
        type: 'ENCODED_SQL_INJECTION',
        severity: 'HIGH',
        score: 85,
        description: `Encoded SQL injection attempt detected`,
        context: { domain, source },
      });
      
      this.statistics.injectionDetected++;
      
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
   * Classify injection type
   */
  classifyInjectionType(pattern) {
    const patternStr = pattern.source.toLowerCase();
    
    if (patternStr.includes('union')) {
      return 'UNION_BASED_INJECTION';
    } else if (patternStr.includes('sleep') || patternStr.includes('benchmark') || patternStr.includes('waitfor')) {
      return 'TIME_BASED_INJECTION';
    } else if (patternStr.includes('or') && patternStr.includes('=')) {
      return 'BOOLEAN_BASED_INJECTION';
    } else if (patternStr.includes('convert') || patternStr.includes('cast') || patternStr.includes('extractvalue')) {
      return 'ERROR_BASED_INJECTION';
    } else if (patternStr.includes(';') && (patternStr.includes('drop') || patternStr.includes('delete'))) {
      return 'STACKED_QUERIES_INJECTION';
    }
    
    return 'SQL_INJECTION';
  }
  
  /**
   * Update injection type statistics
   */
  updateInjectionTypeStats(type) {
    switch (type) {
      case 'UNION_BASED_INJECTION':
        this.statistics.unionBased++;
        break;
      case 'BOOLEAN_BASED_INJECTION':
        this.statistics.booleanBased++;
        break;
      case 'TIME_BASED_INJECTION':
        this.statistics.timeBased++;
        break;
      case 'ERROR_BASED_INJECTION':
        this.statistics.errorBased++;
        break;
      case 'STACKED_QUERIES_INJECTION':
        this.statistics.stackedQueries++;
        break;
    }
  }
  
  /**
   * Count SQL keywords in input
   */
  countSQLKeywords(input) {
    const upperInput = input.toUpperCase();
    let count = 0;
    
    for (const keyword of this.sqlKeywords) {
      if (upperInput.includes(keyword)) {
        count++;
      }
    }
    
    return count;
  }
  
  /**
   * Check for encoded SQL injection
   */
  checkEncodedSQL(input) {
    // Check for URL encoding
    if (input.includes('%27') || input.includes('%22') || input.includes('%20')) {
      const decoded = decodeURIComponent(input);
      
      for (const pattern of this.sqlPatterns) {
        if (pattern.test(decoded)) {
          return true;
        }
      }
    }
    
    // Check for hex encoding
    if (input.includes('0x')) {
      // Simple check for hex-encoded SQL keywords
      const hexPattern = /0x[0-9a-f]+/gi;
      const hexMatches = input.match(hexPattern);
      
      if (hexMatches && hexMatches.length > 0) {
        return true;
      }
    }
    
    return false;
  }
  
  /**
   * Record injection attempt
   */
  recordAttempt(entry) {
    this.injectionAttempts.push(entry);
    
    // Track suspicious queries
    const queryKey = entry.input.substring(0, 100);
    const count = this.suspiciousQueries.get(queryKey) || 0;
    this.suspiciousQueries.set(queryKey, count + 1);
    
    // Limit attempt history
    if (this.injectionAttempts.length > 1000) {
      this.injectionAttempts.shift();
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
   * Get injection attempts
   */
  getInjectionAttempts() {
    return this.injectionAttempts;
  }
  
  /**
   * Get suspicious queries
   */
  getSuspiciousQueries() {
    return Array.from(this.suspiciousQueries.entries()).map(([query, count]) => ({
      query,
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

