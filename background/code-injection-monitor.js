/**
 * Armorly - Code Injection Monitor
 * 
 * Monitors code injection attacks, detects malicious code execution,
 * prevents remote code execution (RCE), and provides code security
 * across all chromium-based agentic browsers.
 * 
 * Features:
 * - Real-time code injection detection
 * - Command injection detection
 * - Template injection detection
 * - Expression injection detection
 * - Remote code execution prevention
 */

export class CodeInjectionMonitor {
  constructor() {
    // Code injection tracking
    this.injectionAttempts = [];
    this.suspiciousCode = new Map(); // code -> count
    
    // Command injection patterns
    this.commandPatterns = [
      // Shell commands
      /;\s*ls\s/gi,
      /;\s*cat\s/gi,
      /;\s*pwd\s/gi,
      /;\s*whoami\s/gi,
      /;\s*id\s/gi,
      /;\s*uname\s/gi,
      /;\s*wget\s/gi,
      /;\s*curl\s/gi,
      
      // Command chaining
      /&&/g,
      /\|\|/g,
      /;\s*\w+/g,
      
      // Pipe operators
      /\|\s*\w+/g,
      
      // Backticks
      /`[^`]+`/g,
      
      // $() command substitution
      /\$\([^)]+\)/g,
    ];
    
    // Template injection patterns
    this.templatePatterns = [
      // Server-side template injection
      /\{\{.*\}\}/g,
      /\{%.*%\}/g,
      /\$\{.*\}/g,
      /<\?.*\?>/g,
      /<%.*%>/g,
      
      // Expression language injection
      /\#\{.*\}/g,
      /@\{.*\}/g,
    ];
    
    // Code execution patterns
    this.codeExecutionPatterns = [
      // JavaScript execution
      /eval\s*\(/gi,
      /Function\s*\(/gi,
      /setTimeout\s*\(/gi,
      /setInterval\s*\(/gi,
      /execScript\s*\(/gi,
      
      // Dynamic code loading
      /import\s*\(/gi,
      /require\s*\(/gi,
      
      // Node.js specific
      /child_process/gi,
      /exec\s*\(/gi,
      /spawn\s*\(/gi,
      /fork\s*\(/gi,
      
      // Python specific
      /__import__/gi,
      /compile\s*\(/gi,
      
      // PHP specific
      /system\s*\(/gi,
      /shell_exec\s*\(/gi,
      /passthru\s*\(/gi,
      /proc_open\s*\(/gi,
    ];
    
    // Path traversal patterns
    this.pathTraversalPatterns = [
      /\.\.\//g,
      /\.\.%2[fF]/g,
      /\.\.%5[cC]/g,
      /%2e%2e%2f/gi,
      /%2e%2e\//gi,
    ];
    
    // Statistics
    this.statistics = {
      totalChecks: 0,
      injectionDetected: 0,
      commandInjection: 0,
      templateInjection: 0,
      codeExecution: 0,
      pathTraversal: 0,
      blockedAttempts: 0,
    };
    
    // Threat callback
    this.threatCallback = null;
    
    // Settings
    this.settings = {
      monitorCodeInjection: true,
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
   * Check input for code injection
   */
  checkInput(request) {
    if (!this.settings.monitorCodeInjection) return { allowed: true };
    
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
      console.warn('[CodeInjectionMonitor] Threats detected:', analysis.threats);
      
      if (this.threatCallback) {
        analysis.threats.forEach(threat => this.threatCallback(threat));
      }
      
      if (analysis.severity === 'CRITICAL' && this.settings.blockInjectionAttempts) {
        this.statistics.blockedAttempts++;
        return {
          allowed: false,
          reason: 'Code injection attack blocked',
          threats: analysis.threats,
        };
      }
    }
    
    return { allowed: true };
  }
  
  /**
   * Analyze input for code injection
   */
  analyzeInput(request) {
    const threats = [];
    let maxSeverity = 'LOW';
    
    const { input, source, domain } = request;
    
    if (!input) {
      return { threats, severity: maxSeverity, hasSuspiciousActivity: false };
    }
    
    // Check for command injection
    for (const pattern of this.commandPatterns) {
      const matches = input.match(pattern);
      
      if (matches) {
        threats.push({
          type: 'COMMAND_INJECTION',
          severity: 'CRITICAL',
          score: 95,
          description: `Command injection detected: ${matches[0].substring(0, 50)}...`,
          context: {
            domain,
            source,
            pattern: pattern.source,
            match: matches[0].substring(0, 100),
          },
        });
        
        this.statistics.injectionDetected++;
        this.statistics.commandInjection++;
        maxSeverity = 'CRITICAL';
        break;
      }
    }
    
    // Check for template injection
    for (const pattern of this.templatePatterns) {
      const matches = input.match(pattern);
      
      if (matches) {
        threats.push({
          type: 'TEMPLATE_INJECTION',
          severity: 'CRITICAL',
          score: 90,
          description: `Template injection detected: ${matches[0].substring(0, 50)}...`,
          context: {
            domain,
            source,
            pattern: pattern.source,
            match: matches[0].substring(0, 100),
          },
        });
        
        this.statistics.injectionDetected++;
        this.statistics.templateInjection++;
        maxSeverity = 'CRITICAL';
        break;
      }
    }
    
    // Check for code execution
    for (const pattern of this.codeExecutionPatterns) {
      const matches = input.match(pattern);
      
      if (matches) {
        threats.push({
          type: 'CODE_EXECUTION_ATTEMPT',
          severity: 'CRITICAL',
          score: 95,
          description: `Code execution attempt detected: ${matches[0].substring(0, 50)}...`,
          context: {
            domain,
            source,
            pattern: pattern.source,
            match: matches[0].substring(0, 100),
          },
        });
        
        this.statistics.injectionDetected++;
        this.statistics.codeExecution++;
        maxSeverity = 'CRITICAL';
        break;
      }
    }
    
    // Check for path traversal
    for (const pattern of this.pathTraversalPatterns) {
      const matches = input.match(pattern);
      
      if (matches) {
        threats.push({
          type: 'PATH_TRAVERSAL',
          severity: 'HIGH',
          score: 85,
          description: `Path traversal attempt detected: ${matches[0].substring(0, 50)}...`,
          context: {
            domain,
            source,
            pattern: pattern.source,
            match: matches[0].substring(0, 100),
          },
        });
        
        this.statistics.injectionDetected++;
        this.statistics.pathTraversal++;
        
        if (maxSeverity !== 'CRITICAL') {
          maxSeverity = 'HIGH';
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
   * Record injection attempt
   */
  recordAttempt(entry) {
    this.injectionAttempts.push(entry);
    
    // Track suspicious code
    const codeKey = entry.input.substring(0, 100);
    const count = this.suspiciousCode.get(codeKey) || 0;
    this.suspiciousCode.set(codeKey, count + 1);
    
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
   * Get suspicious code
   */
  getSuspiciousCode() {
    return Array.from(this.suspiciousCode.entries()).map(([code, count]) => ({
      code,
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

