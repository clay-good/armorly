/**
 * Armorly - File System Monitor
 * 
 * Monitors file system access, detects unauthorized file operations,
 * prevents data exfiltration via file downloads, and provides file security
 * across all chromium-based agentic browsers.
 * 
 * Features:
 * - Real-time file operation monitoring
 * - Unauthorized file access detection
 * - Data exfiltration prevention
 * - Malicious file download detection
 * - File integrity validation
 */

export class FileSystemMonitor {
  constructor() {
    // File operation tracking
    this.fileOperations = [];
    this.downloads = [];
    this.suspiciousOperations = [];
    
    // Dangerous file extensions
    this.dangerousExtensions = [
      '.exe', '.bat', '.cmd', '.com', '.scr', '.pif',
      '.vbs', '.js', '.jar', '.msi', '.app', '.deb', '.rpm',
      '.sh', '.ps1', '.psm1', '.dll', '.sys',
    ];
    
    // Sensitive file patterns
    this.sensitiveFilePatterns = [
      /password/gi,
      /credential/gi,
      /secret/gi,
      /private[_-]?key/gi,
      /api[_-]?key/gi,
      /token/gi,
      /\.pem$/gi,
      /\.key$/gi,
      /\.p12$/gi,
      /\.pfx$/gi,
    ];
    
    // Statistics
    this.statistics = {
      totalFileOperations: 0,
      readOperations: 0,
      writeOperations: 0,
      downloadOperations: 0,
      suspiciousOperations: 0,
      maliciousDownloads: 0,
      dataExfiltrationAttempts: 0,
      blockedOperations: 0,
    };
    
    // Threat callback
    this.threatCallback = null;
    
    // Settings
    this.settings = {
      monitorFileSystem: true,
      blockDangerousDownloads: true,
      detectDataExfiltration: true,
      maxDownloadsPerMinute: 10,
      maxFileSizeBytes: 100000000, // 100MB
    };
    
    // Download rate tracking
    this.downloadRates = new Map(); // domain -> timestamps[]
  }
  
  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }
  
  /**
   * Monitor file operation
   */
  monitorFileOperation(operation) {
    if (!this.settings.monitorFileSystem) return { allowed: true };
    
    this.statistics.totalFileOperations++;
    
    const { type, filename, url, tabId, size } = operation;
    
    // Track operation type
    switch (type) {
      case 'read':
        this.statistics.readOperations++;
        break;
      case 'write':
        this.statistics.writeOperations++;
        break;
      case 'download':
        this.statistics.downloadOperations++;
        break;
    }
    
    // Analyze operation
    const analysis = this.analyzeFileOperation(operation);
    
    // Record operation
    this.recordFileOperation({
      ...operation,
      timestamp: Date.now(),
      analysis,
    });
    
    // Check for threats
    if (analysis.threats.length > 0) {
      console.warn('[FileSystemMonitor] Threats detected:', analysis.threats);
      
      if (this.threatCallback) {
        analysis.threats.forEach(threat => this.threatCallback(threat));
      }
      
      if (analysis.severity === 'CRITICAL' && this.settings.blockDangerousDownloads) {
        this.statistics.blockedOperations++;
        return {
          allowed: false,
          reason: 'Dangerous file operation blocked',
          threats: analysis.threats,
        };
      }
    }
    
    return { allowed: true };
  }
  
  /**
   * Analyze file operation
   */
  analyzeFileOperation(operation) {
    const threats = [];
    let maxSeverity = 'LOW';
    
    const { type, filename, url, size, content } = operation;
    
    // Check for dangerous file extensions
    if (type === 'download' && this.isDangerousFile(filename)) {
      threats.push({
        type: 'DANGEROUS_FILE_DOWNLOAD',
        severity: 'CRITICAL',
        score: 90,
        description: `Dangerous file download detected: ${filename}`,
        context: { filename, url },
      });
      
      this.statistics.maliciousDownloads++;
      maxSeverity = 'CRITICAL';
    }
    
    // Check for sensitive file patterns
    for (const pattern of this.sensitiveFilePatterns) {
      if (pattern.test(filename)) {
        threats.push({
          type: 'SENSITIVE_FILE_ACCESS',
          severity: 'HIGH',
          score: 70,
          description: `Sensitive file detected: ${filename}`,
          context: { filename, url },
        });
        
        if (maxSeverity !== 'CRITICAL') {
          maxSeverity = 'HIGH';
        }
        break;
      }
    }
    
    // Check for large file downloads (potential data exfiltration)
    if (type === 'download' && size > this.settings.maxFileSizeBytes) {
      threats.push({
        type: 'LARGE_FILE_DOWNLOAD',
        severity: 'MEDIUM',
        score: 50,
        description: `Large file download detected (${this.formatBytes(size)})`,
        context: { filename, size, url },
      });
      
      this.statistics.dataExfiltrationAttempts++;
      
      if (maxSeverity === 'LOW') {
        maxSeverity = 'MEDIUM';
      }
    }
    
    // Check download rate
    if (type === 'download') {
      const domain = this.extractDomain(url);
      const rateCheck = this.checkDownloadRate(domain);
      
      if (!rateCheck.allowed) {
        threats.push({
          type: 'EXCESSIVE_DOWNLOADS',
          severity: 'MEDIUM',
          score: 50,
          description: `Excessive downloads from ${domain}`,
          context: { domain, rate: rateCheck.rate },
        });
        
        if (maxSeverity === 'LOW') {
          maxSeverity = 'MEDIUM';
        }
      }
    }
    
    // Check file content for sensitive data (if available)
    if (content && this.settings.detectDataExfiltration) {
      const contentStr = typeof content === 'string' ? content : JSON.stringify(content);
      
      const sensitivePatterns = [
        /password\s*[:=]\s*\S+/gi,
        /api[_-]?key\s*[:=]\s*\S+/gi,
        /secret\s*[:=]\s*\S+/gi,
        /token\s*[:=]\s*\S+/gi,
      ];
      
      for (const pattern of sensitivePatterns) {
        if (pattern.test(contentStr)) {
          threats.push({
            type: 'SENSITIVE_DATA_IN_FILE',
            severity: 'HIGH',
            score: 70,
            description: `Sensitive data detected in file content`,
            context: { filename, pattern: pattern.source },
          });
          
          this.statistics.dataExfiltrationAttempts++;
          
          if (maxSeverity !== 'CRITICAL') {
            maxSeverity = 'HIGH';
          }
          break;
        }
      }
    }
    
    return {
      threats,
      severity: maxSeverity,
      hasSuspiciousActivity: threats.length > 0,
    };
  }
  
  /**
   * Check if file is dangerous
   */
  isDangerousFile(filename) {
    const lowerFilename = filename.toLowerCase();
    return this.dangerousExtensions.some(ext => lowerFilename.endsWith(ext));
  }
  
  /**
   * Check download rate
   */
  checkDownloadRate(domain) {
    const now = Date.now();
    const oneMinuteAgo = now - 60000;
    
    if (!this.downloadRates.has(domain)) {
      this.downloadRates.set(domain, []);
    }
    
    const rates = this.downloadRates.get(domain);
    
    // Remove old timestamps
    const recentRates = rates.filter(time => time > oneMinuteAgo);
    this.downloadRates.set(domain, recentRates);
    
    // Check if rate exceeded
    if (recentRates.length >= this.settings.maxDownloadsPerMinute) {
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
   * Record file operation
   */
  recordFileOperation(entry) {
    this.fileOperations.push(entry);
    
    if (entry.type === 'download') {
      this.downloads.push(entry);
    }
    
    if (entry.analysis.hasSuspiciousActivity) {
      this.suspiciousOperations.push(entry);
      this.statistics.suspiciousOperations++;
      
      // Limit history size
      if (this.suspiciousOperations.length > 100) {
        this.suspiciousOperations.shift();
      }
    }
    
    // Limit operation history
    if (this.fileOperations.length > 1000) {
      this.fileOperations.shift();
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
   * Format bytes to human-readable string
   */
  formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(2) + ' KB';
    if (bytes < 1073741824) return (bytes / 1048576).toFixed(2) + ' MB';
    return (bytes / 1073741824).toFixed(2) + ' GB';
  }
  
  /**
   * Get statistics
   */
  getStatistics() {
    return this.statistics;
  }
  
  /**
   * Get suspicious operations
   */
  getSuspiciousOperations() {
    return this.suspiciousOperations;
  }
  
  /**
   * Update settings
   */
  updateSettings(newSettings) {
    this.settings = { ...this.settings, ...newSettings };
  }
}

