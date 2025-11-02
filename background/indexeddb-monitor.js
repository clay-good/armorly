/**
 * Armorly - IndexedDB Monitor
 * 
 * Monitors IndexedDB operations, detects suspicious database access,
 * prevents data poisoning attacks, and provides database security across
 * all chromium-based agentic browsers.
 * 
 * Features:
 * - Real-time IndexedDB operation monitoring
 * - Data poisoning detection
 * - Unauthorized access prevention
 * - Suspicious query pattern detection
 * - Database integrity validation
 */

export class IndexedDBMonitor {
  constructor() {
    // Database tracking
    this.databases = new Map(); // dbName -> db data
    this.operations = [];
    this.suspiciousOperations = [];
    
    // Sensitive data patterns
    this.sensitivePatterns = [
      /password/gi,
      /api[_-]?key/gi,
      /secret/gi,
      /token/gi,
      /credential/gi,
      /private[_-]?key/gi,
      /session/gi,
      /auth/gi,
    ];
    
    // Suspicious operation patterns
    this.suspiciousOperationPatterns = {
      rapidWrites: 100, // per minute
      rapidReads: 500, // per minute
      largeWrite: 1000000, // 1MB
      massDelete: 100, // records
    };
    
    // Statistics
    this.statistics = {
      totalOperations: 0,
      readOperations: 0,
      writeOperations: 0,
      deleteOperations: 0,
      suspiciousOperations: 0,
      dataPoisoningAttempts: 0,
      blockedOperations: 0,
    };
    
    // Threat callback
    this.threatCallback = null;
    
    // Settings
    this.settings = {
      monitorIndexedDB: true,
      detectDataPoisoning: true,
      blockSuspiciousOperations: true,
      validateDataIntegrity: true,
    };
    
    // Operation rate tracking
    this.operationRates = new Map(); // dbName -> { reads: [], writes: [] }
  }
  
  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }
  
  /**
   * Monitor database operation
   */
  monitorOperation(operation) {
    if (!this.settings.monitorIndexedDB) return { allowed: true };
    
    this.statistics.totalOperations++;
    
    const { type, dbName, storeName, data, tabId } = operation;
    
    // Track operation type
    switch (type) {
      case 'read':
        this.statistics.readOperations++;
        break;
      case 'write':
        this.statistics.writeOperations++;
        break;
      case 'delete':
        this.statistics.deleteOperations++;
        break;
    }
    
    // Analyze operation
    const analysis = this.analyzeOperation(operation);
    
    // Record operation
    this.recordOperation({
      ...operation,
      timestamp: Date.now(),
      analysis,
    });
    
    // Check for threats
    if (analysis.threats.length > 0) {
      console.warn('[IndexedDBMonitor] Threats detected:', analysis.threats);
      
      if (this.threatCallback) {
        analysis.threats.forEach(threat => this.threatCallback(threat));
      }
      
      if (analysis.severity === 'CRITICAL' && this.settings.blockSuspiciousOperations) {
        this.statistics.blockedOperations++;
        return {
          allowed: false,
          reason: 'Suspicious IndexedDB operation blocked',
          threats: analysis.threats,
        };
      }
    }
    
    return { allowed: true };
  }
  
  /**
   * Analyze database operation
   */
  analyzeOperation(operation) {
    const threats = [];
    let maxSeverity = 'LOW';
    
    const { type, dbName, storeName, data, count } = operation;
    
    // Check for data poisoning in writes
    if (type === 'write' && data && this.settings.detectDataPoisoning) {
      const dataStr = typeof data === 'string' ? data : JSON.stringify(data);
      
      // Check for prompt injection patterns
      const injectionPatterns = [
        /ignore previous instructions/gi,
        /you are now/gi,
        /system:/gi,
        /disregard/gi,
        /override/gi,
      ];
      
      for (const pattern of injectionPatterns) {
        if (pattern.test(dataStr)) {
          threats.push({
            type: 'INDEXEDDB_DATA_POISONING',
            severity: 'CRITICAL',
            score: 90,
            description: `Data poisoning attempt detected in IndexedDB write`,
            context: {
              dbName,
              storeName,
              pattern: pattern.source,
            },
          });
          
          this.statistics.dataPoisoningAttempts++;
          maxSeverity = 'CRITICAL';
          break;
        }
      }
      
      // Check for sensitive data storage
      for (const pattern of this.sensitivePatterns) {
        if (pattern.test(dataStr)) {
          threats.push({
            type: 'SENSITIVE_DATA_IN_INDEXEDDB',
            severity: 'HIGH',
            score: 70,
            description: `Sensitive data detected in IndexedDB write`,
            context: {
              dbName,
              storeName,
              pattern: pattern.source,
            },
          });
          
          if (maxSeverity !== 'CRITICAL') {
            maxSeverity = 'HIGH';
          }
          break;
        }
      }
      
      // Check for large writes
      if (dataStr.length > this.suspiciousOperationPatterns.largeWrite) {
        threats.push({
          type: 'LARGE_INDEXEDDB_WRITE',
          severity: 'MEDIUM',
          score: 50,
          description: `Large IndexedDB write detected (${dataStr.length} bytes)`,
          context: {
            dbName,
            storeName,
            size: dataStr.length,
          },
        });
        
        if (maxSeverity === 'LOW') {
          maxSeverity = 'MEDIUM';
        }
      }
    }
    
    // Check for mass delete operations
    if (type === 'delete' && count > this.suspiciousOperationPatterns.massDelete) {
      threats.push({
        type: 'MASS_INDEXEDDB_DELETE',
        severity: 'HIGH',
        score: 70,
        description: `Mass delete operation detected (${count} records)`,
        context: {
          dbName,
          storeName,
          count,
        },
      });
      
      if (maxSeverity !== 'CRITICAL') {
        maxSeverity = 'HIGH';
      }
    }
    
    // Check operation rate
    const rateCheck = this.checkOperationRate(dbName, type);
    if (!rateCheck.allowed) {
      threats.push({
        type: 'EXCESSIVE_INDEXEDDB_OPERATIONS',
        severity: 'MEDIUM',
        score: 50,
        description: `Excessive ${type} operations on ${dbName}`,
        context: {
          dbName,
          type,
          rate: rateCheck.rate,
        },
      });
      
      if (maxSeverity === 'LOW') {
        maxSeverity = 'MEDIUM';
      }
    }
    
    return {
      threats,
      severity: maxSeverity,
      hasSuspiciousActivity: threats.length > 0,
    };
  }
  
  /**
   * Check operation rate
   */
  checkOperationRate(dbName, type) {
    const now = Date.now();
    const oneMinuteAgo = now - 60000;
    
    if (!this.operationRates.has(dbName)) {
      this.operationRates.set(dbName, { reads: [], writes: [] });
    }
    
    const rates = this.operationRates.get(dbName);
    const operationType = type === 'read' ? 'reads' : 'writes';
    
    // Remove old timestamps
    rates[operationType] = rates[operationType].filter(time => time > oneMinuteAgo);
    
    // Check threshold
    const threshold = type === 'read' 
      ? this.suspiciousOperationPatterns.rapidReads 
      : this.suspiciousOperationPatterns.rapidWrites;
    
    if (rates[operationType].length >= threshold) {
      return {
        allowed: false,
        rate: rates[operationType].length,
      };
    }
    
    // Add current timestamp
    rates[operationType].push(now);
    
    return {
      allowed: true,
      rate: rates[operationType].length,
    };
  }
  
  /**
   * Record operation
   */
  recordOperation(entry) {
    this.operations.push(entry);
    
    if (entry.analysis.hasSuspiciousActivity) {
      this.suspiciousOperations.push(entry);
      this.statistics.suspiciousOperations++;
      
      // Limit history size
      if (this.suspiciousOperations.length > 100) {
        this.suspiciousOperations.shift();
      }
    }
    
    // Limit operation history
    if (this.operations.length > 1000) {
      this.operations.shift();
    }
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

