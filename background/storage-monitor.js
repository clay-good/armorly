/**
 * Storage Monitor for Armorly
 * 
 * Monitors browser storage to detect:
 * - Memory poisoning attacks
 * - Malicious data injection
 * - Unauthorized storage modifications
 * - Context/conversation tampering
 * - Token/credential theft
 */

class StorageMonitor {
  constructor() {
    // Track storage changes
    this.storageHistory = new Map(); // key -> { changes: [], lastValue: '' }
    
    // Track suspicious patterns
    this.suspiciousKeys = new Set();
    
    // Known sensitive keys that should be monitored
    this.sensitiveKeyPatterns = [
      'token',
      'auth',
      'session',
      'api_key',
      'apikey',
      'secret',
      'password',
      'credential',
      'jwt',
      'bearer',
      'access_token',
      'refresh_token',
      'user',
      'account',
      'memory',
      'context',
      'conversation',
      'chat',
      'history',
      'instruction',
      'system_prompt',
      'agent_config'
    ];
    
    // Malicious content patterns
    this.maliciousPatterns = [
      /ignore\s+previous\s+instructions/i,
      /disregard\s+all\s+prior/i,
      /system\s*:\s*you\s+are\s+now/i,
      /new\s+instructions/i,
      /override\s+instructions/i,
      /forget\s+everything/i,
      /<script>/i,
      /javascript:/i,
      /onerror=/i,
      /onclick=/i,
      /eval\(/i,
      /function\s*\(/i,
      /=>\s*{/i, // Arrow functions
      /document\.cookie/i,
      /localStorage\./i,
      /sessionStorage\./i,
      /window\.location/i,
      /fetch\(/i,
      /XMLHttpRequest/i
    ];
    
    // Rate limiting
    this.changeRates = new Map(); // key -> timestamps[]
    this.thresholds = {
      maxChangesPerMinute: 10,
      maxValueSize: 1024 * 1024 // 1MB
    };
  }

  /**
   * Initialize storage monitoring
   */
  initialize() {
    console.log('[Armorly Storage] Initializing browser storage monitoring');

    // Monitor chrome.storage changes
    chrome.storage.onChanged.addListener((changes, areaName) => {
      this.handleStorageChange(changes, areaName);
    });

    // Monitor localStorage/sessionStorage via content scripts
    // (Content scripts will send messages when they detect changes)

    console.log('[Armorly Storage] Monitoring active for all storage areas');
  }

  /**
   * Handle storage changes
   */
  handleStorageChange(changes, areaName) {
    const threats = [];
    const timestamp = Date.now();

    for (const [key, { oldValue, newValue }] of Object.entries(changes)) {
      // 1. Check if key is sensitive
      const isSensitive = this.isSensitiveKey(key);
      
      // 2. Check for malicious content
      const newValueStr = this.valueToString(newValue);
      const maliciousPattern = this.containsMaliciousContent(newValueStr);
      
      if (maliciousPattern) {
        threats.push({
          type: 'STORAGE_INJECTION',
          severity: 'CRITICAL',
          description: `Malicious content detected in storage key: ${key}`,
          key,
          areaName,
          pattern: maliciousPattern,
          value: this.truncateValue(newValueStr)
        });
      }

      // 3. Check for prompt injection in memory/context keys
      if (this.isMemoryKey(key)) {
        const injectionDetected = this.detectPromptInjection(newValueStr);
        if (injectionDetected) {
          threats.push({
            type: 'MEMORY_POISONING',
            severity: 'CRITICAL',
            description: `Prompt injection detected in memory storage: ${key}`,
            key,
            areaName,
            value: this.truncateValue(newValueStr)
          });
        }
      }

      // 4. Check for credential theft
      if (isSensitive && newValue && !oldValue) {
        threats.push({
          type: 'CREDENTIAL_STORAGE',
          severity: 'HIGH',
          description: `Sensitive data stored: ${key}`,
          key,
          areaName
        });
      }

      // 5. Check for excessive storage changes (rate limiting)
      this.trackChangeRate(key);
      const rateLimit = this.checkChangeRate(key);
      if (rateLimit.exceeded) {
        threats.push({
          type: 'EXCESSIVE_STORAGE_CHANGES',
          severity: 'MEDIUM',
          description: `Excessive changes to storage key: ${key} (${rateLimit.count} changes/min)`,
          key,
          areaName,
          count: rateLimit.count
        });
      }

      // 6. Check for large values (potential data exfiltration staging)
      if (newValueStr.length > this.thresholds.maxValueSize) {
        threats.push({
          type: 'LARGE_STORAGE_VALUE',
          severity: 'MEDIUM',
          description: `Large value stored in ${key}: ${(newValueStr.length / 1024).toFixed(2)}KB`,
          key,
          areaName,
          size: newValueStr.length
        });
      }

      // 7. Track history
      this.trackHistory(key, oldValue, newValue, timestamp);
    }

    // Report threats if found
    if (threats.length > 0) {
      this.reportThreats(areaName, threats);
    }
  }

  /**
   * Handle localStorage/sessionStorage changes from content scripts
   */
  handleContentStorageChange(message) {
    const { storageType, key, oldValue, newValue, url, tabId } = message;
    const threats = [];

    // Check for malicious content
    const maliciousPattern = this.containsMaliciousContent(newValue);
    if (maliciousPattern) {
      threats.push({
        type: 'LOCAL_STORAGE_INJECTION',
        severity: 'HIGH',
        description: `Malicious content in ${storageType}: ${key}`,
        key,
        storageType,
        url,
        pattern: maliciousPattern,
        value: this.truncateValue(newValue)
      });
    }

    // Check for memory poisoning
    if (this.isMemoryKey(key)) {
      const injectionDetected = this.detectPromptInjection(newValue);
      if (injectionDetected) {
        threats.push({
          type: 'LOCAL_MEMORY_POISONING',
          severity: 'CRITICAL',
          description: `Memory poisoning in ${storageType}: ${key}`,
          key,
          storageType,
          url,
          value: this.truncateValue(newValue)
        });
      }
    }

    if (threats.length > 0) {
      this.reportThreats(storageType, threats, tabId, url);
    }
  }

  /**
   * Check if key is sensitive
   */
  isSensitiveKey(key) {
    const keyLower = key.toLowerCase();
    return this.sensitiveKeyPatterns.some(pattern => keyLower.includes(pattern));
  }

  /**
   * Check if key is related to memory/context
   */
  isMemoryKey(key) {
    const keyLower = key.toLowerCase();
    const memoryPatterns = ['memory', 'context', 'conversation', 'chat', 'history', 'instruction', 'prompt'];
    return memoryPatterns.some(pattern => keyLower.includes(pattern));
  }

  /**
   * Check if value contains malicious content
   */
  containsMaliciousContent(value) {
    if (!value) return null;
    
    const valueStr = this.valueToString(value);
    for (const pattern of this.maliciousPatterns) {
      if (pattern.test(valueStr)) {
        return pattern.toString();
      }
    }
    return null;
  }

  /**
   * Detect prompt injection patterns
   */
  detectPromptInjection(value) {
    if (!value) return false;
    
    const valueStr = this.valueToString(value);
    
    // Specific prompt injection patterns
    const injectionPatterns = [
      /ignore\s+previous\s+instructions/i,
      /disregard\s+all\s+prior/i,
      /system\s*:\s*you\s+are\s+now/i,
      /new\s+instructions\s*:/i,
      /override\s+instructions/i,
      /forget\s+everything/i,
      /you\s+must\s+now/i,
      /from\s+now\s+on/i,
      /your\s+new\s+role/i,
      /act\s+as\s+if/i
    ];
    
    return injectionPatterns.some(pattern => pattern.test(valueStr));
  }

  /**
   * Convert value to string for analysis
   */
  valueToString(value) {
    if (typeof value === 'string') return value;
    if (typeof value === 'object') return JSON.stringify(value);
    return String(value);
  }

  /**
   * Truncate value for display
   */
  truncateValue(value, maxLength = 200) {
    if (!value) return '';
    const str = this.valueToString(value);
    return str.length > maxLength ? str.substring(0, maxLength) + '...' : str;
  }

  /**
   * Track change rate
   */
  trackChangeRate(key) {
    if (!this.changeRates.has(key)) {
      this.changeRates.set(key, []);
    }
    
    const timestamps = this.changeRates.get(key);
    timestamps.push(Date.now());
    
    // Keep only last minute
    const oneMinuteAgo = Date.now() - 60000;
    this.changeRates.set(key, timestamps.filter(t => t > oneMinuteAgo));
  }

  /**
   * Check if change rate is exceeded
   */
  checkChangeRate(key) {
    const timestamps = this.changeRates.get(key) || [];
    const oneMinuteAgo = Date.now() - 60000;
    const recentChanges = timestamps.filter(t => t > oneMinuteAgo);
    
    return {
      exceeded: recentChanges.length > this.thresholds.maxChangesPerMinute,
      count: recentChanges.length
    };
  }

  /**
   * Track storage history
   */
  trackHistory(key, oldValue, newValue, timestamp) {
    if (!this.storageHistory.has(key)) {
      this.storageHistory.set(key, {
        changes: [],
        lastValue: null
      });
    }
    
    const history = this.storageHistory.get(key);
    history.changes.push({
      oldValue,
      newValue,
      timestamp
    });
    history.lastValue = newValue;
    
    // Keep only last 10 changes
    if (history.changes.length > 10) {
      history.changes = history.changes.slice(-10);
    }
  }

  /**
   * Report threats to service worker
   * Note: This is called from within the service worker, so we'll use a callback
   */
  reportThreats(areaName, threats, tabId = null, url = null) {
    console.log(`[Armorly Storage] Reporting ${threats.length} threats from ${areaName}`);

    // Call the callback if it exists (set by service worker)
    if (this.onThreatsDetected) {
      this.onThreatsDetected({
        areaName,
        threats,
        tabId,
        url,
        timestamp: Date.now()
      });
    }
  }

  /**
   * Set callback for threat detection
   */
  setThreatCallback(callback) {
    this.onThreatsDetected = callback;
  }

  /**
   * Get statistics
   */
  getStatistics() {
    return {
      monitoredKeys: this.storageHistory.size,
      suspiciousKeys: this.suspiciousKeys.size,
      totalChanges: Array.from(this.storageHistory.values())
        .reduce((sum, h) => sum + h.changes.length, 0)
    };
  }

  /**
   * Get history for a key
   */
  getHistory(key) {
    return this.storageHistory.get(key) || { changes: [], lastValue: null };
  }
}

// Export for ES6 modules
export { StorageMonitor };
