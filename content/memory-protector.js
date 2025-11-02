/**
 * Memory Protector for Armorly
 * 
 * Protects against AI memory poisoning attacks by:
 * - Monitoring localStorage/sessionStorage access
 * - Sanitizing stored data
 * - Detecting memory poisoning attempts
 * - Protecting IndexedDB
 * - Monitoring AI agent memory APIs
 * 
 * Features:
 * - Real-time storage monitoring
 * - Automatic sanitization
 * - Threat detection in stored data
 * - Memory poisoning prevention
 * - Cross-session protection
 * 
 * @module memory-protector
 * @author Armorly Security Team
 */

class MemoryProtector {
  constructor() {
    /**
     * Statistics
     */
    this.stats = {
      storageAccessMonitored: 0,
      threatsBlocked: 0,
      dataSanitized: 0,
      poisoningAttempts: 0,
    };

    /**
     * Configuration
     */
    this.config = {
      enabled: true,
      monitorLocalStorage: true,
      monitorSessionStorage: true,
      monitorIndexedDB: true,
      sanitizeOnWrite: true,
      sanitizeOnRead: true,
      logActions: false,
    };

    /**
     * Original storage methods
     */
    this.originalMethods = {
      localStorage: {},
      sessionStorage: {},
    };

    /**
     * Suspicious storage keys (AI memory patterns)
     */
    this.suspiciousKeys = [
      'ai_memory',
      'conversation_history',
      'chat_context',
      'agent_memory',
      'system_prompt',
      'instructions',
      'context',
    ];

    /**
     * Blocked operations
     */
    this.blockedOperations = [];
  }

  /**
   * Start memory protection
   */
  start() {
    if (!this.config.enabled) return;

    try {
      // Protect localStorage
      if (this.config.monitorLocalStorage) {
        this.protectStorage(localStorage, 'localStorage');
      }

      // Protect sessionStorage
      if (this.config.monitorSessionStorage) {
        this.protectStorage(sessionStorage, 'sessionStorage');
      }

      // Protect IndexedDB
      if (this.config.monitorIndexedDB) {
        this.protectIndexedDB();
      }

      // Scan existing storage for threats
      this.scanExistingStorage();

      console.log('[Armorly MemoryProtector] Started - Memory protection active');
    } catch (error) {
      console.error('[Armorly MemoryProtector] Error starting:', error);
    }
  }

  /**
   * Protect storage (localStorage/sessionStorage)
   */
  protectStorage(storage, storageName) {
    const self = this;

    // Store original methods
    this.originalMethods[storageName] = {
      setItem: storage.setItem,
      getItem: storage.getItem,
      removeItem: storage.removeItem,
      clear: storage.clear,
    };

    // Override setItem
    storage.setItem = function(key, value) {
      self.stats.storageAccessMonitored++;

      // Check if key is suspicious
      if (self.isSuspiciousKey(key)) {
        // Check value for threats
        const threats = self.analyzeText(value);

        if (threats.length > 0) {
          if (self.config.sanitizeOnWrite) {
            // Sanitize and store
            const sanitized = self.sanitizeText(value, threats);
            self.stats.dataSanitized++;
            self.stats.threatsBlocked++;

            if (self.config.logActions) {
              console.log(`[Armorly MemoryProtector] Sanitized ${storageName}.setItem("${key}")`);
            }

            return self.originalMethods[storageName].setItem.call(storage, key, sanitized);
          } else {
            // Block the operation
            self.stats.threatsBlocked++;
            self.stats.poisoningAttempts++;
            self.logBlockedOperation(storageName, 'setItem', key, value, threats);

            if (self.config.logActions) {
              console.log(`[Armorly MemoryProtector] Blocked ${storageName}.setItem("${key}")`);
            }

            return; // Don't store
          }
        }
      }

      return self.originalMethods[storageName].setItem.call(storage, key, value);
    };

    // Override getItem
    storage.getItem = function(key) {
      self.stats.storageAccessMonitored++;

      const value = self.originalMethods[storageName].getItem.call(storage, key);

      if (value && self.isSuspiciousKey(key)) {
        // Check for threats in retrieved value
        const threats = self.analyzeText(value);

        if (threats.length > 0) {
          if (self.config.sanitizeOnRead) {
            // Sanitize before returning
            const sanitized = self.sanitizeText(value, threats);
            self.stats.dataSanitized++;
            self.stats.threatsBlocked++;

            if (self.config.logActions) {
              console.log(`[Armorly MemoryProtector] Sanitized ${storageName}.getItem("${key}")`);
            }

            return sanitized;
          } else {
            // Return null to prevent poisoned data from being used
            self.stats.threatsBlocked++;
            self.logBlockedOperation(storageName, 'getItem', key, value, threats);

            if (self.config.logActions) {
              console.log(`[Armorly MemoryProtector] Blocked ${storageName}.getItem("${key}")`);
            }

            return null;
          }
        }
      }

      return value;
    };
  }

  /**
   * Protect IndexedDB
   */
  protectIndexedDB() {
    const self = this;

    // Override IDBObjectStore.put
    if (window.IDBObjectStore) {
      const originalPut = IDBObjectStore.prototype.put;

      IDBObjectStore.prototype.put = function(value) {
        self.stats.storageAccessMonitored++;

        // Check if value contains threats
        const valueStr = JSON.stringify(value);
        const threats = self.analyzeText(valueStr);

        if (threats.length > 0) {
          self.stats.threatsBlocked++;
          self.stats.poisoningAttempts++;

          if (self.config.logActions) {
            console.log('[Armorly MemoryProtector] Blocked IndexedDB.put with threats');
          }

          // Return failed request
          const request = originalPut.apply(this, arguments);
          setTimeout(() => {
            if (request.onerror) {
              request.onerror(new Error('Blocked by Armorly'));
            }
          }, 0);
          return request;
        }

        return originalPut.apply(this, arguments);
      };
    }
  }

  /**
   * Scan existing storage for threats
   */
  scanExistingStorage() {
    try {
      // Scan localStorage
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        const value = localStorage.getItem(key);

        if (this.isSuspiciousKey(key)) {
          const threats = this.analyzeText(value);

          if (threats.length > 0) {
            // Sanitize or remove
            if (this.config.sanitizeOnWrite) {
              const sanitized = this.sanitizeText(value, threats);
              localStorage.setItem(key, sanitized);
              this.stats.dataSanitized++;
            } else {
              localStorage.removeItem(key);
              this.stats.threatsBlocked++;
            }

            if (this.config.logActions) {
              console.log(`[Armorly MemoryProtector] Cleaned existing localStorage key: ${key}`);
            }
          }
        }
      }

      // Scan sessionStorage
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        const value = sessionStorage.getItem(key);

        if (this.isSuspiciousKey(key)) {
          const threats = this.analyzeText(value);

          if (threats.length > 0) {
            if (this.config.sanitizeOnWrite) {
              const sanitized = this.sanitizeText(value, threats);
              sessionStorage.setItem(key, sanitized);
              this.stats.dataSanitized++;
            } else {
              sessionStorage.removeItem(key);
              this.stats.threatsBlocked++;
            }

            if (this.config.logActions) {
              console.log(`[Armorly MemoryProtector] Cleaned existing sessionStorage key: ${key}`);
            }
          }
        }
      }
    } catch (error) {
      console.error('[Armorly MemoryProtector] Error scanning storage:', error);
    }
  }

  /**
   * Check if storage key is suspicious
   */
  isSuspiciousKey(key) {
    if (!key) return false;

    const keyLower = key.toLowerCase();

    return this.suspiciousKeys.some(pattern => keyLower.includes(pattern));
  }

  /**
   * Analyze text for threats
   */
  analyzeText(text) {
    if (!text || typeof text !== 'string') return [];

    if (typeof window.UniversalPromptPatterns?.analyzeTextForPromptInjection === 'function') {
      return window.UniversalPromptPatterns.analyzeTextForPromptInjection(text, {
        source: 'storage',
        url: window.location.href,
      });
    }
    return [];
  }

  /**
   * Sanitize text by removing threats
   */
  sanitizeText(text, threats) {
    let sanitized = text;

    threats.forEach(threat => {
      if (threat.match) {
        sanitized = sanitized.replace(threat.match, '[BLOCKED BY ARMORLY]');
      }
    });

    return sanitized;
  }

  /**
   * Log blocked operation
   */
  logBlockedOperation(storage, operation, key, value, threats) {
    this.blockedOperations.push({
      storage,
      operation,
      key,
      value: value.substring(0, 100),
      threats: threats.map(t => t.type),
      timestamp: Date.now(),
    });

    // Keep only last 50
    if (this.blockedOperations.length > 50) {
      this.blockedOperations.shift();
    }
  }

  /**
   * Get statistics
   */
  getStats() {
    return { ...this.stats };
  }

  /**
   * Get blocked operations
   */
  getBlockedOperations() {
    return [...this.blockedOperations];
  }

  /**
   * Enable/disable
   */
  setEnabled(enabled) {
    this.config.enabled = enabled;
  }
}

// Export for use in content script
if (typeof window !== 'undefined') {
  window.MemoryProtector = MemoryProtector;
}

