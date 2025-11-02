/**
 * Armorly - Advanced Storage Protector
 * 
 * Encrypts sensitive data, detects memory poisoning attempts, validates
 * storage writes, and implements secure storage API across all chromium-based
 * agentic browsers.
 * 
 * Features:
 * - Sensitive data encryption
 * - Memory poisoning detection
 * - Storage write validation
 * - Secure storage API
 * - Automatic backup and recovery
 */

export class StorageProtector {
  constructor() {
    // Sensitive key patterns
    this.sensitiveKeyPatterns = [
      /password/i,
      /token/i,
      /secret/i,
      /key/i,
      /auth/i,
      /credential/i,
      /session/i,
      /cookie/i,
    ];

    // Suspicious value patterns (prompt injection in storage)
    this.suspiciousValuePatterns = [
      /ignore\s+(all\s+)?previous\s+instructions/i,
      /you\s+are\s+now/i,
      /system\s*:/i,
      /admin\s+mode/i,
      /override/i,
      /disregard/i,
    ];

    // Storage monitoring
    this.storageWrites = [];
    this.blockedWrites = [];
    this.backups = new Map();

    // Statistics
    this.statistics = {
      totalWrites: 0,
      blockedWrites: 0,
      encryptedKeys: 0,
      memoryPoisoningAttempts: 0,
      backupsCreated: 0,
    };

    // Threat callback
    this.threatCallback = null;

    // Encryption key (in production, use Web Crypto API)
    this.encryptionKey = null;

    // Initialize
    this.initialize();
  }

  /**
   * Initialize storage protector
   */
  async initialize() {
    // Generate encryption key
    await this.generateEncryptionKey();

    // Start monitoring
    this.startMonitoring();
  }

  /**
   * Generate encryption key using Web Crypto API
   */
  async generateEncryptionKey() {
    try {
      // Check if key already exists
      const stored = await chrome.storage.local.get('armorly_encryption_key');
      
      if (stored.armorly_encryption_key) {
        this.encryptionKey = await crypto.subtle.importKey(
          'jwk',
          stored.armorly_encryption_key,
          { name: 'AES-GCM', length: 256 },
          true,
          ['encrypt', 'decrypt']
        );
      } else {
        // Generate new key
        this.encryptionKey = await crypto.subtle.generateKey(
          { name: 'AES-GCM', length: 256 },
          true,
          ['encrypt', 'decrypt']
        );

        // Store key
        const exportedKey = await crypto.subtle.exportKey('jwk', this.encryptionKey);
        await chrome.storage.local.set({ armorly_encryption_key: exportedKey });
      }
    } catch (error) {
      console.error('[StorageProtector] Failed to generate encryption key:', error);
    }
  }

  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }

  /**
   * Start monitoring storage
   */
  startMonitoring() {
    // Monitor chrome.storage changes
    chrome.storage.onChanged.addListener((changes, areaName) => {
      this.handleStorageChange(changes, areaName);
    });
  }

  /**
   * Handle storage change
   */
  handleStorageChange(changes, areaName) {
    for (const [key, { oldValue, newValue }] of Object.entries(changes)) {
      // Skip Armorly's own keys
      if (key.startsWith('armorly_')) continue;

      this.statistics.totalWrites++;

      // Check for memory poisoning
      if (this.isMemoryPoisoning(key, newValue)) {
        this.handleMemoryPoisoning(key, newValue, oldValue, areaName);
      }

      // Record write
      this.storageWrites.push({
        timestamp: Date.now(),
        areaName,
        key,
        oldValue,
        newValue,
      });

      // Limit history
      if (this.storageWrites.length > 1000) {
        this.storageWrites = this.storageWrites.slice(-1000);
      }
    }
  }

  /**
   * Check if storage write is memory poisoning attempt
   */
  isMemoryPoisoning(key, value) {
    if (!value) return false;

    const valueStr = typeof value === 'string' ? value : JSON.stringify(value);

    // Check for suspicious patterns in value
    return this.suspiciousValuePatterns.some(pattern => pattern.test(valueStr));
  }

  /**
   * Handle memory poisoning attempt
   */
  handleMemoryPoisoning(key, newValue, oldValue, areaName) {
    this.statistics.memoryPoisoningAttempts++;
    this.statistics.blockedWrites++;

    const threat = {
      type: 'MEMORY_POISONING',
      severity: 'CRITICAL',
      key,
      areaName,
      timestamp: Date.now(),
      description: 'Memory poisoning attempt detected in storage',
      newValue: typeof newValue === 'string' ? newValue.substring(0, 200) : JSON.stringify(newValue).substring(0, 200),
    };

    this.blockedWrites.push(threat);
    this.reportThreat(threat);

    // Restore old value
    this.restoreValue(key, oldValue, areaName);
  }

  /**
   * Restore old value
   */
  async restoreValue(key, oldValue, areaName) {
    try {
      const storage = areaName === 'local' ? chrome.storage.local : chrome.storage.sync;
      
      if (oldValue !== undefined) {
        await storage.set({ [key]: oldValue });
      } else {
        await storage.remove(key);
      }
    } catch (error) {
      console.error('[StorageProtector] Failed to restore value:', error);
    }
  }

  /**
   * Encrypt sensitive data
   */
  async encryptData(data) {
    if (!this.encryptionKey) {
      throw new Error('Encryption key not initialized');
    }

    try {
      const encoder = new TextEncoder();
      const dataBuffer = encoder.encode(JSON.stringify(data));

      // Generate IV
      const iv = crypto.getRandomValues(new Uint8Array(12));

      // Encrypt
      const encryptedBuffer = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        this.encryptionKey,
        dataBuffer
      );

      // Combine IV and encrypted data
      const combined = new Uint8Array(iv.length + encryptedBuffer.byteLength);
      combined.set(iv, 0);
      combined.set(new Uint8Array(encryptedBuffer), iv.length);

      // Convert to base64
      return btoa(String.fromCharCode(...combined));
    } catch (error) {
      console.error('[StorageProtector] Encryption failed:', error);
      throw error;
    }
  }

  /**
   * Decrypt sensitive data
   */
  async decryptData(encryptedData) {
    if (!this.encryptionKey) {
      throw new Error('Encryption key not initialized');
    }

    try {
      // Convert from base64
      const combined = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));

      // Extract IV and encrypted data
      const iv = combined.slice(0, 12);
      const encryptedBuffer = combined.slice(12);

      // Decrypt
      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        this.encryptionKey,
        encryptedBuffer
      );

      // Decode
      const decoder = new TextDecoder();
      const decryptedStr = decoder.decode(decryptedBuffer);

      return JSON.parse(decryptedStr);
    } catch (error) {
      console.error('[StorageProtector] Decryption failed:', error);
      throw error;
    }
  }

  /**
   * Secure set (with encryption for sensitive keys)
   */
  async secureSet(key, value, areaName = 'local') {
    const storage = areaName === 'local' ? chrome.storage.local : chrome.storage.sync;

    // Check if key is sensitive
    const isSensitive = this.sensitiveKeyPatterns.some(pattern => pattern.test(key));

    if (isSensitive) {
      // Encrypt value
      const encrypted = await this.encryptData(value);
      await storage.set({ [key]: encrypted, [`${key}_encrypted`]: true });
      this.statistics.encryptedKeys++;
    } else {
      // Regular set
      await storage.set({ [key]: value });
    }

    this.statistics.totalWrites++;
  }

  /**
   * Secure get (with decryption for sensitive keys)
   */
  async secureGet(key, areaName = 'local') {
    const storage = areaName === 'local' ? chrome.storage.local : chrome.storage.sync;

    const result = await storage.get([key, `${key}_encrypted`]);

    // Check if encrypted
    if (result[`${key}_encrypted`]) {
      return await this.decryptData(result[key]);
    }

    return result[key];
  }

  /**
   * Create backup
   */
  async createBackup(areaName = 'local') {
    try {
      const storage = areaName === 'local' ? chrome.storage.local : chrome.storage.sync;
      const data = await storage.get(null);

      const backup = {
        timestamp: Date.now(),
        areaName,
        data,
      };

      this.backups.set(`${areaName}_${Date.now()}`, backup);
      this.statistics.backupsCreated++;

      // Limit backups to last 10
      if (this.backups.size > 10) {
        const oldestKey = Array.from(this.backups.keys())[0];
        this.backups.delete(oldestKey);
      }

      return backup;
    } catch (error) {
      console.error('[StorageProtector] Backup failed:', error);
      throw error;
    }
  }

  /**
   * Restore from backup
   */
  async restoreBackup(backupId) {
    const backup = this.backups.get(backupId);
    if (!backup) {
      throw new Error('Backup not found');
    }

    try {
      const storage = backup.areaName === 'local' ? chrome.storage.local : chrome.storage.sync;
      
      // Clear current storage
      await storage.clear();

      // Restore backup
      await storage.set(backup.data);

      return true;
    } catch (error) {
      console.error('[StorageProtector] Restore failed:', error);
      throw error;
    }
  }

  /**
   * Report threat
   */
  reportThreat(threat) {
    if (this.threatCallback) {
      this.threatCallback(threat);
    }
  }

  /**
   * Get statistics
   */
  getStatistics() {
    return {
      ...this.statistics,
      recentWrites: this.storageWrites.slice(-10),
      recentBlocked: this.blockedWrites.slice(-10),
      backupCount: this.backups.size,
    };
  }

  /**
   * Get recent writes
   */
  getRecentWrites(limit = 50) {
    return this.storageWrites.slice(-limit).reverse();
  }

  /**
   * Get blocked writes
   */
  getBlockedWrites(limit = 50) {
    return this.blockedWrites.slice(-limit).reverse();
  }

  /**
   * Get backups
   */
  getBackups() {
    return Array.from(this.backups.entries()).map(([id, backup]) => ({
      id,
      timestamp: backup.timestamp,
      areaName: backup.areaName,
    }));
  }

  /**
   * Reset statistics
   */
  resetStatistics() {
    this.statistics = {
      totalWrites: 0,
      blockedWrites: 0,
      encryptedKeys: 0,
      memoryPoisoningAttempts: 0,
      backupsCreated: this.backups.size,
    };
    this.storageWrites = [];
    this.blockedWrites = [];
  }
}

