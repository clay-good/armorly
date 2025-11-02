/**
 * Storage Manager for Armorly
 * 
 * Centralized storage handling with:
 * - Type-safe storage operations
 * - Data validation
 * - Migration support
 * - Quota management
 * - Backup/restore functionality
 * 
 * @module storage-manager
 * @author Armorly Security Team
 * @license MIT
 */

class StorageManager {
  constructor() {
    this.version = '1.0.0';
    this.storageArea = chrome.storage.local;
    
    /**
     * Storage keys
     */
    this.keys = {
      SETTINGS: 'settings',
      THREAT_LOG: 'threatLog',
      STATISTICS: 'statistics',
      WHITELIST: 'whitelist',
      BLACKLIST: 'blacklist',
      MEMORY_AUDIT_LOG: 'memoryAuditLog',
      USER_ACTIONS: 'userActions',
      VERSION: 'storageVersion'
    };

    /**
     * Default values
     */
    this.defaults = {
      settings: {
        protectionEnabled: true,
        autoBlock: true,
        showNotifications: true,
        sensitivityLevel: 'balanced',
        whitelistedDomains: [],
        blacklistedDomains: [],
        memoryAuditFrequency: 'weekly',
        enableDOMScanning: true,
        enableCSRFProtection: true,
        enableMemoryMonitoring: true
      },
      threatLog: [],
      statistics: {
        totalThreatsBlocked: 0,
        threatsByType: {},
        lastThreatDetected: null,
        protectionStartDate: Date.now(),
        pagesScanned: 0,
        threatsDetectedToday: 0,
        lastResetDate: Date.now()
      },
      whitelist: [],
      blacklist: [],
      memoryAuditLog: [],
      userActions: []
    };
  }

  /**
   * Initialize storage with default values
   * 
   * @returns {Promise<void>}
   */
  async initialize() {
    try {
      const currentVersion = await this.get(this.keys.VERSION);
      
      if (!currentVersion) {
        // First time initialization
        console.log('[Armorly] Initializing storage for the first time');
        await this.setDefaults();
        await this.set(this.keys.VERSION, this.version);
      } else if (currentVersion !== this.version) {
        // Migration needed
        console.log(`[Armorly] Migrating storage from ${currentVersion} to ${this.version}`);
        await this.migrate(currentVersion, this.version);
      }

      console.log('[Armorly] Storage initialized successfully');
    } catch (error) {
      console.error('[Armorly] Storage initialization failed:', error);
      throw error;
    }
  }

  /**
   * Set default values for all keys
   * 
   * @returns {Promise<void>}
   */
  async setDefaults() {
    const data = {};
    
    for (const [key, value] of Object.entries(this.defaults)) {
      data[key] = value;
    }

    await this.storageArea.set(data);
  }

  /**
   * Get value from storage
   * 
   * @param {string} key - Storage key
   * @param {*} defaultValue - Default value if key doesn't exist
   * @returns {Promise<*>} Stored value or default
   */
  async get(key, defaultValue = null) {
    try {
      const result = await this.storageArea.get(key);
      return result[key] !== undefined ? result[key] : defaultValue;
    } catch (error) {
      console.error(`[Armorly] Error getting ${key}:`, error);
      return defaultValue;
    }
  }

  /**
   * Get multiple values from storage
   * 
   * @param {Array<string>} keys - Array of storage keys
   * @returns {Promise<Object>} Object with key-value pairs
   */
  async getMultiple(keys) {
    try {
      return await this.storageArea.get(keys);
    } catch (error) {
      console.error('[Armorly] Error getting multiple keys:', error);
      return {};
    }
  }

  /**
   * Set value in storage
   * 
   * @param {string} key - Storage key
   * @param {*} value - Value to store
   * @returns {Promise<void>}
   */
  async set(key, value) {
    try {
      await this.storageArea.set({ [key]: value });
    } catch (error) {
      console.error(`[Armorly] Error setting ${key}:`, error);
      throw error;
    }
  }

  /**
   * Set multiple values in storage
   * 
   * @param {Object} data - Object with key-value pairs
   * @returns {Promise<void>}
   */
  async setMultiple(data) {
    try {
      await this.storageArea.set(data);
    } catch (error) {
      console.error('[Armorly] Error setting multiple keys:', error);
      throw error;
    }
  }

  /**
   * Remove value from storage
   * 
   * @param {string} key - Storage key
   * @returns {Promise<void>}
   */
  async remove(key) {
    try {
      await this.storageArea.remove(key);
    } catch (error) {
      console.error(`[Armorly] Error removing ${key}:`, error);
      throw error;
    }
  }

  /**
   * Clear all storage
   * 
   * @returns {Promise<void>}
   */
  async clear() {
    try {
      await this.storageArea.clear();
      await this.setDefaults();
    } catch (error) {
      console.error('[Armorly] Error clearing storage:', error);
      throw error;
    }
  }

  /**
   * Get current settings
   * 
   * @returns {Promise<Object>} Settings object
   */
  async getSettings() {
    return await this.get(this.keys.SETTINGS, this.defaults.settings);
  }

  /**
   * Update settings
   * 
   * @param {Object} updates - Settings to update
   * @returns {Promise<void>}
   */
  async updateSettings(updates) {
    const current = await this.getSettings();
    const updated = { ...current, ...updates };
    await this.set(this.keys.SETTINGS, updated);
  }

  /**
   * Get threat log
   * 
   * @param {number} limit - Maximum number of entries to return
   * @returns {Promise<Array>} Threat log entries
   */
  async getThreatLog(limit = null) {
    const log = await this.get(this.keys.THREAT_LOG, []);
    return limit ? log.slice(0, limit) : log;
  }

  /**
   * Add threat to log
   * 
   * @param {Object} threat - Threat entry
   * @returns {Promise<void>}
   */
  async addThreat(threat) {
    const log = await this.getThreatLog();
    log.unshift(threat);
    
    // Keep only last 1000 entries
    if (log.length > 1000) {
      log.splice(1000);
    }

    await this.set(this.keys.THREAT_LOG, log);
  }

  /**
   * Clear threat log
   * 
   * @returns {Promise<void>}
   */
  async clearThreatLog() {
    await this.set(this.keys.THREAT_LOG, []);
  }

  /**
   * Get statistics
   * 
   * @returns {Promise<Object>} Statistics object
   */
  async getStatistics() {
    return await this.get(this.keys.STATISTICS, this.defaults.statistics);
  }

  /**
   * Update statistics
   * 
   * @param {Object} updates - Statistics to update
   * @returns {Promise<void>}
   */
  async updateStatistics(updates) {
    const current = await this.getStatistics();
    const updated = { ...current, ...updates };
    await this.set(this.keys.STATISTICS, updated);
  }

  /**
   * Increment threat counter
   * 
   * @param {string} threatType - Type of threat
   * @returns {Promise<void>}
   */
  async incrementThreatCounter(threatType) {
    const stats = await this.getStatistics();
    stats.totalThreatsBlocked++;
    stats.threatsDetectedToday++;
    stats.lastThreatDetected = Date.now();
    
    if (!stats.threatsByType[threatType]) {
      stats.threatsByType[threatType] = 0;
    }
    stats.threatsByType[threatType]++;

    await this.set(this.keys.STATISTICS, stats);
  }

  /**
   * Get storage usage information
   * 
   * @returns {Promise<Object>} Storage usage stats
   */
  async getStorageUsage() {
    try {
      const bytesInUse = await this.storageArea.getBytesInUse();
      const quota = chrome.storage.local.QUOTA_BYTES || 10485760; // 10MB default
      
      return {
        bytesInUse,
        quota,
        percentUsed: (bytesInUse / quota) * 100,
        available: quota - bytesInUse
      };
    } catch (error) {
      console.error('[Armorly] Error getting storage usage:', error);
      return null;
    }
  }

  /**
   * Export all data for backup
   * 
   * @returns {Promise<Object>} All stored data
   */
  async exportData() {
    try {
      const data = await this.storageArea.get(null);
      return {
        version: this.version,
        exportDate: Date.now(),
        data: data
      };
    } catch (error) {
      console.error('[Armorly] Error exporting data:', error);
      throw error;
    }
  }

  /**
   * Import data from backup
   * 
   * @param {Object} backup - Backup data
   * @returns {Promise<void>}
   */
  async importData(backup) {
    try {
      if (!backup.data) {
        throw new Error('Invalid backup format');
      }

      await this.storageArea.clear();
      await this.storageArea.set(backup.data);
      
      console.log('[Armorly] Data imported successfully');
    } catch (error) {
      console.error('[Armorly] Error importing data:', error);
      throw error;
    }
  }

  /**
   * Migrate storage between versions
   * 
   * @param {string} fromVersion - Current version
   * @param {string} toVersion - Target version
   * @returns {Promise<void>}
   */
  async migrate(fromVersion, toVersion) {
    console.log(`[Armorly] Migrating from ${fromVersion} to ${toVersion}`);
    
    // Add migration logic here as needed
    // For now, just update the version
    await this.set(this.keys.VERSION, toVersion);
  }
}

// Export for use in other modules
export { StorageManager };
