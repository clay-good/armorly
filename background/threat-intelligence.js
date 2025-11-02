/**
 * Threat Intelligence System for Armorly
 * 
 * Manages updates to attack patterns and threat signatures
 * 
 * @module threat-intelligence
 * @author Armorly Security Team
 * @license MIT
 */

export class ThreatIntelligence {
  constructor(patternLibrary) {
    this.patternLibrary = patternLibrary;

    /**
     * Update configuration
     */
    this.config = {
      updateFrequency: 'weekly', // daily, weekly, manual
      lastUpdateCheck: null,
      lastSuccessfulUpdate: null,
      autoUpdate: true
    };

    /**
     * Update sources (for future implementation)
     */
    this.updateSources = [
      {
        name: 'Armorly Community',
        url: 'https://api.armorly.security/patterns/latest',
        enabled: false // Disabled until we have a real API
      }
    ];

    /**
     * Update history
     */
    this.updateHistory = [];

    // Load config from storage
    this.loadConfig();
  }

  /**
   * Load configuration from storage
   * 
   * @returns {Promise<void>}
   */
  async loadConfig() {
    try {
      const data = await chrome.storage.local.get(['threatIntelConfig']);
      
      if (data.threatIntelConfig) {
        this.config = { ...this.config, ...data.threatIntelConfig };
      }

      console.log('[Armorly] Threat intelligence config loaded');
    } catch (error) {
      console.error('[Armorly] Error loading threat intel config:', error);
    }
  }

  /**
   * Save configuration to storage
   * 
   * @returns {Promise<void>}
   */
  async saveConfig() {
    try {
      await chrome.storage.local.set({
        threatIntelConfig: this.config
      });
      
      console.log('[Armorly] Threat intelligence config saved');
    } catch (error) {
      console.error('[Armorly] Error saving threat intel config:', error);
    }
  }

  /**
   * Check for pattern updates
   * 
   * @returns {Promise<Object>} Update check result
   */
  async checkForUpdates() {
    console.log('[Armorly] Checking for threat intelligence updates...');

    const result = {
      updateAvailable: false,
      currentVersion: this.patternLibrary.version,
      latestVersion: null,
      timestamp: Date.now()
    };

    try {
      // Update last check time
      this.config.lastUpdateCheck = Date.now();
      await this.saveConfig();

      // For now, we'll use a simulated update check
      // In production, this would query a real API
      result.updateAvailable = false;
      result.latestVersion = this.patternLibrary.version;

      console.log('[Armorly] Update check complete:', result);

      return result;
    } catch (error) {
      console.error('[Armorly] Error checking for updates:', error);
      result.error = error.message;
      return result;
    }
  }

  /**
   * Apply pattern updates
   * 
   * @param {Object} updateData - Update data with new patterns
   * @returns {Promise<Object>} Update result
   */
  async applyUpdate(updateData) {
    console.log('[Armorly] Applying threat intelligence update...');

    const result = {
      success: false,
      patternsAdded: 0,
      patternsUpdated: 0,
      patternsRemoved: 0,
      timestamp: Date.now()
    };

    try {
      // Validate update data
      if (!updateData || !updateData.version || !updateData.patterns) {
        throw new Error('Invalid update data format');
      }

      // Check version compatibility
      if (this.compareVersions(updateData.version, this.patternLibrary.version) <= 0) {
        throw new Error('Update version is not newer than current version');
      }

      // Apply pattern updates
      if (updateData.patterns.add) {
        for (const [category, patterns] of Object.entries(updateData.patterns.add)) {
          if (!this.patternLibrary.patterns[category]) {
            this.patternLibrary.patterns[category] = [];
          }
          this.patternLibrary.patterns[category].push(...patterns);
          result.patternsAdded += patterns.length;
        }
      }

      // Update pattern library version
      this.patternLibrary.version = updateData.version;

      // Update config
      this.config.lastSuccessfulUpdate = Date.now();
      await this.saveConfig();

      // Add to history
      this.updateHistory.unshift({
        timestamp: Date.now(),
        version: updateData.version,
        patternsAdded: result.patternsAdded,
        patternsUpdated: result.patternsUpdated,
        patternsRemoved: result.patternsRemoved
      });

      // Keep only last 20 updates in history
      if (this.updateHistory.length > 20) {
        this.updateHistory.splice(20);
      }

      result.success = true;
      console.log('[Armorly] Update applied successfully:', result);

      return result;
    } catch (error) {
      console.error('[Armorly] Error applying update:', error);
      result.error = error.message;
      return result;
    }
  }

  /**
   * Compare version strings
   * 
   * @param {string} v1 - First version
   * @param {string} v2 - Second version
   * @returns {number} -1 if v1 < v2, 0 if equal, 1 if v1 > v2
   */
  compareVersions(v1, v2) {
    const parts1 = v1.split('.').map(Number);
    const parts2 = v2.split('.').map(Number);

    for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
      const p1 = parts1[i] || 0;
      const p2 = parts2[i] || 0;

      if (p1 > p2) return 1;
      if (p1 < p2) return -1;
    }

    return 0;
  }

  /**
   * Get update statistics
   * 
   * @returns {Object} Statistics
   */
  getStatistics() {
    return {
      currentVersion: this.patternLibrary.version,
      lastUpdateCheck: this.config.lastUpdateCheck,
      lastSuccessfulUpdate: this.config.lastSuccessfulUpdate,
      updateFrequency: this.config.updateFrequency,
      autoUpdate: this.config.autoUpdate,
      updateHistory: this.updateHistory.slice(0, 5)
    };
  }

  /**
   * Enable or disable auto-updates
   * 
   * @param {boolean} enabled - Whether to enable auto-updates
   * @returns {Promise<void>}
   */
  async setAutoUpdate(enabled) {
    this.config.autoUpdate = enabled;
    await this.saveConfig();
    console.log(`[Armorly] Auto-update ${enabled ? 'enabled' : 'disabled'}`);
  }

  /**
   * Set update frequency
   * 
   * @param {string} frequency - 'daily', 'weekly', or 'manual'
   * @returns {Promise<void>}
   */
  async setUpdateFrequency(frequency) {
    if (!['daily', 'weekly', 'manual'].includes(frequency)) {
      throw new Error('Invalid frequency. Must be daily, weekly, or manual');
    }

    this.config.updateFrequency = frequency;
    await this.saveConfig();
    console.log(`[Armorly] Update frequency set to: ${frequency}`);
  }

  /**
   * Check if update is due based on frequency setting
   * 
   * @returns {boolean} True if update check is due
   */
  isUpdateDue() {
    if (!this.config.autoUpdate) {
      return false;
    }

    if (!this.config.lastUpdateCheck) {
      return true;
    }

    const now = Date.now();
    const timeSinceLastCheck = now - this.config.lastUpdateCheck;

    switch (this.config.updateFrequency) {
      case 'daily':
        return timeSinceLastCheck > 24 * 60 * 60 * 1000; // 24 hours
      case 'weekly':
        return timeSinceLastCheck > 7 * 24 * 60 * 60 * 1000; // 7 days
      case 'manual':
        return false;
      default:
        return false;
    }
  }

  /**
   * Perform automatic update check if due
   * 
   * @returns {Promise<Object|null>} Update result or null if not due
   */
  async autoUpdateCheck() {
    if (!this.isUpdateDue()) {
      return null;
    }

    console.log('[Armorly] Automatic update check triggered');
    return await this.checkForUpdates();
  }

  /**
   * Export current pattern library
   * 
   * @returns {string} JSON string of pattern library
   */
  exportPatterns() {
    return JSON.stringify({
      version: this.patternLibrary.version,
      exported: Date.now(),
      patterns: this.patternLibrary.patterns
    }, null, 2);
  }

  /**
   * Import pattern library (for manual updates)
   * 
   * @param {string} jsonString - JSON string of patterns
   * @returns {Promise<Object>} Import result
   */
  async importPatterns(jsonString) {
    try {
      const data = JSON.parse(jsonString);
      return await this.applyUpdate(data);
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }
}

