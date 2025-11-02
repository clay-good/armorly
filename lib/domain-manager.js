/**
 * Domain Manager for Armorly
 * 
 * Manages whitelist and blacklist of domains for customized protection
 * 
 * @module domain-manager
 * @author Armorly Security Team
 * @license MIT
 */

export class DomainManager {
  constructor() {
    /**
     * Whitelist - domains that are always trusted
     */
    this.whitelist = new Set();

    /**
     * Blacklist - domains that are always blocked
     */
    this.blacklist = new Set();

    /**
     * Default trusted domains (can't be removed)
     */
    this.defaultTrusted = new Set([
      'chatgpt.com',
      'openai.com',
      'perplexity.ai',
      'anthropic.com',
      'claude.ai',
      'google.com',
      'github.com',
      'stackoverflow.com'
    ]);

    /**
     * Load saved lists from storage
     */
    this.loadFromStorage();
  }

  /**
   * Load whitelist and blacklist from storage
   * 
   * @returns {Promise<void>}
   */
  async loadFromStorage() {
    try {
      const data = await chrome.storage.local.get(['whitelist', 'blacklist']);
      
      if (data.whitelist && Array.isArray(data.whitelist)) {
        this.whitelist = new Set(data.whitelist);
      }
      
      if (data.blacklist && Array.isArray(data.blacklist)) {
        this.blacklist = new Set(data.blacklist);
      }

      console.log('[Armorly] Domain lists loaded:', {
        whitelist: this.whitelist.size,
        blacklist: this.blacklist.size
      });
    } catch (error) {
      console.error('[Armorly] Error loading domain lists:', error);
    }
  }

  /**
   * Save whitelist and blacklist to storage
   * 
   * @returns {Promise<void>}
   */
  async saveToStorage() {
    try {
      await chrome.storage.local.set({
        whitelist: Array.from(this.whitelist),
        blacklist: Array.from(this.blacklist)
      });
      
      console.log('[Armorly] Domain lists saved');
    } catch (error) {
      console.error('[Armorly] Error saving domain lists:', error);
    }
  }

  /**
   * Add domain to whitelist
   * 
   * @param {string} domain - Domain to whitelist
   * @returns {Promise<boolean>} Success status
   */
  async addToWhitelist(domain) {
    const normalized = this.normalizeDomain(domain);
    
    if (!normalized) {
      return false;
    }

    // Remove from blacklist if present
    this.blacklist.delete(normalized);
    
    // Add to whitelist
    this.whitelist.add(normalized);
    
    await this.saveToStorage();
    return true;
  }

  /**
   * Add domain to blacklist
   * 
   * @param {string} domain - Domain to blacklist
   * @returns {Promise<boolean>} Success status
   */
  async addToBlacklist(domain) {
    const normalized = this.normalizeDomain(domain);
    
    if (!normalized) {
      return false;
    }

    // Can't blacklist default trusted domains
    if (this.defaultTrusted.has(normalized)) {
      console.warn('[Armorly] Cannot blacklist default trusted domain:', normalized);
      return false;
    }

    // Remove from whitelist if present
    this.whitelist.delete(normalized);
    
    // Add to blacklist
    this.blacklist.add(normalized);
    
    await this.saveToStorage();
    return true;
  }

  /**
   * Remove domain from whitelist
   * 
   * @param {string} domain - Domain to remove
   * @returns {Promise<boolean>} Success status
   */
  async removeFromWhitelist(domain) {
    const normalized = this.normalizeDomain(domain);
    
    if (!normalized) {
      return false;
    }

    this.whitelist.delete(normalized);
    await this.saveToStorage();
    return true;
  }

  /**
   * Remove domain from blacklist
   * 
   * @param {string} domain - Domain to remove
   * @returns {Promise<boolean>} Success status
   */
  async removeFromBlacklist(domain) {
    const normalized = this.normalizeDomain(domain);
    
    if (!normalized) {
      return false;
    }

    this.blacklist.delete(normalized);
    await this.saveToStorage();
    return true;
  }

  /**
   * Check if domain is whitelisted
   * 
   * @param {string} url - URL or domain to check
   * @returns {boolean} True if whitelisted
   */
  isWhitelisted(url) {
    const domain = this.extractDomain(url);
    
    if (!domain) {
      return false;
    }

    // Check default trusted domains
    if (this.defaultTrusted.has(domain)) {
      return true;
    }

    // Check whitelist
    if (this.whitelist.has(domain)) {
      return true;
    }

    // Check for subdomain matches
    for (const whitelisted of this.whitelist) {
      if (domain.endsWith('.' + whitelisted)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if domain is blacklisted
   * 
   * @param {string} url - URL or domain to check
   * @returns {boolean} True if blacklisted
   */
  isBlacklisted(url) {
    const domain = this.extractDomain(url);
    
    if (!domain) {
      return false;
    }

    // Check blacklist
    if (this.blacklist.has(domain)) {
      return true;
    }

    // Check for subdomain matches
    for (const blacklisted of this.blacklist) {
      if (domain.endsWith('.' + blacklisted)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Get protection level for domain
   * 
   * @param {string} url - URL to check
   * @returns {string} 'trusted', 'blocked', or 'normal'
   */
  getProtectionLevel(url) {
    if (this.isBlacklisted(url)) {
      return 'blocked';
    }
    
    if (this.isWhitelisted(url)) {
      return 'trusted';
    }
    
    return 'normal';
  }

  /**
   * Extract domain from URL
   * 
   * @param {string} url - URL to parse
   * @returns {string|null} Domain or null if invalid
   */
  extractDomain(url) {
    try {
      // If it's already a domain (no protocol), add one
      if (!url.includes('://')) {
        url = 'https://' + url;
      }
      
      const urlObj = new URL(url);
      return urlObj.hostname.toLowerCase();
    } catch (error) {
      return null;
    }
  }

  /**
   * Normalize domain (remove www, lowercase, etc.)
   * 
   * @param {string} domain - Domain to normalize
   * @returns {string|null} Normalized domain or null if invalid
   */
  normalizeDomain(domain) {
    const extracted = this.extractDomain(domain);
    
    if (!extracted) {
      return null;
    }

    // Remove www prefix
    return extracted.replace(/^www\./, '');
  }

  /**
   * Export lists to JSON
   * 
   * @returns {string} JSON string of lists
   */
  exportLists() {
    return JSON.stringify({
      version: '1.0',
      exported: Date.now(),
      whitelist: Array.from(this.whitelist),
      blacklist: Array.from(this.blacklist)
    }, null, 2);
  }

  /**
   * Import lists from JSON
   * 
   * @param {string} jsonString - JSON string to import
   * @returns {Promise<Object>} Import result
   */
  async importLists(jsonString) {
    try {
      const data = JSON.parse(jsonString);
      
      const result = {
        success: true,
        whitelistAdded: 0,
        blacklistAdded: 0,
        errors: []
      };

      // Import whitelist
      if (data.whitelist && Array.isArray(data.whitelist)) {
        for (const domain of data.whitelist) {
          const normalized = this.normalizeDomain(domain);
          if (normalized) {
            this.whitelist.add(normalized);
            result.whitelistAdded++;
          }
        }
      }

      // Import blacklist
      if (data.blacklist && Array.isArray(data.blacklist)) {
        for (const domain of data.blacklist) {
          const normalized = this.normalizeDomain(domain);
          if (normalized && !this.defaultTrusted.has(normalized)) {
            this.blacklist.add(normalized);
            result.blacklistAdded++;
          }
        }
      }

      await this.saveToStorage();
      return result;
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get all lists
   * 
   * @returns {Object} All domain lists
   */
  getAllLists() {
    return {
      whitelist: Array.from(this.whitelist),
      blacklist: Array.from(this.blacklist),
      defaultTrusted: Array.from(this.defaultTrusted)
    };
  }

  /**
   * Clear all custom lists (keeps default trusted)
   * 
   * @returns {Promise<void>}
   */
  async clearAllLists() {
    this.whitelist.clear();
    this.blacklist.clear();
    await this.saveToStorage();
  }
}

