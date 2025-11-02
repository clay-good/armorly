/**
 * Armorly - User Consent Manager
 * 
 * Manages user consent for sensitive AI agent actions across all
 * chromium-based agentic browsers. Provides granular control over
 * what AI agents can do on behalf of the user.
 * 
 * Features:
 * - Consent prompts for sensitive actions
 * - Remember user preferences
 * - Granular permission control
 * - Domain-specific rules
 * - Action whitelisting/blacklisting
 */

export class ConsentManager {
  constructor() {
    // Consent rules
    this.rules = {
      navigation: {
        requireConsent: true,
        exceptions: [], // Whitelisted domains
        alwaysBlock: [], // Blacklisted domains
      },
      formSubmission: {
        requireConsent: true,
        exceptions: [],
        alwaysBlock: [],
      },
      credentialAccess: {
        requireConsent: true,
        exceptions: [],
        alwaysBlock: [],
      },
      storageModification: {
        requireConsent: true,
        exceptions: [],
        alwaysBlock: [],
      },
      dataTransfer: {
        requireConsent: true,
        exceptions: [],
        alwaysBlock: [],
        sizeThreshold: 10000, // Bytes
      },
      fileAccess: {
        requireConsent: true,
        exceptions: [],
        alwaysBlock: [],
      },
      clipboardAccess: {
        requireConsent: true,
        exceptions: [],
        alwaysBlock: [],
      },
    };

    // Consent history
    this.history = [];

    // Pending consent requests
    this.pendingRequests = new Map();

    // Load saved rules
    this.loadRules();
  }

  /**
   * Request consent for an action
   * @param {Object} action - Action details
   * @returns {Promise<boolean>} - Whether consent was granted
   */
  async requestConsent(action) {
    const { type, domain, details } = action;

    // Check if action is always blocked
    if (this.isAlwaysBlocked(type, domain)) {
      this.recordDecision(action, false, 'ALWAYS_BLOCKED');
      return false;
    }

    // Check if action is whitelisted
    if (this.isWhitelisted(type, domain)) {
      this.recordDecision(action, true, 'WHITELISTED');
      return true;
    }

    // Check if consent is required
    const rule = this.rules[type];
    if (!rule || !rule.requireConsent) {
      this.recordDecision(action, true, 'NO_CONSENT_REQUIRED');
      return true;
    }

    // Check size threshold for data transfers
    if (type === 'dataTransfer' && details?.size < rule.sizeThreshold) {
      this.recordDecision(action, true, 'BELOW_THRESHOLD');
      return true;
    }

    // Request consent from user
    return await this.promptUser(action);
  }

  /**
   * Check if action is always blocked
   */
  isAlwaysBlocked(type, domain) {
    const rule = this.rules[type];
    if (!rule) return false;

    return rule.alwaysBlock.some(pattern => this.matchesDomain(domain, pattern));
  }

  /**
   * Check if action is whitelisted
   */
  isWhitelisted(type, domain) {
    const rule = this.rules[type];
    if (!rule) return false;

    return rule.exceptions.some(pattern => this.matchesDomain(domain, pattern));
  }

  /**
   * Match domain against pattern
   */
  matchesDomain(domain, pattern) {
    if (!domain || !pattern) return false;

    // Exact match
    if (domain === pattern) return true;

    // Wildcard match
    if (pattern.startsWith('*.')) {
      const baseDomain = pattern.slice(2);
      return domain.endsWith(baseDomain);
    }

    return false;
  }

  /**
   * Prompt user for consent
   */
  async promptUser(action) {
    const requestId = `${Date.now()}_${Math.random()}`;

    // Create promise for user response
    const promise = new Promise((resolve) => {
      this.pendingRequests.set(requestId, { action, resolve });
    });

    // Send message to popup/UI to show consent dialog
    try {
      chrome.runtime.sendMessage({
        type: 'CONSENT_REQUEST',
        requestId,
        action,
      });
    } catch (error) {
      console.error('[ConsentManager] Failed to send consent request:', error);
      // Default to deny if can't show prompt
      this.pendingRequests.delete(requestId);
      this.recordDecision(action, false, 'PROMPT_FAILED');
      return false;
    }

    // Timeout after 30 seconds
    const timeout = setTimeout(() => {
      if (this.pendingRequests.has(requestId)) {
        this.handleConsentResponse(requestId, false, 'TIMEOUT');
      }
    }, 30000);

    const granted = await promise;
    clearTimeout(timeout);

    return granted;
  }

  /**
   * Handle consent response from user
   */
  handleConsentResponse(requestId, granted, remember = false, scope = 'once') {
    const request = this.pendingRequests.get(requestId);
    if (!request) return;

    const { action, resolve } = request;

    // Record decision
    this.recordDecision(action, granted, remember ? `REMEMBERED_${scope.toUpperCase()}` : 'USER_DECISION');

    // Update rules if user wants to remember
    if (remember && granted) {
      this.addException(action.type, action.domain, scope);
    } else if (remember && !granted) {
      this.addBlock(action.type, action.domain, scope);
    }

    // Resolve promise
    resolve(granted);

    // Clean up
    this.pendingRequests.delete(requestId);
  }

  /**
   * Add exception (whitelist)
   */
  addException(type, domain, scope = 'domain') {
    const rule = this.rules[type];
    if (!rule) return;

    const pattern = scope === 'domain' ? domain : `*.${this.getBaseDomain(domain)}`;
    
    if (!rule.exceptions.includes(pattern)) {
      rule.exceptions.push(pattern);
      this.saveRules();
    }
  }

  /**
   * Add block (blacklist)
   */
  addBlock(type, domain, scope = 'domain') {
    const rule = this.rules[type];
    if (!rule) return;

    const pattern = scope === 'domain' ? domain : `*.${this.getBaseDomain(domain)}`;
    
    if (!rule.alwaysBlock.includes(pattern)) {
      rule.alwaysBlock.push(pattern);
      this.saveRules();
    }
  }

  /**
   * Get base domain from full domain
   */
  getBaseDomain(domain) {
    if (!domain) return '';
    
    const parts = domain.split('.');
    if (parts.length <= 2) return domain;
    
    return parts.slice(-2).join('.');
  }

  /**
   * Record consent decision
   */
  recordDecision(action, granted, reason) {
    this.history.push({
      timestamp: Date.now(),
      action,
      granted,
      reason,
    });

    // Limit history to last 1000 decisions
    if (this.history.length > 1000) {
      this.history = this.history.slice(-1000);
    }
  }

  /**
   * Remove exception
   */
  removeException(type, pattern) {
    const rule = this.rules[type];
    if (!rule) return;

    rule.exceptions = rule.exceptions.filter(p => p !== pattern);
    this.saveRules();
  }

  /**
   * Remove block
   */
  removeBlock(type, pattern) {
    const rule = this.rules[type];
    if (!rule) return;

    rule.alwaysBlock = rule.alwaysBlock.filter(p => p !== pattern);
    this.saveRules();
  }

  /**
   * Set consent requirement for action type
   */
  setConsentRequirement(type, required) {
    const rule = this.rules[type];
    if (!rule) return;

    rule.requireConsent = required;
    this.saveRules();
  }

  /**
   * Get consent statistics
   */
  getStatistics() {
    const total = this.history.length;
    const granted = this.history.filter(h => h.granted).length;
    const denied = total - granted;

    const byType = {};
    for (const entry of this.history) {
      const type = entry.action.type;
      if (!byType[type]) {
        byType[type] = { total: 0, granted: 0, denied: 0 };
      }
      byType[type].total++;
      if (entry.granted) {
        byType[type].granted++;
      } else {
        byType[type].denied++;
      }
    }

    return {
      total,
      granted,
      denied,
      grantRate: total > 0 ? (granted / total * 100).toFixed(1) : 0,
      byType,
    };
  }

  /**
   * Get recent decisions
   */
  getRecentDecisions(limit = 20) {
    return this.history.slice(-limit).reverse();
  }

  /**
   * Get all rules
   */
  getRules() {
    return JSON.parse(JSON.stringify(this.rules));
  }

  /**
   * Save rules to storage
   */
  async saveRules() {
    try {
      await chrome.storage.local.set({
        consentRules: this.rules,
      });
    } catch (error) {
      console.error('[ConsentManager] Failed to save rules:', error);
    }
  }

  /**
   * Load rules from storage
   */
  async loadRules() {
    try {
      const result = await chrome.storage.local.get('consentRules');
      if (result.consentRules) {
        // Merge with defaults to ensure all rule types exist
        this.rules = {
          ...this.rules,
          ...result.consentRules,
        };
      }
    } catch (error) {
      console.error('[ConsentManager] Failed to load rules:', error);
    }
  }

  /**
   * Reset all rules to defaults
   */
  async resetRules() {
    for (const rule of Object.values(this.rules)) {
      rule.exceptions = [];
      rule.alwaysBlock = [];
      rule.requireConsent = true;
    }
    await this.saveRules();
  }

  /**
   * Export rules
   */
  exportRules() {
    return JSON.stringify(this.rules, null, 2);
  }

  /**
   * Import rules
   */
  async importRules(rulesJson) {
    try {
      const imported = JSON.parse(rulesJson);
      this.rules = {
        ...this.rules,
        ...imported,
      };
      await this.saveRules();
      return true;
    } catch (error) {
      console.error('[ConsentManager] Failed to import rules:', error);
      return false;
    }
  }
}

