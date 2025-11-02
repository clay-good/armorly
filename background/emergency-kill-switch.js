/**
 * Armorly - Emergency Kill Switch
 * 
 * Provides instant AI agent shutdown, rollback of malicious actions,
 * tab quarantine, and emergency recovery mode across all chromium-based
 * agentic browsers.
 * 
 * Features:
 * - Instant AI agent shutdown
 * - Malicious action rollback
 * - Tab quarantine
 * - Emergency recovery mode
 * - Automatic threat response
 */

export class EmergencyKillSwitch {
  constructor() {
    // Kill switch state
    this.state = {
      active: false,
      triggered: false,
      triggeredAt: null,
      reason: null,
      autoTriggerEnabled: true,
    };

    // Action history for rollback
    this.actionHistory = [];

    // Quarantined tabs
    this.quarantinedTabs = new Set();

    // Blocked domains
    this.blockedDomains = new Set();

    // Statistics
    this.statistics = {
      totalTriggers: 0,
      autoTriggers: 0,
      manualTriggers: 0,
      actionsRolledBack: 0,
      tabsQuarantined: 0,
    };

    // Threat threshold for auto-trigger
    this.autoTriggerThreshold = {
      criticalThreats: 3, // 3 critical threats in 1 minute
      highThreats: 10, // 10 high threats in 1 minute
      timeWindow: 60000, // 1 minute
    };

    // Recent threats for auto-trigger
    this.recentThreats = [];

    // Callback for kill switch activation
    this.activationCallback = null;
  }

  /**
   * Set activation callback
   */
  setActivationCallback(callback) {
    this.activationCallback = callback;
  }

  /**
   * Record action for potential rollback
   */
  recordAction(action) {
    this.actionHistory.push({
      ...action,
      timestamp: Date.now(),
      rolledBack: false,
    });

    // Limit history to last 1000 actions
    if (this.actionHistory.length > 1000) {
      this.actionHistory = this.actionHistory.slice(-1000);
    }
  }

  /**
   * Record threat for auto-trigger evaluation
   */
  recordThreat(threat) {
    this.recentThreats.push({
      ...threat,
      timestamp: Date.now(),
    });

    // Clean old threats
    const cutoff = Date.now() - this.autoTriggerThreshold.timeWindow;
    this.recentThreats = this.recentThreats.filter(t => t.timestamp > cutoff);

    // Check if should auto-trigger
    if (this.state.autoTriggerEnabled && !this.state.triggered) {
      this.evaluateAutoTrigger();
    }
  }

  /**
   * Evaluate if kill switch should auto-trigger
   */
  evaluateAutoTrigger() {
    const criticalCount = this.recentThreats.filter(t => t.severity === 'CRITICAL').length;
    const highCount = this.recentThreats.filter(t => t.severity === 'HIGH').length;

    if (criticalCount >= this.autoTriggerThreshold.criticalThreats) {
      this.trigger('AUTO_TRIGGER_CRITICAL', `${criticalCount} critical threats detected`);
    } else if (highCount >= this.autoTriggerThreshold.highThreats) {
      this.trigger('AUTO_TRIGGER_HIGH', `${highCount} high-severity threats detected`);
    }
  }

  /**
   * Trigger kill switch
   */
  async trigger(reason, description) {
    if (this.state.triggered) {
      console.warn('[EmergencyKillSwitch] Already triggered');
      return;
    }

    console.warn('[EmergencyKillSwitch] TRIGGERED:', reason, description);

    this.state.triggered = true;
    this.state.triggeredAt = Date.now();
    this.state.reason = reason;
    this.statistics.totalTriggers++;

    if (reason.startsWith('AUTO_TRIGGER')) {
      this.statistics.autoTriggers++;
    } else {
      this.statistics.manualTriggers++;
    }

    // Execute emergency procedures
    await this.executeEmergencyProcedures(description);

    // Notify user
    this.notifyUser(reason, description);

    // Call activation callback
    if (this.activationCallback) {
      this.activationCallback({
        reason,
        description,
        timestamp: this.state.triggeredAt,
      });
    }
  }

  /**
   * Execute emergency procedures
   */
  async executeEmergencyProcedures(description) {
    console.warn('[EmergencyKillSwitch] Executing emergency procedures...');

    // 1. Block all suspicious domains
    await this.blockSuspiciousDomains();

    // 2. Quarantine suspicious tabs
    await this.quarantineSuspiciousTabs();

    // 3. Rollback recent malicious actions
    await this.rollbackMaliciousActions();

    // 4. Clear suspicious storage
    await this.clearSuspiciousStorage();

    // 5. Disable AI agent APIs (browser-specific)
    await this.disableAIAgentAPIs();

    console.warn('[EmergencyKillSwitch] Emergency procedures complete');
  }

  /**
   * Block suspicious domains
   */
  async blockSuspiciousDomains() {
    // Extract domains from recent threats
    for (const threat of this.recentThreats) {
      if (threat.url) {
        try {
          const domain = new URL(threat.url).hostname;
          this.blockedDomains.add(domain);
        } catch {
          // Invalid URL
        }
      }
      if (threat.domain) {
        this.blockedDomains.add(threat.domain);
      }
    }

    console.warn('[EmergencyKillSwitch] Blocked domains:', Array.from(this.blockedDomains));
  }

  /**
   * Quarantine suspicious tabs
   */
  async quarantineSuspiciousTabs() {
    try {
      const tabs = await chrome.tabs.query({});

      for (const tab of tabs) {
        // Check if tab URL matches blocked domain
        if (tab.url) {
          try {
            const domain = new URL(tab.url).hostname;
            if (this.blockedDomains.has(domain)) {
              await this.quarantineTab(tab.id, 'Suspicious domain');
            }
          } catch {
            // Invalid URL
          }
        }
      }
    } catch (error) {
      console.error('[EmergencyKillSwitch] Failed to quarantine tabs:', error);
    }
  }

  /**
   * Quarantine a tab
   */
  async quarantineTab(tabId, reason) {
    try {
      this.quarantinedTabs.add(tabId);
      this.statistics.tabsQuarantined++;

      // Send message to content script to freeze tab
      await chrome.tabs.sendMessage(tabId, {
        type: 'QUARANTINE_TAB',
        reason,
      });

      // Optionally close the tab
      // await chrome.tabs.remove(tabId);

      console.warn(`[EmergencyKillSwitch] Quarantined tab ${tabId}: ${reason}`);
    } catch (error) {
      console.error('[EmergencyKillSwitch] Failed to quarantine tab:', error);
    }
  }

  /**
   * Rollback malicious actions
   */
  async rollbackMaliciousActions() {
    // Get recent actions (last 5 minutes)
    const cutoff = Date.now() - 300000;
    const recentActions = this.actionHistory.filter(a => 
      a.timestamp > cutoff && !a.rolledBack
    );

    for (const action of recentActions) {
      try {
        await this.rollbackAction(action);
        action.rolledBack = true;
        this.statistics.actionsRolledBack++;
      } catch (error) {
        console.error('[EmergencyKillSwitch] Failed to rollback action:', error);
      }
    }

    console.warn(`[EmergencyKillSwitch] Rolled back ${this.statistics.actionsRolledBack} actions`);
  }

  /**
   * Rollback a single action
   */
  async rollbackAction(action) {
    switch (action.type) {
      case 'storageWrite':
        // Restore previous value
        if (action.previousValue !== undefined) {
          await chrome.storage.local.set({ [action.key]: action.previousValue });
        } else {
          await chrome.storage.local.remove(action.key);
        }
        break;

      case 'navigation':
        // Can't rollback navigation, but can close tab
        if (action.tabId) {
          await chrome.tabs.remove(action.tabId);
        }
        break;

      case 'formSubmission':
        // Can't rollback form submission
        break;

      default:
        console.warn('[EmergencyKillSwitch] Unknown action type:', action.type);
    }
  }

  /**
   * Clear suspicious storage
   */
  async clearSuspiciousStorage() {
    try {
      const storage = await chrome.storage.local.get(null);

      for (const [key, value] of Object.entries(storage)) {
        // Skip Armorly's own keys
        if (key.startsWith('armorly_')) continue;

        // Check if value contains suspicious content
        const valueStr = typeof value === 'string' ? value : JSON.stringify(value);
        const suspicious = /ignore|disregard|override|system|admin/i.test(valueStr);

        if (suspicious) {
          await chrome.storage.local.remove(key);
          console.warn(`[EmergencyKillSwitch] Cleared suspicious storage key: ${key}`);
        }
      }
    } catch (error) {
      console.error('[EmergencyKillSwitch] Failed to clear storage:', error);
    }
  }

  /**
   * Disable AI agent APIs (browser-specific)
   */
  async disableAIAgentAPIs() {
    // Send message to all tabs to disable AI agent APIs
    try {
      const tabs = await chrome.tabs.query({});

      for (const tab of tabs) {
        try {
          await chrome.tabs.sendMessage(tab.id, {
            type: 'DISABLE_AI_AGENT',
          });
        } catch {
          // Tab may not have content script
        }
      }
    } catch (error) {
      console.error('[EmergencyKillSwitch] Failed to disable AI agents:', error);
    }
  }

  /**
   * Notify user
   */
  notifyUser(reason, description) {
    // Create notification
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: '🚨 Armorly Emergency Kill Switch Activated',
      message: `Reason: ${description}\n\nAll AI agents have been shut down. Click to review.`,
      priority: 2,
      requireInteraction: true,
    });

    // Update badge
    chrome.action.setBadgeText({ text: '🚨' });
    chrome.action.setBadgeBackgroundColor({ color: '#FF0000' });
  }

  /**
   * Reset kill switch
   */
  async reset() {
    console.warn('[EmergencyKillSwitch] Resetting...');

    this.state.triggered = false;
    this.state.triggeredAt = null;
    this.state.reason = null;

    // Clear blocked domains
    this.blockedDomains.clear();

    // Clear quarantined tabs
    this.quarantinedTabs.clear();

    // Clear recent threats
    this.recentThreats = [];

    // Re-enable AI agents
    await this.enableAIAgentAPIs();

    // Update badge
    chrome.action.setBadgeText({ text: '' });

    console.warn('[EmergencyKillSwitch] Reset complete');
  }

  /**
   * Enable AI agent APIs
   */
  async enableAIAgentAPIs() {
    try {
      const tabs = await chrome.tabs.query({});

      for (const tab of tabs) {
        try {
          await chrome.tabs.sendMessage(tab.id, {
            type: 'ENABLE_AI_AGENT',
          });
        } catch {
          // Tab may not have content script
        }
      }
    } catch (error) {
      console.error('[EmergencyKillSwitch] Failed to enable AI agents:', error);
    }
  }

  /**
   * Set auto-trigger enabled
   */
  setAutoTriggerEnabled(enabled) {
    this.state.autoTriggerEnabled = enabled;
  }

  /**
   * Set auto-trigger threshold
   */
  setAutoTriggerThreshold(threshold) {
    this.autoTriggerThreshold = {
      ...this.autoTriggerThreshold,
      ...threshold,
    };
  }

  /**
   * Get state
   */
  getState() {
    return {
      ...this.state,
      recentThreatsCount: this.recentThreats.length,
      blockedDomainsCount: this.blockedDomains.size,
      quarantinedTabsCount: this.quarantinedTabs.size,
    };
  }

  /**
   * Get statistics
   */
  getStatistics() {
    return {
      ...this.statistics,
      blockedDomains: Array.from(this.blockedDomains),
      quarantinedTabs: Array.from(this.quarantinedTabs),
    };
  }

  /**
   * Get action history
   */
  getActionHistory(limit = 100) {
    return this.actionHistory.slice(-limit).reverse();
  }
}

