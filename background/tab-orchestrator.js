/**
 * Tab Orchestrator for Armorly
 * 
 * Tracks and correlates activity across all tabs to detect:
 * - Cross-tab attacks
 * - Coordinated multi-tab exploits
 * - Tab-based data exfiltration
 * - Background agent activities
 * - Suspicious tab creation patterns
 */

class TabOrchestrator {
  constructor() {
    // Track all tabs and their relationships
    this.tabs = new Map(); // tabId -> { url, openerTabId, createdAt, threats, aiAgent, status }
    
    // Track tab groups (related tabs)
    this.tabGroups = new Map(); // groupId -> Set<tabId>
    
    // Track cross-tab threat patterns
    this.crossTabPatterns = new Map(); // pattern -> { tabs: Set<tabId>, timestamps: [] }
    
    // Track suspicious tab creation patterns
    this.tabCreationHistory = []; // { tabId, url, timestamp, openerTabId }
    
    // Thresholds
    this.thresholds = {
      maxTabsPerMinute: 20,
      maxTabsFromSameOpener: 10,
      suspiciousTabCreationInterval: 1000 // 1 second
    };
  }

  /**
   * Initialize tab orchestration
   */
  initialize() {
    console.log('[Armorly TabOrch] Initializing tab orchestration');

    // Monitor tab creation
    chrome.tabs.onCreated.addListener((tab) => {
      this.handleTabCreated(tab);
    });

    // Monitor tab updates
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      this.handleTabUpdated(tabId, changeInfo, tab);
    });

    // Monitor tab removal
    chrome.tabs.onRemoved.addListener((tabId, removeInfo) => {
      this.handleTabRemoved(tabId, removeInfo);
    });

    // Monitor tab activation
    chrome.tabs.onActivated.addListener((activeInfo) => {
      this.handleTabActivated(activeInfo);
    });

    // Load existing tabs
    chrome.tabs.query({}, (tabs) => {
      tabs.forEach(tab => this.registerTab(tab));
      console.log(`[Armorly TabOrch] Registered ${tabs.length} existing tabs`);
    });

    // Cleanup old data every minute
    setInterval(() => this.cleanup(), 60000);

    console.log('[Armorly TabOrch] Orchestration active');
  }

  /**
   * Handle tab creation
   */
  handleTabCreated(tab) {
    this.registerTab(tab);
    
    const threats = [];
    const timestamp = Date.now();

    // 1. Check for rapid tab creation
    const recentCreations = this.tabCreationHistory.filter(
      t => timestamp - t.timestamp < 60000
    );
    if (recentCreations.length > this.thresholds.maxTabsPerMinute) {
      threats.push({
        type: 'RAPID_TAB_CREATION',
        severity: 'MEDIUM',
        description: `Rapid tab creation detected: ${recentCreations.length} tabs in 1 minute`,
        count: recentCreations.length
      });
    }

    // 2. Check for tabs created in quick succession (bot-like behavior)
    if (recentCreations.length > 0) {
      const lastCreation = recentCreations[recentCreations.length - 1];
      const timeSinceLastCreation = timestamp - lastCreation.timestamp;
      if (timeSinceLastCreation < this.thresholds.suspiciousTabCreationInterval) {
        threats.push({
          type: 'SUSPICIOUS_TAB_TIMING',
          severity: 'LOW',
          description: `Tab created ${timeSinceLastCreation}ms after previous tab (bot-like)`,
          interval: timeSinceLastCreation
        });
      }
    }

    // 3. Check for excessive tabs from same opener
    if (tab.openerTabId) {
      const siblingTabs = Array.from(this.tabs.values()).filter(
        t => t.openerTabId === tab.openerTabId
      );
      if (siblingTabs.length > this.thresholds.maxTabsFromSameOpener) {
        threats.push({
          type: 'EXCESSIVE_TAB_SPAWNING',
          severity: 'HIGH',
          description: `Excessive tabs spawned from tab ${tab.openerTabId}: ${siblingTabs.length} tabs`,
          openerTabId: tab.openerTabId,
          count: siblingTabs.length
        });
      }

      // Create tab group
      this.addToTabGroup(tab.openerTabId, tab.id);
    }

    // Track creation
    this.tabCreationHistory.push({
      tabId: tab.id,
      url: tab.url,
      timestamp,
      openerTabId: tab.openerTabId
    });

    // Report threats
    if (threats.length > 0) {
      this.reportThreats(tab.id, threats);
    }
  }

  /**
   * Handle tab updates
   */
  handleTabUpdated(tabId, changeInfo, tab) {
    const tabInfo = this.tabs.get(tabId);
    if (!tabInfo) {
      this.registerTab(tab);
      return;
    }

    const threats = [];

    // Update tab info
    if (changeInfo.url) {
      const oldUrl = tabInfo.url;
      tabInfo.url = changeInfo.url;
      tabInfo.urlChanges = (tabInfo.urlChanges || 0) + 1;
      tabInfo.lastUrlChange = Date.now();

      // Check for rapid URL changes (potential redirect chain attack)
      if (tabInfo.urlChanges > 5) {
        const timeSinceCreation = Date.now() - tabInfo.createdAt;
        if (timeSinceCreation < 10000) { // 10 seconds
          threats.push({
            type: 'RAPID_URL_CHANGES',
            severity: 'MEDIUM',
            description: `Rapid URL changes in tab: ${tabInfo.urlChanges} changes in ${(timeSinceCreation / 1000).toFixed(1)}s`,
            tabId,
            count: tabInfo.urlChanges,
            oldUrl,
            newUrl: changeInfo.url
          });
        }
      }

      // Check for cross-origin redirects
      try {
        const oldOrigin = new URL(oldUrl).origin;
        const newOrigin = new URL(changeInfo.url).origin;
        if (oldOrigin !== newOrigin) {
          tabInfo.crossOriginRedirects = (tabInfo.crossOriginRedirects || 0) + 1;
          
          if (tabInfo.crossOriginRedirects > 3) {
            threats.push({
              type: 'MULTIPLE_CROSS_ORIGIN_REDIRECTS',
              severity: 'HIGH',
              description: `Multiple cross-origin redirects: ${tabInfo.crossOriginRedirects} redirects`,
              tabId,
              count: tabInfo.crossOriginRedirects
            });
          }
        }
      } catch (e) {
        // Invalid URL
      }
    }

    if (changeInfo.status === 'complete') {
      tabInfo.status = 'complete';
      tabInfo.lastLoadTime = Date.now();
    }

    if (threats.length > 0) {
      this.reportThreats(tabId, threats);
    }
  }

  /**
   * Handle tab removal
   */
  handleTabRemoved(tabId, removeInfo) {
    const tabInfo = this.tabs.get(tabId);
    if (!tabInfo) return;

    // Check for suspicious rapid tab closure
    const lifetime = Date.now() - tabInfo.createdAt;
    if (lifetime < 2000 && tabInfo.threats && tabInfo.threats.length > 0) {
      // Tab with threats closed quickly - might be trying to hide evidence
      this.reportThreats(tabId, [{
        type: 'SUSPICIOUS_TAB_CLOSURE',
        severity: 'MEDIUM',
        description: `Tab with threats closed quickly (${lifetime}ms lifetime)`,
        tabId,
        lifetime,
        threatCount: tabInfo.threats.length
      }]);
    }

    // Remove from tracking
    this.tabs.delete(tabId);
    
    // Remove from tab groups
    for (const [groupId, tabIds] of this.tabGroups.entries()) {
      tabIds.delete(tabId);
      if (tabIds.size === 0) {
        this.tabGroups.delete(groupId);
      }
    }
  }

  /**
   * Handle tab activation
   */
  handleTabActivated(activeInfo) {
    const tabInfo = this.tabs.get(activeInfo.tabId);
    if (tabInfo) {
      tabInfo.lastActivated = Date.now();
      tabInfo.activationCount = (tabInfo.activationCount || 0) + 1;
    }
  }

  /**
   * Register a tab
   */
  registerTab(tab) {
    if (!tab || !tab.id) return;

    this.tabs.set(tab.id, {
      id: tab.id,
      url: tab.url,
      openerTabId: tab.openerTabId,
      createdAt: Date.now(),
      status: tab.status,
      threats: [],
      aiAgent: null,
      urlChanges: 0,
      crossOriginRedirects: 0,
      activationCount: 0
    });
  }

  /**
   * Add tab to group
   */
  addToTabGroup(openerTabId, childTabId) {
    if (!this.tabGroups.has(openerTabId)) {
      this.tabGroups.set(openerTabId, new Set([openerTabId]));
    }
    this.tabGroups.get(openerTabId).add(childTabId);
  }

  /**
   * Record threat for a tab
   */
  recordThreat(tabId, threat) {
    const tabInfo = this.tabs.get(tabId);
    if (tabInfo) {
      tabInfo.threats.push({
        ...threat,
        timestamp: Date.now()
      });
    }

    // Check for cross-tab threat patterns
    this.checkCrossTabPatterns(tabId, threat);
  }

  /**
   * Check for cross-tab threat patterns
   */
  checkCrossTabPatterns(tabId, threat) {
    const patternKey = threat.type;
    
    if (!this.crossTabPatterns.has(patternKey)) {
      this.crossTabPatterns.set(patternKey, {
        tabs: new Set(),
        timestamps: []
      });
    }
    
    const pattern = this.crossTabPatterns.get(patternKey);
    pattern.tabs.add(tabId);
    pattern.timestamps.push(Date.now());
    
    // Keep only last minute
    const oneMinuteAgo = Date.now() - 60000;
    pattern.timestamps = pattern.timestamps.filter(t => t > oneMinuteAgo);
    
    // Check if same threat type appears across multiple tabs
    if (pattern.tabs.size >= 3 && pattern.timestamps.length >= 5) {
      this.reportThreats(null, [{
        type: 'CROSS_TAB_ATTACK_PATTERN',
        severity: 'CRITICAL',
        description: `Same threat type (${patternKey}) detected across ${pattern.tabs.size} tabs`,
        threatType: patternKey,
        affectedTabs: Array.from(pattern.tabs),
        occurrences: pattern.timestamps.length
      }]);
    }
  }

  /**
   * Mark tab as having AI agent
   */
  markAIAgent(tabId, agentType) {
    const tabInfo = this.tabs.get(tabId);
    if (tabInfo) {
      tabInfo.aiAgent = agentType;
    }
  }

  /**
   * Get tab info
   */
  getTabInfo(tabId) {
    return this.tabs.get(tabId);
  }

  /**
   * Get tab group
   */
  getTabGroup(tabId) {
    for (const [groupId, tabIds] of this.tabGroups.entries()) {
      if (tabIds.has(tabId)) {
        return Array.from(tabIds);
      }
    }
    return [tabId];
  }

  /**
   * Get all tabs with threats
   */
  getTabsWithThreats() {
    return Array.from(this.tabs.values()).filter(t => t.threats.length > 0);
  }

  /**
   * Report threats
   * Note: This is called from within the service worker, so we'll use a callback
   */
  reportThreats(tabId, threats) {
    console.log(`[Armorly TabOrch] Reporting ${threats.length} threats${tabId ? ` from tab ${tabId}` : ''}`);

    // Call the callback if it exists (set by service worker)
    if (this.onThreatsDetected) {
      this.onThreatsDetected({
        tabId,
        threats,
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
   * Cleanup old data
   */
  cleanup() {
    const oneHourAgo = Date.now() - 3600000;
    
    // Cleanup tab creation history
    this.tabCreationHistory = this.tabCreationHistory.filter(
      t => t.timestamp > oneHourAgo
    );
    
    // Cleanup cross-tab patterns
    for (const [key, pattern] of this.crossTabPatterns.entries()) {
      const oneMinuteAgo = Date.now() - 60000;
      pattern.timestamps = pattern.timestamps.filter(t => t > oneMinuteAgo);
      if (pattern.timestamps.length === 0) {
        this.crossTabPatterns.delete(key);
      }
    }
  }

  /**
   * Get statistics
   */
  getStatistics() {
    return {
      totalTabs: this.tabs.size,
      tabGroups: this.tabGroups.size,
      tabsWithThreats: this.getTabsWithThreats().length,
      tabsWithAIAgents: Array.from(this.tabs.values()).filter(t => t.aiAgent).length,
      crossTabPatterns: this.crossTabPatterns.size
    };
  }
}

// Export for ES6 modules
export { TabOrchestrator };
