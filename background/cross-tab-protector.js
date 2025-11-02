/**
 * Armorly - Cross-Tab Attack Protector
 * 
 * Detects and blocks cross-tab communication attacks, prevents tab hijacking,
 * and monitors postMessage abuse across all chromium-based agentic browsers.
 * 
 * Features:
 * - Cross-tab communication monitoring
 * - Tab isolation enforcement
 * - postMessage abuse detection
 * - Coordinated attack detection
 * - Tab hijacking prevention
 */

export class CrossTabProtector {
  constructor() {
    // Tab tracking
    this.tabs = new Map();
    
    // Cross-tab messages
    this.messages = [];
    
    // Suspicious patterns
    this.suspiciousPatterns = [];
    
    // Statistics
    this.statistics = {
      totalTabs: 0,
      activeTabs: 0,
      crossTabMessages: 0,
      blockedMessages: 0,
      suspiciousPatterns: 0,
    };

    // Threat callback
    this.threatCallback = null;

    // Initialize listeners
    this.initializeListeners();
  }

  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }

  /**
   * Initialize listeners
   */
  initializeListeners() {
    // Tab created
    chrome.tabs.onCreated.addListener((tab) => {
      this.handleTabCreated(tab);
    });

    // Tab updated
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      this.handleTabUpdated(tabId, changeInfo, tab);
    });

    // Tab removed
    chrome.tabs.onRemoved.addListener((tabId) => {
      this.handleTabRemoved(tabId);
    });

    // Tab activated
    chrome.tabs.onActivated.addListener((activeInfo) => {
      this.handleTabActivated(activeInfo);
    });

    // Listen for messages from content scripts
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.type === 'CROSS_TAB_MESSAGE') {
        this.handleCrossTabMessage(message, sender);
      }
    });
  }

  /**
   * Handle tab created
   */
  handleTabCreated(tab) {
    this.statistics.totalTabs++;
    this.statistics.activeTabs++;

    this.tabs.set(tab.id, {
      id: tab.id,
      url: tab.url,
      title: tab.title,
      openerTabId: tab.openerTabId,
      createdAt: Date.now(),
      actions: [],
      messages: [],
      suspicious: false,
    });

    // Check if opened by another tab (potential tab hijacking)
    if (tab.openerTabId) {
      this.checkTabOpener(tab);
    }
  }

  /**
   * Handle tab updated
   */
  handleTabUpdated(tabId, changeInfo, tab) {
    const tabData = this.tabs.get(tabId);
    if (!tabData) return;

    // Update tab data
    if (changeInfo.url) {
      tabData.url = changeInfo.url;
      tabData.urlChanges = (tabData.urlChanges || 0) + 1;

      // Check for rapid URL changes (potential tab hijacking)
      if (tabData.urlChanges > 5) {
        const timeSpan = Date.now() - tabData.createdAt;
        if (timeSpan < 10000) { // 5+ changes in 10 seconds
          this.reportThreat({
            type: 'TAB_HIJACKING',
            severity: 'CRITICAL',
            tabId,
            description: 'Rapid URL changes detected (potential tab hijacking)',
            urlChanges: tabData.urlChanges,
            timeSpan,
          });
        }
      }
    }

    if (changeInfo.title) {
      tabData.title = changeInfo.title;
    }
  }

  /**
   * Handle tab removed
   */
  handleTabRemoved(tabId) {
    this.statistics.activeTabs--;
    this.tabs.delete(tabId);
  }

  /**
   * Handle tab activated
   */
  handleTabActivated(activeInfo) {
    const tabData = this.tabs.get(activeInfo.tabId);
    if (tabData) {
      tabData.lastActivated = Date.now();
    }
  }

  /**
   * Check tab opener for suspicious behavior
   */
  checkTabOpener(tab) {
    const openerTab = this.tabs.get(tab.openerTabId);
    if (!openerTab) return;

    // Count tabs opened by this tab
    openerTab.openedTabs = (openerTab.openedTabs || 0) + 1;

    // Check for tab bombing (opening many tabs)
    if (openerTab.openedTabs > 5) {
      const timeSpan = Date.now() - openerTab.createdAt;
      if (timeSpan < 30000) { // 5+ tabs in 30 seconds
        this.reportThreat({
          type: 'TAB_BOMBING',
          severity: 'HIGH',
          tabId: tab.openerTabId,
          description: 'Multiple tabs opened rapidly (potential tab bombing)',
          openedTabs: openerTab.openedTabs,
          timeSpan,
        });
      }
    }
  }

  /**
   * Handle cross-tab message
   */
  handleCrossTabMessage(message, sender) {
    this.statistics.crossTabMessages++;

    const messageRecord = {
      timestamp: Date.now(),
      sourceTabId: sender.tab?.id,
      sourceUrl: sender.tab?.url,
      targetTabId: message.targetTabId,
      data: message.data,
      origin: message.origin,
    };

    this.messages.push(messageRecord);

    // Analyze message for threats
    this.analyzeMessage(messageRecord);

    // Check for coordinated attack pattern
    this.checkCoordinatedAttack();

    // Limit message history
    if (this.messages.length > 1000) {
      this.messages = this.messages.slice(-1000);
    }
  }

  /**
   * Analyze message for threats
   */
  analyzeMessage(message) {
    const { data, sourceUrl, targetTabId } = message;

    // Check for suspicious data
    if (typeof data === 'string') {
      // Check for instruction-like content
      const suspiciousKeywords = [
        'ignore', 'disregard', 'override', 'bypass', 'admin', 'system',
        'execute', 'eval', 'script', 'inject', 'steal', 'exfiltrate',
      ];

      const lowerData = data.toLowerCase();
      const foundKeywords = suspiciousKeywords.filter(keyword => 
        lowerData.includes(keyword)
      );

      if (foundKeywords.length >= 2) {
        this.reportThreat({
          type: 'SUSPICIOUS_CROSS_TAB_MESSAGE',
          severity: 'HIGH',
          sourceUrl,
          targetTabId,
          description: 'Suspicious keywords in cross-tab message',
          keywords: foundKeywords,
          timestamp: Date.now(),
        });
      }
    }

    // Check for credential data
    if (data && typeof data === 'object') {
      const keys = Object.keys(data).map(k => k.toLowerCase());
      const credentialKeys = ['password', 'token', 'secret', 'key', 'auth'];
      
      const hasCredentials = credentialKeys.some(ck => 
        keys.some(k => k.includes(ck))
      );

      if (hasCredentials) {
        this.reportThreat({
          type: 'CREDENTIAL_CROSS_TAB_TRANSFER',
          severity: 'CRITICAL',
          sourceUrl,
          targetTabId,
          description: 'Credentials detected in cross-tab message',
          timestamp: Date.now(),
        });
      }
    }
  }

  /**
   * Check for coordinated attack pattern
   */
  checkCoordinatedAttack() {
    // Get recent messages (last 10 seconds)
    const recentMessages = this.messages.filter(m => 
      Date.now() - m.timestamp < 10000
    );

    if (recentMessages.length < 5) return;

    // Check if messages involve multiple tabs
    const sourceTabs = new Set(recentMessages.map(m => m.sourceTabId));
    const targetTabs = new Set(recentMessages.map(m => m.targetTabId));

    if (sourceTabs.size >= 3 || targetTabs.size >= 3) {
      // Check if not already reported recently
      const alreadyReported = this.suspiciousPatterns.some(p => 
        p.type === 'COORDINATED_CROSS_TAB_ATTACK' && 
        (Date.now() - p.timestamp) < 60000
      );

      if (!alreadyReported) {
        const pattern = {
          type: 'COORDINATED_CROSS_TAB_ATTACK',
          severity: 'CRITICAL',
          description: 'Coordinated cross-tab communication detected',
          messageCount: recentMessages.length,
          sourceTabCount: sourceTabs.size,
          targetTabCount: targetTabs.size,
          timestamp: Date.now(),
        };

        this.suspiciousPatterns.push(pattern);
        this.statistics.suspiciousPatterns++;
        this.reportThreat(pattern);
      }
    }
  }

  /**
   * Isolate tab (prevent cross-tab communication)
   */
  async isolateTab(tabId) {
    const tabData = this.tabs.get(tabId);
    if (!tabData) return;

    tabData.isolated = true;

    // Send message to content script to disable postMessage
    try {
      await chrome.tabs.sendMessage(tabId, {
        type: 'ISOLATE_TAB',
      });
    } catch (error) {
      console.error('[CrossTabProtector] Failed to isolate tab:', error);
    }
  }

  /**
   * Quarantine tab (close and block)
   */
  async quarantineTab(tabId, reason) {
    const tabData = this.tabs.get(tabId);
    if (!tabData) return;

    // Record quarantine
    this.reportThreat({
      type: 'TAB_QUARANTINED',
      severity: 'CRITICAL',
      tabId,
      reason,
      url: tabData.url,
      timestamp: Date.now(),
    });

    // Close tab
    try {
      await chrome.tabs.remove(tabId);
    } catch (error) {
      console.error('[CrossTabProtector] Failed to quarantine tab:', error);
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
   * Get tab statistics
   */
  getTabStatistics() {
    return {
      ...this.statistics,
      tabs: Array.from(this.tabs.values()).map(tab => ({
        id: tab.id,
        url: tab.url,
        title: tab.title,
        suspicious: tab.suspicious,
        isolated: tab.isolated,
        messageCount: tab.messages.length,
      })),
    };
  }

  /**
   * Get recent messages
   */
  getRecentMessages(limit = 50) {
    return this.messages.slice(-limit).reverse();
  }

  /**
   * Get suspicious patterns
   */
  getSuspiciousPatterns(limit = 20) {
    return this.suspiciousPatterns.slice(-limit).reverse();
  }

  /**
   * Get tab info
   */
  getTabInfo(tabId) {
    return this.tabs.get(tabId);
  }

  /**
   * Reset statistics
   */
  resetStatistics() {
    this.statistics = {
      totalTabs: this.tabs.size,
      activeTabs: this.tabs.size,
      crossTabMessages: 0,
      blockedMessages: 0,
      suspiciousPatterns: 0,
    };
    this.messages = [];
    this.suspiciousPatterns = [];
  }
}

