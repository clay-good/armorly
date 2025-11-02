/**
 * AI Agent Detector
 * 
 * Detects when AI agents (ChatGPT Atlas, Perplexity Comet, BrowserOS) are active
 * and applies heightened security protection. This is critical because AI agents
 * can read and execute instructions from web pages, making them prime targets for
 * prompt injection and memory poisoning attacks.
 * 
 * @module background/ai-agent-detector
 * @author Armorly Security Team
 * @license MIT
 */

/**
 * AI Agent Detector Class
 * 
 * Monitors browser activity to detect when AI agents are active and reading web content.
 * When agents are detected, threat scoring multipliers are increased to provide
 * heightened protection against prompt injection and memory poisoning attacks.
 */
export class AIAgentDetector {
  constructor() {
    /**
     * Known AI browser user agents and detection patterns
     */
    this.agentPatterns = {
      // ChatGPT Atlas browser
      atlas: {
        userAgentPattern: /ChatGPT|Atlas/i,
        domains: ['chatgpt.com', 'chat.openai.com'],
        indicators: [
          'chatgpt-prompt-textarea',
          'composer-background',
          'gizmo-shadow-stroke'
        ],
        threatMultiplier: 2.0 // Double threat scores when Atlas active
      },
      
      // Perplexity Comet browser
      comet: {
        userAgentPattern: /Perplexity|Comet/i,
        domains: ['perplexity.ai', 'www.perplexity.ai'],
        indicators: [
          'perplexity-search',
          'copilot-mode',
          'pro-search'
        ],
        threatMultiplier: 1.8
      },
      
      // BrowserOS
      browseros: {
        userAgentPattern: /BrowserOS/i,
        domains: ['browseros.com', 'www.browseros.com'],
        indicators: [
          'browser-os-agent',
          'autonomous-mode'
        ],
        threatMultiplier: 1.9
      },
      
      // Generic AI agent detection
      generic: {
        userAgentPattern: /AI-Agent|Autonomous|WebAgent/i,
        domains: [],
        indicators: [
          'ai-assistant',
          'agent-mode',
          'autonomous-browsing'
        ],
        threatMultiplier: 1.5
      }
    };

    /**
     * Currently active AI agents by tab ID
     * Map<tabId, { type: string, confidence: number, timestamp: number }>
     */
    this.activeAgents = new Map();

    /**
     * Detection confidence thresholds
     */
    this.confidenceThreshold = 0.7; // 70% confidence required

    /**
     * Cache for user agent checks
     */
    this.userAgentCache = new Map();
  }

  /**
   * Detect if an AI agent is active on a given tab
   * 
   * @param {number} tabId - Chrome tab ID
   * @param {string} url - Current page URL
   * @param {Object} context - Additional context (user agent, DOM indicators, etc.)
   * @returns {Promise<Object>} Detection result with agent type and confidence
   */
  async detectAgent(tabId, url, context = {}) {
    const detectionResults = [];
    const urlObj = new URL(url);
    const domain = urlObj.hostname;

    // Check each agent type
    for (const [agentType, config] of Object.entries(this.agentPatterns)) {
      let confidence = 0;
      const reasons = [];

      // Check 1: Domain match (high confidence)
      if (config.domains.some(d => domain.includes(d))) {
        confidence += 0.5;
        reasons.push(`Domain matches ${agentType}`);
      }

      // Check 2: User agent string (medium confidence)
      if (context.userAgent && config.userAgentPattern.test(context.userAgent)) {
        confidence += 0.3;
        reasons.push(`User agent matches ${agentType}`);
      }

      // Check 3: DOM indicators (medium confidence)
      if (context.domIndicators) {
        const matchedIndicators = config.indicators.filter(indicator =>
          context.domIndicators.includes(indicator)
        );
        if (matchedIndicators.length > 0) {
          confidence += 0.3 * (matchedIndicators.length / config.indicators.length);
          reasons.push(`DOM indicators: ${matchedIndicators.join(', ')}`);
        }
      }

      // Check 4: Active interaction patterns (low confidence boost)
      if (context.hasActiveInput) {
        confidence += 0.1;
        reasons.push('Active input detected');
      }

      if (confidence >= this.confidenceThreshold) {
        detectionResults.push({
          type: agentType,
          confidence,
          reasons,
          threatMultiplier: config.threatMultiplier
        });
      }
    }

    // Select highest confidence detection
    const bestMatch = detectionResults.sort((a, b) => b.confidence - a.confidence)[0];

    if (bestMatch) {
      // Store active agent
      this.activeAgents.set(tabId, {
        type: bestMatch.type,
        confidence: bestMatch.confidence,
        timestamp: Date.now(),
        threatMultiplier: bestMatch.threatMultiplier
      });

      console.log(`[Armorly] AI agent detected on tab ${tabId}:`, bestMatch);
      
      return {
        detected: true,
        agent: bestMatch
      };
    }

    // No agent detected
    this.activeAgents.delete(tabId);
    return {
      detected: false,
      agent: null
    };
  }

  /**
   * Check if an AI agent is currently active on a tab
   * 
   * @param {number} tabId - Chrome tab ID
   * @returns {Object|null} Active agent info or null
   */
  getActiveAgent(tabId) {
    const agent = this.activeAgents.get(tabId);
    
    if (!agent) {
      return null;
    }

    // Check if detection is stale (older than 5 minutes)
    const age = Date.now() - agent.timestamp;
    if (age > 5 * 60 * 1000) {
      this.activeAgents.delete(tabId);
      return null;
    }

    return agent;
  }

  /**
   * Get threat multiplier for a tab based on AI agent activity
   * 
   * @param {number} tabId - Chrome tab ID
   * @returns {number} Threat score multiplier (1.0 if no agent, higher if agent active)
   */
  getThreatMultiplier(tabId) {
    const agent = this.getActiveAgent(tabId);
    return agent ? agent.threatMultiplier : 1.0;
  }

  /**
   * Check if user is currently on a ChatGPT page
   * This is critical because memory poisoning attacks are most dangerous
   * when the user is actively using ChatGPT
   * 
   * @param {string} url - Current page URL
   * @returns {boolean} True if on ChatGPT domain
   */
  isOnChatGPT(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname.includes('chatgpt.com') || 
             urlObj.hostname.includes('chat.openai.com');
    } catch (e) {
      return false;
    }
  }

  /**
   * Check if user is on any AI browser platform
   * 
   * @param {string} url - Current page URL
   * @returns {Object} { isAIBrowser: boolean, platform: string|null }
   */
  checkAIBrowserPlatform(url) {
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname;

      for (const [agentType, config] of Object.entries(this.agentPatterns)) {
        if (config.domains.some(d => domain.includes(d))) {
          return {
            isAIBrowser: true,
            platform: agentType
          };
        }
      }

      return { isAIBrowser: false, platform: null };
    } catch (e) {
      return { isAIBrowser: false, platform: null };
    }
  }

  /**
   * Clear agent detection for a tab (called when tab closes or navigates)
   * 
   * @param {number} tabId - Chrome tab ID
   */
  clearAgent(tabId) {
    this.activeAgents.delete(tabId);
    console.log(`[Armorly] Cleared AI agent detection for tab ${tabId}`);
  }

  /**
   * Get statistics about AI agent activity
   * 
   * @returns {Object} Statistics object
   */
  getStatistics() {
    const stats = {
      totalActiveAgents: this.activeAgents.size,
      agentsByType: {},
      averageConfidence: 0
    };

    let totalConfidence = 0;
    for (const agent of this.activeAgents.values()) {
      stats.agentsByType[agent.type] = (stats.agentsByType[agent.type] || 0) + 1;
      totalConfidence += agent.confidence;
    }

    if (this.activeAgents.size > 0) {
      stats.averageConfidence = totalConfidence / this.activeAgents.size;
    }

    return stats;
  }

  /**
   * Request DOM indicators from content script
   * This is called to get additional context for agent detection
   * 
   * @param {number} tabId - Chrome tab ID
   * @returns {Promise<Array>} Array of detected DOM indicators
   */
  async requestDOMIndicators(tabId) {
    try {
      const response = await chrome.tabs.sendMessage(tabId, {
        type: 'GET_AI_INDICATORS'
      });

      return response?.indicators || [];
    } catch (error) {
      console.error('[Armorly] Error requesting DOM indicators:', error);
      return [];
    }
  }
}

