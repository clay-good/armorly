/**
 * Threat Analysis Engine for Armorly
 * 
 * Sophisticated threat scoring and decision logic that:
 * - Aggregates threats from multiple sources (CSRF, DOM, patterns)
 * - Applies context-aware scoring
 * - Makes blocking/warning decisions
 * - Tracks threat trends
 * - Provides actionable recommendations
 * 
 * @module threat-detector
 * @author Armorly Security Team
 * @license MIT
 */

class ThreatDetector {
  constructor() {
    /**
     * Threat severity thresholds
     */
    this.thresholds = {
      CRITICAL: 90,  // Block immediately
      HIGH: 70,      // Show warning overlay
      MEDIUM: 40,    // Log and notify
      LOW: 0         // Log silently
    };

    /**
     * Context multipliers for different scenarios
     */
    this.contextMultipliers = {
      aiAgentActive: 1.5,        // AI agent detected on page
      chatGPTDomain: 1.3,        // On ChatGPT domain
      perplexityDomain: 1.3,     // On Perplexity domain
      browserOSDomain: 1.3,      // On BrowserOS domain
      edgeCopilot: 1.2,          // Edge with Copilot
      operaAI: 1.2,              // Opera with AI
      braveAI: 1.2,              // Brave with Leo
      multipleThreats: 1.4,      // Multiple threat types
      repeatedThreat: 1.3,       // Same threat seen before
      crossOrigin: 1.2,          // Cross-origin context
      hiddenContent: 1.3         // Hidden/invisible content
    };

    /**
     * Threat type weights
     */
    this.threatWeights = {
      CSRF: 1.0,
      MEMORY_POISONING: 1.3,
      DATA_EXFILTRATION: 1.2,
      PROMPT_INJECTION: 1.0,
      INVISIBLE_TEXT: 0.9,
      INSTRUCTION_HIJACK: 1.1,
      GOAL_HIJACK: 1.0,
      SOCIAL_ENGINEERING: 0.8,
      OBFUSCATION: 0.7
    };

    /**
     * Recent threat cache for pattern detection
     */
    this.recentThreats = new Map();
    this.threatHistory = [];
  }

  /**
   * Analyze aggregated threats and determine action
   * 
   * @param {Object} context - Analysis context
   * @param {Array} context.threats - Array of detected threats
   * @param {string} context.url - Page URL
   * @param {boolean} context.aiAgentActive - Whether AI agent is active
   * @param {Object} context.pageInfo - Additional page information
   * @returns {Object} Analysis result with decision
   */
  analyzeThreat(context) {
    const { threats, url, aiAgentActive, pageInfo = {} } = context;

    if (!threats || threats.length === 0) {
      return {
        severity: 'SAFE',
        score: 0,
        shouldBlock: false,
        shouldWarn: false,
        shouldNotify: false,
        threats: [],
        recommendation: 'No threats detected'
      };
    }

    // Calculate base score from all threats
    let baseScore = 0;
    const threatTypes = new Set();

    threats.forEach(threat => {
      const weight = this.threatWeights[threat.type] || 1.0;
      baseScore += (threat.score || 0) * weight;
      threatTypes.add(threat.type);
    });

    // Apply context multipliers
    let finalScore = baseScore;
    const appliedMultipliers = [];

    if (aiAgentActive) {
      finalScore *= this.contextMultipliers.aiAgentActive;
      appliedMultipliers.push('AI Agent Active');
    }

    if (this.isAIDomain(url)) {
      const domain = new URL(url).hostname;
      if (domain.includes('chatgpt.com') || domain.includes('openai.com')) {
        finalScore *= this.contextMultipliers.chatGPTDomain;
        appliedMultipliers.push('ChatGPT Domain');
      } else if (domain.includes('perplexity.ai')) {
        finalScore *= this.contextMultipliers.perplexityDomain;
        appliedMultipliers.push('Perplexity Domain');
      } else if (domain.includes('browseros.com')) {
        finalScore *= this.contextMultipliers.browserOSDomain;
        appliedMultipliers.push('BrowserOS Domain');
      }
    }

    if (threatTypes.size > 1) {
      finalScore *= this.contextMultipliers.multipleThreats;
      appliedMultipliers.push('Multiple Threat Types');
    }

    if (this.isRepeatedThreat(url, threats)) {
      finalScore *= this.contextMultipliers.repeatedThreat;
      appliedMultipliers.push('Repeated Threat');
    }

    if (pageInfo.crossOrigin) {
      finalScore *= this.contextMultipliers.crossOrigin;
      appliedMultipliers.push('Cross-Origin');
    }

    if (pageInfo.hasHiddenContent) {
      finalScore *= this.contextMultipliers.hiddenContent;
      appliedMultipliers.push('Hidden Content');
    }

    // Normalize score to 0-100
    finalScore = Math.min(100, finalScore);

    // Determine severity
    let severity = 'LOW';
    if (finalScore >= this.thresholds.CRITICAL) {
      severity = 'CRITICAL';
    } else if (finalScore >= this.thresholds.HIGH) {
      severity = 'HIGH';
    } else if (finalScore >= this.thresholds.MEDIUM) {
      severity = 'MEDIUM';
    }

    // Make decision
    const shouldBlock = finalScore >= this.thresholds.CRITICAL;
    const shouldWarn = finalScore >= this.thresholds.HIGH;
    const shouldNotify = finalScore >= this.thresholds.MEDIUM;

    // Generate recommendation
    const recommendation = this.generateRecommendation(severity, threats, context);

    // Cache threat for pattern detection
    this.cacheThreats(url, threats, finalScore);

    // Build result
    const result = {
      severity,
      score: Math.round(finalScore),
      baseScore: Math.round(baseScore),
      shouldBlock,
      shouldWarn,
      shouldNotify,
      threats,
      threatTypes: Array.from(threatTypes),
      appliedMultipliers,
      recommendation,
      timestamp: Date.now()
    };

    // Add to history
    this.addToHistory(result);

    return result;
  }

  /**
   * Check if URL is an AI domain
   * 
   * @param {string} url - URL to check
   * @returns {boolean} True if AI domain
   */
  isAIDomain(url) {
    try {
      const hostname = new URL(url).hostname.toLowerCase();
      const aiDomains = [
        'chatgpt.com',
        'openai.com',
        'perplexity.ai',
        'browseros.com',
        'opera.com',
        'brave.com'
      ];
      
      return aiDomains.some(domain => hostname.includes(domain));
    } catch {
      return false;
    }
  }

  /**
   * Check if threat is repeated
   * 
   * @param {string} url - Page URL
   * @param {Array} threats - Current threats
   * @returns {boolean} True if repeated
   */
  isRepeatedThreat(url, threats) {
    const cached = this.recentThreats.get(url);
    if (!cached) return false;

    const currentTypes = new Set(threats.map(t => t.type));
    const cachedTypes = new Set(cached.threats.map(t => t.type));

    // Check if any threat type matches
    for (const type of currentTypes) {
      if (cachedTypes.has(type)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Cache threats for pattern detection
   * 
   * @param {string} url - Page URL
   * @param {Array} threats - Threats to cache
   * @param {number} score - Threat score
   */
  cacheThreats(url, threats, score) {
    this.recentThreats.set(url, {
      threats,
      score,
      timestamp: Date.now()
    });

    // Clean old cache entries (older than 1 hour)
    const oneHourAgo = Date.now() - 3600000;
    for (const [cachedUrl, data] of this.recentThreats.entries()) {
      if (data.timestamp < oneHourAgo) {
        this.recentThreats.delete(cachedUrl);
      }
    }
  }

  /**
   * Generate actionable recommendation
   * 
   * @param {string} severity - Threat severity
   * @param {Array} threats - Detected threats
   * @param {Object} context - Analysis context
   * @returns {string} Recommendation text
   */
  generateRecommendation(severity, threats, context) {
    const recommendations = {
      CRITICAL: [
        'Navigate away from this page immediately',
        'Do not interact with any AI agents on this page',
        'Report this page if you believe it\'s malicious'
      ],
      HIGH: [
        'Exercise extreme caution on this page',
        'Avoid using AI agents until threats are resolved',
        'Consider reporting this page'
      ],
      MEDIUM: [
        'Be cautious when using AI agents on this page',
        'Review the detected threats before proceeding',
        'Monitor AI agent behavior for anomalies'
      ],
      LOW: [
        'Minor security concerns detected',
        'Safe to proceed with normal caution'
      ]
    };

    const baseRecs = recommendations[severity] || recommendations.LOW;
    
    // Add specific recommendations based on threat types
    const specificRecs = [];
    threats.forEach(threat => {
      if (threat.type === 'MEMORY_POISONING') {
        specificRecs.push('Check your ChatGPT memories for suspicious content');
      } else if (threat.type === 'DATA_EXFILTRATION') {
        specificRecs.push('Do not share sensitive information with AI agents on this page');
      } else if (threat.type === 'CSRF') {
        specificRecs.push('This page may be attempting unauthorized actions');
      }
    });

    return [...new Set([...baseRecs, ...specificRecs])].join('. ');
  }

  /**
   * Add result to history
   * 
   * @param {Object} result - Analysis result
   */
  addToHistory(result) {
    this.threatHistory.unshift(result);
    
    // Keep only last 100 entries
    if (this.threatHistory.length > 100) {
      this.threatHistory.splice(100);
    }
  }

  /**
   * Get threat statistics
   * 
   * @returns {Object} Statistics
   */
  getStatistics() {
    const stats = {
      totalAnalyzed: this.threatHistory.length,
      bySeverity: {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0
      },
      byType: {},
      averageScore: 0
    };

    let totalScore = 0;

    this.threatHistory.forEach(result => {
      stats.bySeverity[result.severity]++;
      totalScore += result.score;

      result.threatTypes.forEach(type => {
        stats.byType[type] = (stats.byType[type] || 0) + 1;
      });
    });

    stats.averageScore = this.threatHistory.length > 0 
      ? Math.round(totalScore / this.threatHistory.length) 
      : 0;

    return stats;
  }

  /**
   * Clear threat history
   */
  clearHistory() {
    this.threatHistory = [];
    this.recentThreats.clear();
  }
}

// Export for use in service worker
export { ThreatDetector };
