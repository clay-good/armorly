/**
 * Multi-turn Attack Chain Detector for Armorly
 *
 * Detects sophisticated attacks that spread across multiple messages
 * to evade single-message detection. Tracks behavioral patterns and
 * attack chains across entire conversations.
 *
 * CRITICAL: Addresses the gap where individual messages look benign
 * but combine to form a malicious attack chain.
 *
 * @module multi-turn-attack-detector
 * @author Armorly Security Team
 * @license MIT
 */

class MultiTurnAttackDetector {
  constructor() {
    /**
     * Statistics
     */
    this.stats = {
      conversationsAnalyzed: 0,
      attackChainsDetected: 0,
      suspiciousPatternsFound: 0,
      threatsBlocked: 0,
    };

    /**
     * Configuration
     */
    this.config = {
      enabled: true,
      chainLength: 5, // Analyze last 5 messages
      suspicionThreshold: 0.6, // 60% suspicion score triggers alert
      patternMatchThreshold: 3, // 3+ pattern matches = attack chain
      logActions: false, // Silent operation
    };

    /**
     * Conversation history tracking
     * Map<conversationId, ConversationAnalysis>
     */
    this.conversations = new Map();

    /**
     * Current conversation ID
     */
    this.currentConversationId = null;

    /**
     * Attack chain patterns
     * These patterns indicate multi-turn attacks when combined
     */
    this.attackChainPatterns = {
      // Gradual privilege escalation
      privilegeEscalation: [
        /can\s+you\s+(?:access|read|check)/i,
        /(?:now|also)\s+(?:read|access|get)/i,
        /(?:delete|remove|modify)\s+(?:this|that|the)/i,
      ],

      // Information gathering -> exploitation
      reconnaissance: [
        /what\s+(?:files|directories|folders)\s+(?:do you have|can you see)/i,
        /list\s+(?:all|the)\s+(?:files|directories)/i,
        /(?:read|show|display)\s+(?:the\s+)?(?:content|file)/i,
      ],

      // Trust building -> malicious request
      trustExploitation: [
        /thank\s+you/i,
        /you\'re\s+(?:helpful|great|amazing)/i,
        /(?:ignore|disregard|forget)\s+(?:previous|that|those)/i,
      ],

      // Instruction fragmentation
      fragmentedCommand: [
        /remember\s+(?:this|that|to)/i,
        /(?:recall|use)\s+what\s+i\s+(?:told|said)/i,
        /(?:now|finally)\s+(?:execute|run|do)/i,
      ],

      // Role manipulation over time
      roleShifting: [
        /you\s+are\s+(?:a|an|my)/i,
        /act\s+(?:as|like)\s+(?:a|an)/i,
        /(?:now|from now on)\s+you\s+(?:should|must|will)/i,
      ],
    };

    /**
     * Behavioral indicators
     * Patterns that suggest suspicious intent
     */
    this.behavioralIndicators = [
      // Repeated permission requests
      /can\s+(?:i|you)/i,
      /(?:allow|permit|let)\s+me/i,

      // Testing boundaries
      /what\s+(?:if|happens)/i,
      /try\s+(?:to|this)/i,

      // Obfuscation attempts
      /don't\s+(?:tell|mention|say)/i,
      /(?:secret|hidden|private)/i,

      // Urgency pressure
      /(?:urgent|asap|immediately|now)/i,
      /(?:quick|hurry|fast)/i,
    ];

    /**
     * Message history per conversation
     */
    this.messageHistory = new Map();
  }

  /**
   * Start monitoring for multi-turn attacks
   */
  start() {
    if (!this.config.enabled) return;

    console.log('[Armorly Multi-turn Detector] Starting - detecting attack chains');

    // Detect current conversation
    this.detectConversation();

    // Set up periodic analysis
    this.analysisInterval = setInterval(() => {
      this.analyzeCurrentConversation();
    }, 5000); // Analyze every 5 seconds
  }

  /**
   * Stop monitoring
   */
  stop() {
    if (this.analysisInterval) {
      clearInterval(this.analysisInterval);
      this.analysisInterval = null;
    }

    console.log('[Armorly Multi-turn Detector] Stopped');
  }

  /**
   * Detect current conversation ID from URL
   */
  detectConversation() {
    const url = window.location.href;
    let conversationId = null;

    // ChatGPT
    if (url.includes('chatgpt.com') || url.includes('chat.openai.com')) {
      const match = url.match(/\/c\/([a-f0-9-]+)/);
      conversationId = match ? match[1] : 'chatgpt-' + this.generateId();
    }
    // Claude
    else if (url.includes('claude.ai')) {
      const match = url.match(/\/chat\/([a-f0-9-]+)/);
      conversationId = match ? match[1] : 'claude-' + this.generateId();
    }
    // Gemini
    else if (url.includes('gemini.google.com')) {
      conversationId = 'gemini-' + this.generateId();
    }
    // Generic fallback
    else {
      conversationId = 'conversation-' + this.generateId();
    }

    this.currentConversationId = conversationId;

    // Initialize conversation tracking
    if (!this.conversations.has(conversationId)) {
      this.conversations.set(conversationId, {
        id: conversationId,
        startTime: Date.now(),
        messageCount: 0,
        suspicionScore: 0,
        detectedPatterns: [],
        attackChains: [],
      });

      this.messageHistory.set(conversationId, []);
      this.stats.conversationsAnalyzed++;
    }
  }

  /**
   * Track new message
   */
  trackMessage(text, role) {
    if (!this.currentConversationId) {
      this.detectConversation();
    }

    const history = this.messageHistory.get(this.currentConversationId) || [];
    const conversation = this.conversations.get(this.currentConversationId);

    // Add message to history
    const message = {
      text,
      role, // 'user' or 'assistant'
      timestamp: Date.now(),
      suspicionScore: this.calculateMessageSuspicion(text),
      patterns: this.detectPatterns(text),
    };

    history.push(message);
    conversation.messageCount++;

    // Keep only recent messages (sliding window)
    if (history.length > this.config.chainLength * 2) {
      history.shift();
    }

    this.messageHistory.set(this.currentConversationId, history);

    // Analyze for attack chains
    this.analyzeAttackChain(history, conversation);
  }

  /**
   * Calculate suspicion score for a single message
   */
  calculateMessageSuspicion(text) {
    let score = 0;
    let matches = 0;

    // Check behavioral indicators
    for (const pattern of this.behavioralIndicators) {
      if (pattern.test(text)) {
        matches++;
        score += 0.1;
      }
    }

    // Check attack chain patterns
    for (const category in this.attackChainPatterns) {
      for (const pattern of this.attackChainPatterns[category]) {
        if (pattern.test(text)) {
          matches++;
          score += 0.15;
        }
      }
    }

    return Math.min(score, 1.0); // Cap at 1.0
  }

  /**
   * Detect which patterns match in message
   */
  detectPatterns(text) {
    const matched = [];

    for (const category in this.attackChainPatterns) {
      for (let i = 0; i < this.attackChainPatterns[category].length; i++) {
        const pattern = this.attackChainPatterns[category][i];
        if (pattern.test(text)) {
          matched.push({
            category,
            index: i,
            pattern: pattern.source,
          });
        }
      }
    }

    return matched;
  }

  /**
   * Analyze message history for attack chains
   */
  analyzeAttackChain(history, conversation) {
    if (history.length < 3) return; // Need at least 3 messages

    // Get recent messages (last N messages)
    const recentMessages = history.slice(-this.config.chainLength);

    // Check for sequential attack patterns
    const detectedChains = [];

    for (const category in this.attackChainPatterns) {
      const categoryPatterns = this.attackChainPatterns[category];
      let sequenceMatches = 0;
      let matchedIndices = [];

      // Check if messages follow attack pattern sequence
      for (let i = 0; i < recentMessages.length; i++) {
        const message = recentMessages[i];

        // Check if this message matches the next pattern in sequence
        for (const patternMatch of message.patterns) {
          if (patternMatch.category === category) {
            sequenceMatches++;
            matchedIndices.push(i);
            break;
          }
        }
      }

      // If we found sequential patterns, it's an attack chain
      if (sequenceMatches >= this.config.patternMatchThreshold) {
        detectedChains.push({
          category,
          confidence: sequenceMatches / categoryPatterns.length,
          matchedMessages: matchedIndices,
          severity: 'HIGH',
        });

        this.stats.attackChainsDetected++;
      }
    }

    // Calculate overall suspicion score
    const avgSuspicion = recentMessages.reduce((sum, msg) => sum + msg.suspicionScore, 0) / recentMessages.length;
    conversation.suspicionScore = avgSuspicion;
    conversation.attackChains = detectedChains;

    // Alert if threshold exceeded
    if (detectedChains.length > 0 || avgSuspicion > this.config.suspicionThreshold) {
      this.handleAttackChainDetected(conversation, detectedChains);
    }
  }

  /**
   * Analyze current conversation
   */
  analyzeCurrentConversation() {
    if (!this.currentConversationId) return;

    const conversation = this.conversations.get(this.currentConversationId);
    const history = this.messageHistory.get(this.currentConversationId);

    if (!conversation || !history || history.length < 3) return;

    this.analyzeAttackChain(history, conversation);
  }

  /**
   * Handle detected attack chain
   */
  handleAttackChainDetected(conversation, chains) {
    this.stats.threatsBlocked++;

    console.warn('[Armorly Multi-turn Detector] Attack chain detected:', {
      conversationId: conversation.id,
      chains,
      suspicionScore: conversation.suspicionScore,
    });

    // Show warning to user
    this.showAttackChainWarning(chains, conversation.suspicionScore);

    // Report to background
    this.reportAttackChain(conversation, chains);
  }

  /**
   * Show visual warning about attack chain
   */
  showAttackChainWarning(chains, suspicionScore) {
    const warning = document.createElement('div');
    warning.style.cssText = `
      position: fixed;
      top: 80px;
      right: 20px;
      background: #ff9800;
      color: white;
      padding: 16px 24px;
      border-radius: 8px;
      font-family: system-ui, -apple-system, sans-serif;
      font-size: 14px;
      z-index: 999999;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      max-width: 350px;
      border: 2px solid #f57c00;
    `;

    const header = document.createElement('div');
    header.style.cssText = 'font-weight: bold; margin-bottom: 8px;';
    header.textContent = 'Multi-turn Attack Chain Detected';
    warning.appendChild(header);

    const desc = document.createElement('div');
    desc.style.cssText = 'font-size: 13px; margin-bottom: 12px;';
    desc.textContent = `Armorly detected ${chains.length} attack pattern(s) across recent messages. Suspicion score: ${Math.round(suspicionScore * 100)}%`;
    warning.appendChild(desc);

    // List detected chains
    const chainList = document.createElement('div');
    chainList.style.cssText = 'font-size: 12px; margin-top: 8px;';

    for (const chain of chains) {
      const chainItem = document.createElement('div');
      chainItem.style.cssText = 'margin: 4px 0;';
      chainItem.textContent = `• ${chain.category.replace(/([A-Z])/g, ' $1').trim()} (${Math.round(chain.confidence * 100)}% confidence)`;
      chainList.appendChild(chainItem);
    }

    warning.appendChild(chainList);

    document.body.appendChild(warning);

    // Auto-dismiss after 15 seconds
    setTimeout(() => {
      warning.style.transition = 'opacity 0.3s';
      warning.style.opacity = '0';
      setTimeout(() => warning.remove(), 300);
    }, 15000);
  }

  /**
   * Report attack chain to background
   */
  reportAttackChain(conversation, chains) {
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({
        type: 'MULTI_TURN_ATTACK_DETECTED',
        conversationId: conversation.id,
        chains,
        suspicionScore: conversation.suspicionScore,
        messageCount: conversation.messageCount,
        timestamp: Date.now(),
      }).catch(() => {
        // Service worker may be inactive
      });
    }
  }

  /**
   * Generate unique ID
   */
  generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substring(2);
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      ...this.stats,
      activeConversations: this.conversations.size,
    };
  }

  /**
   * Enable/disable detector
   */
  setEnabled(enabled) {
    this.config.enabled = enabled;

    if (enabled) {
      this.start();
    } else {
      this.stop();
    }
  }
}

// Export for use in content script
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { MultiTurnAttackDetector };
}
