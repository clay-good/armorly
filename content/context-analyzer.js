/**
 * Context Analyzer for Armorly
 * 
 * Analyzes conversation context to detect sophisticated prompt injection attempts.
 * Uses behavioral analysis and conversation flow to identify threats.
 * 
 * Features:
 * - Conversation history tracking
 * - Context-aware threat detection
 * - Behavioral pattern analysis
 * - Multi-turn attack detection
 * - Intent classification
 * - Anomaly detection
 * 
 * @module context-analyzer
 * @author Armorly Security Team
 */

class ContextAnalyzer {
  constructor() {
    /**
     * Statistics
     */
    this.stats = {
      messagesAnalyzed: 0,
      threatsDetected: 0,
      anomaliesDetected: 0,
      contextViolations: 0,
    };

    /**
     * Configuration
     */
    this.config = {
      enabled: true,
      maxHistoryLength: 50,
      anomalyThreshold: 0.7,
      logActions: true,
    };

    /**
     * Conversation history
     */
    this.conversationHistory = [];

    /**
     * User behavior baseline
     */
    this.userBaseline = {
      avgMessageLength: 0,
      avgWordsPerMessage: 0,
      commonTopics: new Set(),
      typicalSentiment: 'neutral',
    };

    /**
     * Suspicious context patterns
     */
    this.suspiciousPatterns = {
      // Role manipulation
      roleManipulation: [
        /you are now/i,
        /act as/i,
        /pretend to be/i,
        /roleplay as/i,
        /simulate/i,
      ],
      
      // Instruction override
      instructionOverride: [
        /ignore (previous|all|above|prior)/i,
        /disregard (previous|all|above|prior)/i,
        /forget (previous|all|above|prior)/i,
        /override/i,
        /new instructions/i,
      ],
      
      // System prompt extraction
      systemExtraction: [
        /what are your instructions/i,
        /show me your prompt/i,
        /reveal your system/i,
        /what is your system prompt/i,
        /print your instructions/i,
      ],
      
      // Jailbreak attempts
      jailbreak: [
        /DAN mode/i,
        /developer mode/i,
        /god mode/i,
        /unrestricted/i,
        /without limitations/i,
      ],
      
      // Context injection
      contextInjection: [
        /\[SYSTEM\]/i,
        /\[INST\]/i,
        /\[\/INST\]/i,
        /<\|system\|>/i,
        /<\|user\|>/i,
      ],
    };

    /**
     * Intent categories
     */
    this.intentCategories = {
      benign: ['question', 'request', 'clarification', 'feedback'],
      suspicious: ['manipulation', 'extraction', 'override', 'jailbreak'],
      malicious: ['injection', 'exploit', 'attack'],
    };
  }

  /**
   * Start context analysis
   */
  start() {
    if (!this.config.enabled) return;

    try {
      // Load conversation history
      this.loadHistory();

      // Monitor input fields
      this.monitorInputs();

      console.log('[Armorly ContextAnalyzer] Started - Context analysis active');
    } catch (error) {
      console.error('[Armorly ContextAnalyzer] Error starting:', error);
    }
  }

  /**
   * Monitor input fields
   */
  monitorInputs() {
    // Monitor all text inputs
    document.addEventListener('input', (event) => {
      const element = event.target;
      
      if (element.tagName === 'TEXTAREA' || element.tagName === 'INPUT') {
        this.analyzeInput(element.value);
      }
    }, true);
  }

  /**
   * Analyze input with context
   */
  analyzeInput(text) {
    if (!text || text.length < 10) return { safe: true };

    this.stats.messagesAnalyzed++;

    // Add to conversation history
    this.addToHistory('user', text);

    // Analyze the message
    const analysis = {
      text: text,
      timestamp: Date.now(),
      threats: [],
      anomalies: [],
      intent: null,
      riskScore: 0,
      safe: true,
    };

    // Pattern-based detection
    analysis.threats = this.detectPatterns(text);

    // Context-based detection
    const contextThreats = this.analyzeContext(text);
    analysis.threats.push(...contextThreats);

    // Behavioral anomaly detection
    const anomalies = this.detectAnomalies(text);
    analysis.anomalies = anomalies;

    // Intent classification
    analysis.intent = this.classifyIntent(text, analysis.threats);

    // Calculate risk score
    analysis.riskScore = this.calculateRiskScore(analysis);

    // Determine if safe
    analysis.safe = analysis.riskScore < 0.5;

    // Update statistics
    if (analysis.threats.length > 0) {
      this.stats.threatsDetected++;
    }

    if (analysis.anomalies.length > 0) {
      this.stats.anomaliesDetected++;
    }

    // Log if suspicious
    if (!analysis.safe && this.config.logActions) {
      console.warn('[Armorly ContextAnalyzer] Suspicious input detected:', analysis);
    }

    return analysis;
  }

  /**
   * Detect pattern-based threats
   */
  detectPatterns(text) {
    const threats = [];

    for (const [category, patterns] of Object.entries(this.suspiciousPatterns)) {
      for (const pattern of patterns) {
        if (pattern.test(text)) {
          threats.push({
            type: category,
            pattern: pattern.toString(),
            match: text.match(pattern)?.[0],
            severity: this.getSeverity(category),
          });
        }
      }
    }

    return threats;
  }

  /**
   * Analyze context for threats
   */
  analyzeContext(text) {
    const threats = [];

    // Check for context switching
    if (this.isContextSwitch(text)) {
      threats.push({
        type: 'context-switch',
        severity: 'high',
        description: 'Detected attempt to switch conversation context',
      });
      this.stats.contextViolations++;
    }

    // Check for multi-turn attacks
    if (this.isMultiTurnAttack(text)) {
      threats.push({
        type: 'multi-turn-attack',
        severity: 'critical',
        description: 'Detected multi-turn attack pattern',
      });
    }

    // Check for gradual manipulation
    if (this.isGradualManipulation()) {
      threats.push({
        type: 'gradual-manipulation',
        severity: 'high',
        description: 'Detected gradual manipulation attempt',
      });
    }

    return threats;
  }

  /**
   * Detect behavioral anomalies
   */
  detectAnomalies(text) {
    const anomalies = [];

    // Check message length anomaly
    const lengthAnomaly = this.checkLengthAnomaly(text);
    if (lengthAnomaly) {
      anomalies.push(lengthAnomaly);
      this.stats.anomaliesDetected++;
    }

    // Check vocabulary anomaly
    const vocabAnomaly = this.checkVocabularyAnomaly(text);
    if (vocabAnomaly) {
      anomalies.push(vocabAnomaly);
    }

    // Check structure anomaly
    const structureAnomaly = this.checkStructureAnomaly(text);
    if (structureAnomaly) {
      anomalies.push(structureAnomaly);
    }

    return anomalies;
  }

  /**
   * Check if context switch is occurring
   */
  isContextSwitch(text) {
    if (this.conversationHistory.length < 3) return false;

    // Get recent messages
    const recent = this.conversationHistory.slice(-3);

    // Check for sudden topic change with instruction keywords
    const hasInstructionKeywords = /now|instead|actually|forget|ignore/i.test(text);
    const topicChanged = this.hasTopicChanged(text, recent);

    return hasInstructionKeywords && topicChanged;
  }

  /**
   * Check if multi-turn attack is occurring
   */
  isMultiTurnAttack(text) {
    if (this.conversationHistory.length < 5) return false;

    // Look for escalating manipulation across turns
    const recent = this.conversationHistory.slice(-5);
    
    let manipulationScore = 0;
    for (const msg of recent) {
      if (msg.role === 'user') {
        // Check for manipulation keywords
        if (/please|help|just|try|can you/i.test(msg.content)) {
          manipulationScore++;
        }
      }
    }

    // If current message has strong manipulation and history shows buildup
    const hasStrongManipulation = /ignore|override|system|instructions/i.test(text);
    
    return manipulationScore >= 3 && hasStrongManipulation;
  }

  /**
   * Check for gradual manipulation
   */
  isGradualManipulation() {
    if (this.conversationHistory.length < 10) return false;

    // Analyze trend in message complexity and manipulation attempts
    const recent = this.conversationHistory.slice(-10);
    
    let complexityTrend = 0;
    let prevComplexity = 0;

    for (const msg of recent) {
      if (msg.role === 'user') {
        const complexity = this.calculateComplexity(msg.content);
        if (complexity > prevComplexity) {
          complexityTrend++;
        }
        prevComplexity = complexity;
      }
    }

    // Increasing complexity might indicate gradual manipulation
    return complexityTrend >= 5;
  }

  /**
   * Check length anomaly
   */
  checkLengthAnomaly(text) {
    if (this.conversationHistory.length < 5) return null;

    const avgLength = this.userBaseline.avgMessageLength;
    const currentLength = text.length;

    // If message is 3x longer than average, it's anomalous
    if (avgLength > 0 && currentLength > avgLength * 3) {
      return {
        type: 'length-anomaly',
        severity: 'medium',
        expected: avgLength,
        actual: currentLength,
      };
    }

    return null;
  }

  /**
   * Check vocabulary anomaly
   */
  checkVocabularyAnomaly(text) {
    // Check for technical/system vocabulary that's unusual
    const technicalTerms = [
      'system', 'prompt', 'instruction', 'override', 'bypass',
      'jailbreak', 'token', 'parameter', 'config', 'admin',
    ];

    const termCount = technicalTerms.filter(term => 
      text.toLowerCase().includes(term)
    ).length;

    if (termCount >= 3) {
      return {
        type: 'vocabulary-anomaly',
        severity: 'high',
        termCount: termCount,
      };
    }

    return null;
  }

  /**
   * Check structure anomaly
   */
  checkStructureAnomaly(text) {
    // Check for unusual structure (e.g., multiple special characters, brackets)
    const specialCharCount = (text.match(/[[\]<>{}|]/g) || []).length;
    const lineBreaks = (text.match(/\n/g) || []).length;

    if (specialCharCount > 10 || lineBreaks > 5) {
      return {
        type: 'structure-anomaly',
        severity: 'medium',
        specialChars: specialCharCount,
        lineBreaks: lineBreaks,
      };
    }

    return null;
  }

  /**
   * Classify intent
   */
  classifyIntent(text, threats) {
    if (threats.length === 0) {
      return 'benign';
    }

    // Check severity of threats
    const hasCritical = threats.some(t => t.severity === 'critical');
    const hasHigh = threats.some(t => t.severity === 'high');

    if (hasCritical) {
      return 'malicious';
    } else if (hasHigh) {
      return 'suspicious';
    } else {
      return 'questionable';
    }
  }

  /**
   * Calculate risk score
   */
  calculateRiskScore(analysis) {
    let score = 0;

    // Threat contribution
    for (const threat of analysis.threats) {
      switch (threat.severity) {
        case 'critical': score += 0.4; break;
        case 'high': score += 0.25; break;
        case 'medium': score += 0.15; break;
        case 'low': score += 0.05; break;
      }
    }

    // Anomaly contribution
    for (const anomaly of analysis.anomalies) {
      switch (anomaly.severity) {
        case 'high': score += 0.2; break;
        case 'medium': score += 0.1; break;
        case 'low': score += 0.05; break;
      }
    }

    // Cap at 1.0
    return Math.min(score, 1.0);
  }

  /**
   * Get severity for category
   */
  getSeverity(category) {
    const severityMap = {
      roleManipulation: 'high',
      instructionOverride: 'critical',
      systemExtraction: 'high',
      jailbreak: 'critical',
      contextInjection: 'critical',
    };

    return severityMap[category] || 'medium';
  }

  /**
   * Check if topic has changed
   */
  hasTopicChanged(text, recentMessages) {
    // Simple topic change detection based on keyword overlap
    const currentWords = new Set(text.toLowerCase().split(/\s+/));
    
    for (const msg of recentMessages) {
      const msgWords = new Set(msg.content.toLowerCase().split(/\s+/));
      const overlap = [...currentWords].filter(w => msgWords.has(w)).length;
      
      if (overlap > 3) {
        return false; // Topic hasn't changed
      }
    }

    return true; // Topic changed
  }

  /**
   * Calculate message complexity
   */
  calculateComplexity(text) {
    const words = text.split(/\s+/).length;
    const sentences = text.split(/[.!?]+/).length;
    const avgWordLength = text.replace(/\s/g, '').length / words;
    
    return words * 0.5 + sentences * 0.3 + avgWordLength * 0.2;
  }

  /**
   * Add message to history
   */
  addToHistory(role, content) {
    this.conversationHistory.push({
      role,
      content,
      timestamp: Date.now(),
    });

    // Update baseline
    this.updateBaseline(content);

    // Trim history
    if (this.conversationHistory.length > this.config.maxHistoryLength) {
      this.conversationHistory.shift();
    }

    // Save history
    this.saveHistory();
  }

  /**
   * Update user baseline
   */
  updateBaseline(text) {
    const userMessages = this.conversationHistory.filter(m => m.role === 'user');
    
    if (userMessages.length > 0) {
      const totalLength = userMessages.reduce((sum, m) => sum + m.content.length, 0);
      this.userBaseline.avgMessageLength = totalLength / userMessages.length;

      const totalWords = userMessages.reduce((sum, m) => 
        sum + m.content.split(/\s+/).length, 0
      );
      this.userBaseline.avgWordsPerMessage = totalWords / userMessages.length;
    }
  }

  /**
   * Load conversation history
   */
  async loadHistory() {
    try {
      const data = await chrome.storage.local.get(['conversationHistory']);
      if (data.conversationHistory) {
        this.conversationHistory = data.conversationHistory;
      }
    } catch (error) {
      // Ignore errors
    }
  }

  /**
   * Save conversation history
   */
  async saveHistory() {
    try {
      await chrome.storage.local.set({
        conversationHistory: this.conversationHistory.slice(-this.config.maxHistoryLength)
      });
    } catch (error) {
      // Ignore errors
    }
  }

  /**
   * Get statistics
   */
  getStats() {
    return { ...this.stats };
  }

  /**
   * Enable/disable
   */
  setEnabled(enabled) {
    this.config.enabled = enabled;
  }
}

// Export for use in content script
if (typeof window !== 'undefined') {
  window.ContextAnalyzer = ContextAnalyzer;
}

