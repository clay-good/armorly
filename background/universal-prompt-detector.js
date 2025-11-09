/**
 * Universal Prompt Injection Detector
 *
 * Detects prompt injection attacks across ALL agentic browsers.
 * Works independently of browser-specific APIs.
 *
 * Detection Methods:
 * 1. Pattern matching (instruction keywords, special tokens)
 * 2. Context analysis (hidden content, suspicious positioning)
 * 3. Semantic analysis (instruction-like language)
 * 4. Behavioral heuristics (unusual combinations)
 * 5. Web Worker offloading for heavy analysis (performance optimization)
 */

import {
  PROMPT_INJECTION_PATTERNS,
  INSTRUCTION_KEYWORDS,
  SUSPICIOUS_URL_PATTERNS,
  analyzeTextForPromptInjection,
  analyzeNodeForPromptInjection,
  isNodeHidden,
  calculateThreatScore
} from '../lib/universal-prompt-patterns.js';

import { workerManager } from '../lib/worker-manager.js';

export class UniversalPromptDetector {
  constructor() {
    this.threatCallback = null;
    this.statistics = {
      patternsDetected: 0,
      hiddenContentDetected: 0,
      semanticThreatsDetected: 0,
      totalScans: 0,
      workerUsed: 0,
      fallbackUsed: 0,
    };

    // Use shared patterns from universal-prompt-patterns.js
    this.promptInjectionPatterns = PROMPT_INJECTION_PATTERNS;
    this.instructionKeywords = INSTRUCTION_KEYWORDS;
    this.suspiciousURLPatterns = SUSPICIOUS_URL_PATTERNS;

    // Worker manager for offloading heavy analysis
    this.workerManager = workerManager;
    this.useWorker = true; // Can be toggled for testing
  }

  /**
   * Set threat callback
   * @param {Function} callback - Callback function for threats
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }

  /**
   * Analyze text for prompt injection
   * @param {string} text - Text to analyze
   * @param {Object} context - Context information (source, url, etc.)
   * @returns {Promise<Array<Object>>} Detected threats
   */
  async analyzeText(text, context = {}) {
    this.statistics.totalScans++;

    let threats = [];

    // Try to use worker for heavy analysis
    if (this.useWorker && text.length > 100) {
      try {
        const workerResult = await this.workerManager.analyzePromptInjection(text);

        if (workerResult.detected) {
          // Convert worker result to threat format
          threats = workerResult.threats.map(threat => ({
            type: 'PROMPT_INJECTION',
            severity: threat.severity || 'MEDIUM',
            score: threat.score || 0,
            description: `Prompt injection detected: ${threat.type}`,
            context: { ...context, workerAnalysis: true },
            evidence: threat,
          }));

          this.statistics.workerUsed++;
        }
      } catch (error) {
        // Fallback to main thread analysis
        console.warn('[UniversalPromptDetector] Worker failed, using fallback:', error.message);
        threats = analyzeTextForPromptInjection(text, context);
        this.statistics.fallbackUsed++;
      }
    } else {
      // Use main thread for short texts or when worker is disabled
      threats = analyzeTextForPromptInjection(text, context);
      this.statistics.fallbackUsed++;
    }

    // Update statistics
    threats.forEach(threat => {
      if (threat.type === 'PROMPT_INJECTION') {
        this.statistics.patternsDetected++;
      } else if (threat.type === 'SEMANTIC_PROMPT_INJECTION') {
        this.statistics.semanticThreatsDetected++;
      } else if (threat.type === 'HIDDEN_PROMPT_INJECTION') {
        this.statistics.hiddenContentDetected++;
      }
    });

    // Report threats
    if (threats.length > 0 && this.threatCallback) {
      threats.forEach(threat => this.threatCallback(threat));
    }

    return threats;
  }

  /**
   * Analyze DOM node for prompt injection
   * @param {Element} node - DOM node to analyze
   * @param {Object} context - Context information
   * @returns {Array<Object>} Detected threats
   */
  analyzeNode(node, context = {}) {
    this.statistics.totalScans++;

    // Use shared universal prompt injection analysis for nodes
    const threats = analyzeNodeForPromptInjection(node, context);

    // Update statistics
    threats.forEach(threat => {
      if (threat.type === 'PROMPT_INJECTION') {
        this.statistics.patternsDetected++;
      } else if (threat.type === 'SEMANTIC_PROMPT_INJECTION') {
        this.statistics.semanticThreatsDetected++;
      } else if (threat.type === 'HIDDEN_PROMPT_INJECTION') {
        this.statistics.hiddenContentDetected++;
      }
    });

    // Report threats
    if (threats.length > 0 && this.threatCallback) {
      threats.forEach(threat => this.threatCallback(threat));
    }

    return threats;
  }

  /**
   * Detect pattern-based threats
   * @param {string} text - Text to analyze
   * @param {Object} context - Context information
   * @returns {Array<Object>} Detected threats
   */
  detectPatterns(text, context) {
    const threats = [];

    for (const pattern of this.promptInjectionPatterns) {
      const matches = text.match(pattern);
      if (matches) {
        this.statistics.patternsDetected++;
        threats.push({
          type: 'PROMPT_INJECTION',
          severity: 'high',
          pattern: pattern.source,
          match: matches[0],
          text: text.substring(Math.max(0, matches.index - 50), Math.min(text.length, matches.index + matches[0].length + 50)),
          source: context.source || 'unknown',
          url: context.url || '',
          timestamp: Date.now(),
        });
      }
    }

    return threats;
  }

  /**
   * Detect semantic threats (instruction-like language)
   * @param {string} text - Text to analyze
   * @param {Object} context - Context information
   * @returns {Array<Object>} Detected threats
   */
  detectSemanticThreats(text, context) {
    const threats = [];
    const lowerText = text.toLowerCase();

    // Count instruction keywords
    let keywordCount = 0;
    const foundKeywords = [];

    for (const keyword of this.instructionKeywords) {
      if (lowerText.includes(keyword.toLowerCase())) {
        keywordCount++;
        foundKeywords.push(keyword);
      }
    }

    // If multiple instruction keywords found, flag as suspicious
    if (keywordCount >= 3) {
      this.statistics.semanticThreatsDetected++;
      threats.push({
        type: 'SEMANTIC_PROMPT_INJECTION',
        severity: 'medium',
        reason: `Multiple instruction keywords detected: ${foundKeywords.join(', ')}`,
        keywordCount,
        keywords: foundKeywords,
        source: context.source || 'unknown',
        url: context.url || '',
        timestamp: Date.now(),
      });
    }

    return threats;
  }

  /**
   * Detect suspicious URLs
   * @param {string} text - Text to analyze
   * @param {Object} context - Context information
   * @returns {Array<Object>} Detected threats
   */
  detectSuspiciousURLs(text, context) {
    const threats = [];

    for (const pattern of this.suspiciousURLPatterns) {
      const matches = text.match(pattern);
      if (matches) {
        threats.push({
          type: 'SUSPICIOUS_URL',
          severity: 'medium',
          url: matches[0],
          reason: 'Suspicious URL pattern detected',
          source: context.source || 'unknown',
          timestamp: Date.now(),
        });
      }
    }

    return threats;
  }

  /**
   * Detect obfuscation attempts
   * @param {string} text - Text to analyze
   * @param {Object} context - Context information
   * @returns {Array<Object>} Detected threats
   */
  detectObfuscation(text, context) {
    const threats = [];

    // Check for zero-width characters
    const zeroWidthChars = ['\u200b', '\u200c', '\u200d', '\ufeff'];
    let zeroWidthCount = 0;

    for (const char of zeroWidthChars) {
      const count = (text.match(new RegExp(char, 'g')) || []).length;
      zeroWidthCount += count;
    }

    if (zeroWidthCount > 5) {
      threats.push({
        type: 'OBFUSCATION_ATTEMPT',
        severity: 'high',
        reason: `Excessive zero-width characters detected (${zeroWidthCount})`,
        count: zeroWidthCount,
        source: context.source || 'unknown',
        url: context.url || '',
        timestamp: Date.now(),
      });
    }

    return threats;
  }

  /**
   * Check if node is hidden
   * @param {Element} node - DOM node
   * @returns {boolean} True if hidden
   */
  isNodeHidden(node) {
    if (!node || !node.style) return false;

    const style = window.getComputedStyle(node);
    
    return (
      style.display === 'none' ||
      style.visibility === 'hidden' ||
      style.opacity === '0' ||
      parseFloat(style.opacity) === 0 ||
      node.hidden === true ||
      node.getAttribute('aria-hidden') === 'true' ||
      parseInt(style.width) === 0 ||
      parseInt(style.height) === 0 ||
      parseInt(style.left) < -1000 ||
      parseInt(style.top) < -1000
    );
  }

  /**
   * Get statistics
   * @returns {Object} Statistics
   */
  getStatistics() {
    return { ...this.statistics };
  }

  /**
   * Reset statistics
   */
  resetStatistics() {
    this.statistics = {
      patternsDetected: 0,
      hiddenContentDetected: 0,
      semanticThreatsDetected: 0,
      totalScans: 0,
    };
  }
}

