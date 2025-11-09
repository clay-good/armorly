/**
 * Confidence Scorer for Armorly
 * 
 * Scores AI output reliability and warns users about low-confidence responses.
 * Addresses OWASP LLM09: Overreliance
 * 
 * Features:
 * - Confidence scoring for AI outputs
 * - Uncertainty detection
 * - Hallucination indicators
 * - Fact-checking suggestions
 * - Visual confidence indicators
 * - User education
 * 
 * @module confidence-scorer
 * @author Armorly Security Team
 */

class ConfidenceScorer {
  constructor() {
    /**
     * Statistics
     */
    this.stats = {
      outputsScored: 0,
      lowConfidenceDetected: 0,
      warningsShown: 0,
      hallucinationIndicators: 0,
    };

    /**
     * AI Platform Detection
     * Auto-enable confidence scoring only on AI platforms
     */
    const isAIPlatform = this.isAIPlatform();

    /**
     * Configuration
     *
     * UPDATED: Auto-enable on AI platforms only.
     * Designed for ChatGPT, Claude, Perplexity, etc.
     */
    this.config = {
      enabled: isAIPlatform, // Auto-detect AI platforms
      showVisualIndicators: isAIPlatform,
      warnOnLowConfidence: isAIPlatform,
      confidenceThreshold: 0.6,
      logActions: false,
    };

    /**
     * Low confidence indicators
     */
    this.lowConfidenceIndicators = {
      // Hedging language
      hedging: [
        /I think/i,
        /I believe/i,
        /probably/i,
        /possibly/i,
        /might be/i,
        /could be/i,
        /perhaps/i,
        /maybe/i,
        /it seems/i,
        /appears to/i,
      ],
      
      // Uncertainty expressions
      uncertainty: [
        /I'm not sure/i,
        /I don't know/i,
        /uncertain/i,
        /unclear/i,
        /difficult to say/i,
        /hard to tell/i,
        /can't confirm/i,
      ],
      
      // Qualification statements
      qualifications: [
        /however/i,
        /but/i,
        /although/i,
        /on the other hand/i,
        /that said/i,
        /to be fair/i,
      ],
      
      // Vague language
      vagueness: [
        /some/i,
        /various/i,
        /several/i,
        /many/i,
        /often/i,
        /sometimes/i,
        /generally/i,
        /typically/i,
      ],
    };

    /**
     * Hallucination indicators
     */
    this.hallucinationIndicators = {
      // Overly specific false details
      specificDates: /\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b/g,
      specificNumbers: /\b\d{1,3}(,\d{3})*(\.\d+)?\s*(percent|%|dollars?|\$|people|users|customers)\b/gi,
      
      // Contradictions
      contradictions: [
        /but actually/i,
        /correction/i,
        /I meant to say/i,
        /let me clarify/i,
      ],
      
      // Fabricated sources
      sources: [
        /according to (a|the) (study|research|report)/i,
        /studies show/i,
        /research indicates/i,
        /experts say/i,
      ],
    };

    /**
     * Confidence boosters (things that increase confidence)
     */
    this.confidenceBoosters = {
      citations: /\[citation\]|\[source\]|\[ref\]/gi,
      codeBlocks: /```[\s\S]*?```/g,
      structuredData: /\{[\s\S]*?\}|\[[\s\S]*?\]/g,
    };
  }

  /**
   * Start confidence scoring
   */
  start() {
    if (!this.config.enabled) return;

    try {
      // Monitor DOM for AI responses
      this.monitorResponses();

      console.log('[Armorly ConfidenceScorer] Started - Confidence scoring active');
    } catch (error) {
      console.error('[Armorly ConfidenceScorer] Error starting:', error);
    }
  }

  /**
   * Monitor AI responses
   */
  monitorResponses() {
    // Safety check: document.body might not exist at document_start
    if (!document.body) {
      // Wait for DOM ready
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => this.monitorResponses());
      }
      return;
    }

    // Use MutationObserver to detect new content
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.addedNodes.length > 0) {
          mutation.addedNodes.forEach(node => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              this.scoreElement(node);
            }
          });
        }
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
    });
  }

  /**
   * Score an element's content
   */
  scoreElement(element) {
    // Look for text content that looks like AI responses
    const textContent = element.textContent || '';
    
    // Skip short content
    if (textContent.length < 50) return;

    // Skip if already scored
    if (element.hasAttribute('data-armorly-scored')) return;

    // Score the content
    const score = this.scoreText(textContent);

    // Mark as scored
    element.setAttribute('data-armorly-scored', 'true');
    element.setAttribute('data-armorly-confidence', score.confidence.toFixed(2));

    this.stats.outputsScored++;

    // Show visual indicator if enabled
    if (this.config.showVisualIndicators) {
      this.addVisualIndicator(element, score);
    }

    // Warn if low confidence
    if (score.confidence < this.config.confidenceThreshold && this.config.warnOnLowConfidence) {
      this.showLowConfidenceWarning(element, score);
      this.stats.lowConfidenceDetected++;
      this.stats.warningsShown++;
    }

    // Log if enabled
    if (this.config.logActions && score.confidence < 0.7) {
      console.warn('[Armorly ConfidenceScorer] Low confidence output detected:', score);
    }
  }

  /**
   * Score text content
   */
  scoreText(text) {
    const score = {
      confidence: 1.0,
      indicators: [],
      warnings: [],
      suggestions: [],
    };

    // Check for low confidence indicators
    for (const [category, patterns] of Object.entries(this.lowConfidenceIndicators)) {
      let matchCount = 0;
      
      for (const pattern of patterns) {
        const matches = text.match(pattern);
        if (matches) {
          matchCount += matches.length;
        }
      }

      if (matchCount > 0) {
        const penalty = this.calculatePenalty(category, matchCount, text.length);
        score.confidence -= penalty;
        
        score.indicators.push({
          type: category,
          count: matchCount,
          penalty: penalty,
        });
      }
    }

    // Check for hallucination indicators
    const hallucinationScore = this.detectHallucinations(text);
    if (hallucinationScore > 0) {
      score.confidence -= hallucinationScore;
      score.warnings.push('Potential hallucination detected');
      this.stats.hallucinationIndicators++;
    }

    // Check for confidence boosters
    const boostScore = this.detectConfidenceBoosters(text);
    score.confidence += boostScore;

    // Clamp between 0 and 1
    score.confidence = Math.max(0, Math.min(1, score.confidence));

    // Add suggestions based on confidence level
    if (score.confidence < 0.4) {
      score.suggestions.push('Verify this information with authoritative sources');
      score.suggestions.push('Consider this response as potentially unreliable');
    } else if (score.confidence < 0.6) {
      score.suggestions.push('Cross-check key facts before relying on this information');
    } else if (score.confidence < 0.8) {
      score.suggestions.push('This response appears mostly reliable but verify critical details');
    }

    return score;
  }

  /**
   * Calculate penalty for indicator category
   */
  calculatePenalty(category, count, textLength) {
    // Normalize by text length (per 100 words)
    const words = textLength / 5; // Rough estimate
    const normalizedCount = (count / words) * 100;

    const penalties = {
      hedging: 0.05,
      uncertainty: 0.15,
      qualifications: 0.03,
      vagueness: 0.02,
    };

    const basePenalty = penalties[category] || 0.05;
    return Math.min(basePenalty * normalizedCount, 0.3);
  }

  /**
   * Detect hallucination indicators
   */
  detectHallucinations(text) {
    let score = 0;

    // Check for overly specific dates without sources
    const dateMatches = text.match(this.hallucinationIndicators.specificDates);
    if (dateMatches && dateMatches.length > 2) {
      score += 0.1;
    }

    // Check for specific numbers without sources
    const numberMatches = text.match(this.hallucinationIndicators.specificNumbers);
    if (numberMatches && numberMatches.length > 3) {
      score += 0.1;
    }

    // Check for contradictions
    for (const pattern of this.hallucinationIndicators.contradictions) {
      if (pattern.test(text)) {
        score += 0.15;
      }
    }

    // Check for unsourced claims
    for (const pattern of this.hallucinationIndicators.sources) {
      if (pattern.test(text)) {
        // If mentions sources but no actual citations, penalize
        if (!text.includes('[') && !text.includes('http')) {
          score += 0.1;
        }
      }
    }

    return Math.min(score, 0.4);
  }

  /**
   * Detect confidence boosters
   */
  detectConfidenceBoosters(text) {
    let boost = 0;

    // Citations boost confidence
    const citations = text.match(this.confidenceBoosters.citations);
    if (citations) {
      boost += Math.min(citations.length * 0.05, 0.15);
    }

    // Code blocks boost confidence (factual, verifiable)
    const codeBlocks = text.match(this.confidenceBoosters.codeBlocks);
    if (codeBlocks) {
      boost += Math.min(codeBlocks.length * 0.03, 0.1);
    }

    return boost;
  }

  /**
   * Add visual confidence indicator
   */
  addVisualIndicator(element, score) {
    // Create indicator badge
    const indicator = document.createElement('div');
    indicator.className = 'armorly-confidence-indicator';
    
    const confidence = score.confidence;
    let color, emoji, label;

    if (confidence >= 0.8) {
      color = '#4CAF50';
      emoji = '✓';
      label = 'High Confidence';
    } else if (confidence >= 0.6) {
      color = '#FFC107';
      emoji = '⚠';
      label = 'Medium Confidence';
    } else {
      color = '#FF5722';
      emoji = '⚠';
      label = 'Low Confidence';
    }

    indicator.style.cssText = `
      position: absolute;
      top: 5px;
      right: 5px;
      background: ${color};
      color: white;
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: bold;
      z-index: 1000;
      cursor: help;
    `;
    indicator.textContent = `${emoji} ${Math.round(confidence * 100)}%`;
    indicator.title = `${label}\n\nConfidence Score: ${(confidence * 100).toFixed(1)}%\n\n${score.suggestions.join('\n')}`;

    // Make parent position relative if needed
    if (getComputedStyle(element).position === 'static') {
      element.style.position = 'relative';
    }

    element.appendChild(indicator);
  }

  /**
   * Show low confidence warning
   */
  showLowConfidenceWarning(element, score) {
    // Create warning banner
    const warning = document.createElement('div');
    warning.className = 'armorly-confidence-warning';
    warning.style.cssText = `
      background: #FFF3CD;
      border: 1px solid #FFC107;
      border-radius: 6px;
      padding: 12px;
      margin: 10px 0;
      font-size: 13px;
      color: #856404;
    `;

    // SECURITY: Use safe DOM methods instead of innerHTML to prevent XSS
    const strong = document.createElement('strong');
    strong.textContent = '⚠️ Armorly Confidence Warning';
    warning.appendChild(strong);

    warning.appendChild(document.createElement('br'));

    const confidenceText = document.createTextNode(
      `This AI response has a low confidence score (${Math.round(score.confidence * 100)}%).`
    );
    warning.appendChild(confidenceText);
    warning.appendChild(document.createElement('br'));

    const ul = document.createElement('ul');
    ul.style.cssText = 'margin: 8px 0 0 20px; padding: 0;';
    score.suggestions.forEach(suggestion => {
      const li = document.createElement('li');
      li.textContent = suggestion; // Safe: textContent escapes HTML
      ul.appendChild(li);
    });
    warning.appendChild(ul);

    // Insert before the element
    element.parentNode?.insertBefore(warning, element);
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

  /**
   * Detect if we're on an AI platform
   * Returns true for ChatGPT, Claude, Perplexity, Gemini, etc.
   */
  isAIPlatform() {
    const hostname = window.location.hostname.toLowerCase();

    const aiPlatforms = [
      'chatgpt.com',
      'chat.openai.com',
      'openai.com',
      'claude.ai',
      'anthropic.com',
      'perplexity.ai',
      'gemini.google.com',
      'bard.google.com',
      'bing.com/chat',
      'you.com',
      'poe.com',
      'character.ai',
      'huggingface.co/chat',
      'phind.com',
      'codeium.com',
    ];

    return aiPlatforms.some(platform => hostname.includes(platform));
  }
}

// Export for use in content script
if (typeof window !== 'undefined') {
  window.ConfidenceScorer = ConfidenceScorer;
}

