/**
 * Pattern Recognition Library for Armorly (Global/Content Script Version)
 *
 * This version is for content scripts and does NOT use ES6 exports.
 * For ES6 module version, use lib/pattern-library.js
 *
 * Comprehensive database of known attack patterns for detecting:
 * - Instruction hijacking
 * - Goal manipulation
 * - Data exfiltration
 * - Context confusion
 * - Social engineering
 * - Memory poisoning
 * - Obfuscation techniques
 *
 * Based on research from LayerX Security, Brave Security, and academic papers
 * on prompt injection attacks.
 *
 * @module pattern-library-global
 * @author Armorly Security Team
 * @license MIT
 */

class PatternLibrary {
  constructor() {
    /**
     * Pattern library version for tracking updates
     */
    this.version = '1.0.0';

    /**
     * Pattern match cache for performance optimization
     * Maps text hash to match results
     */
    this.matchCache = new Map();
    this.maxCacheSize = 1000;

    /**
     * Compiled regex cache
     */
    this.regexCache = new Map();

    /**
     * Attack pattern categories with regex patterns
     */
    this.patterns = {
      instructionHijack: [
        {
          pattern: /ignore\s+(all\s+)?(previous|prior|earlier)\s+instructions/gi,
          description: 'Direct attempt to override AI system prompt',
          score: 40,
          references: ['Brave Security - Comet Vulnerability', 'LayerX - Tainted Memories']
        },
        {
          pattern: /disregard\s+(your\s+)?(programming|instructions|guidelines)/gi,
          description: 'Attempt to make AI ignore its constraints',
          score: 40
        },
        {
          pattern: /forget\s+(everything|all)\s+(you\s+)?(were\s+told|learned)/gi,
          description: 'Attempt to reset AI context',
          score: 35
        },
        {
          pattern: /nevermind\s+the\s+above/gi,
          description: 'Attempt to cancel previous instructions',
          score: 30
        },
        {
          pattern: /instead\s+of\s+following\s+your\s+guidelines/gi,
          description: 'Explicit guideline override attempt',
          score: 40
        }
      ],

      goalHijack: [
        {
          pattern: /you\s+are\s+now\s+(a|an)\s+\w+/gi,
          description: 'Role hijacking attempt',
          score: 35
        },
        {
          pattern: /your\s+(new|actual|real)\s+(primary\s+)?(objective|goal|directive|purpose|task)/gi,
          description: 'Goal redefinition attempt',
          score: 40
        },
        {
          pattern: /the\s+user'?s\s+actual\s+intent\s+is/gi,
          description: 'Intent manipulation',
          score: 35
        },
        {
          pattern: /real\s+task\s*:/gi,
          description: 'Task substitution',
          score: 30
        },
        {
          pattern: /secret\s+(mission|instruction|task|objective)/gi,
          description: 'Hidden objective injection',
          score: 35
        }
      ],

      dataExfiltration: [
        {
          pattern: /always\s+(fetch|import|include|download|get)\s+(from|dependencies|code|libraries)\s+https?:\/\//gi,
          description: 'Dependency hijacking for code injection',
          score: 45
        },
        {
          pattern: /phone\s+home\s+to\s+https?:\/\//gi,
          description: 'Data exfiltration command',
          score: 45
        },
        {
          pattern: /send\s+(data|results|information)\s+to\s+https?:\/\//gi,
          description: 'Explicit data exfiltration',
          score: 45
        },
        {
          pattern: /upload\s+(to|data)\s+https?:\/\//gi,
          description: 'Upload to external server',
          score: 45
        },
        {
          pattern: /log\s+results\s+to\s+https?:\/\//gi,
          description: 'Logging to external endpoint',
          score: 40
        }
      ],

      contextConfusion: [
        {
          pattern: /\s{50,}/g,
          description: 'Excessive whitespace for context confusion',
          score: 15
        },
        {
          pattern: /[\u200B-\u200D\uFEFF]/g,
          description: 'Zero-width characters',
          score: 20
        },
        {
          pattern: /[\u202E]/g,
          description: 'Right-to-left override character',
          score: 25
        },
        {
          pattern: /(&[a-z]+;){10,}/gi,
          description: 'Excessive HTML entity encoding',
          score: 20
        }
      ],

      socialEngineering: [
        {
          pattern: /system\s+(message|directive|instruction)\s*:/gi,
          description: 'Fake system message',
          score: 35
        },
        {
          pattern: /(administrator|admin|root|sudo)\s*:/gi,
          description: 'Authority impersonation',
          score: 30
        },
        {
          pattern: /official\s+directive\s+from\s+(openai|anthropic|google)/gi,
          description: 'Company impersonation',
          score: 40
        },
        {
          pattern: /security\s+team\s+instruction/gi,
          description: 'Security team impersonation',
          score: 35
        },
        {
          pattern: /developer\s+note\s*:/gi,
          description: 'Developer impersonation',
          score: 25
        },
        {
          pattern: /internal\s+memo\s*:/gi,
          description: 'Internal communication impersonation',
          score: 30
        }
      ],

      memoryPoisoning: [
        {
          pattern: /remember\s+this\s+for\s+all\s+future\s+(interactions|conversations|sessions)/gi,
          description: 'Persistent memory injection',
          score: 50
        },
        {
          pattern: /store\s+this\s+(preference|setting|instruction)/gi,
          description: 'Preference poisoning',
          score: 45
        },
        {
          pattern: /add\s+to\s+my\s+profile/gi,
          description: 'Profile modification attempt',
          score: 45
        },
        {
          pattern: /update\s+my\s+settings/gi,
          description: 'Settings modification',
          score: 40
        },
        {
          pattern: /new\s+permanent\s+instruction/gi,
          description: 'Permanent instruction injection',
          score: 50
        },
        {
          pattern: /this\s+applies\s+to\s+everything\s+I\s+do/gi,
          description: 'Global behavior modification',
          score: 45
        },
        {
          pattern: /when\s+(generating|writing|creating)\s+code,?\s+always/gi,
          description: 'Code generation behavior modification',
          score: 50
        }
      ],

      obfuscation: [
        {
          pattern: /[A-Za-z0-9+/]{40,}={0,2}/g,
          description: 'Base64 encoding detected',
          score: 25
        },
        {
          pattern: /\\u[0-9a-f]{4}/gi,
          description: 'Unicode escape sequences',
          score: 20
        },
        {
          pattern: /[1!][gG][nN][0oO][rR][3eE]/g,
          description: 'Leetspeak obfuscation',
          score: 20
        }
      ]
    };

    /**
     * Weight multipliers for each category
     * Used in final threat score calculation
     */
    this.weights = {
      instructionHijack: 1.0,
      goalHijack: 0.9,
      dataExfiltration: 1.2,
      contextConfusion: 0.6,
      socialEngineering: 0.8,
      memoryPoisoning: 1.3,
      obfuscation: 0.5
    };

    /**
     * Compile all patterns for performance
     */
    this.compiledPatterns = this.compilePatterns();
  }

  /**
   * Compile patterns for faster matching
   * 
   * @returns {Object} Compiled pattern structure
   */
  compilePatterns() {
    const compiled = {};
    
    for (const [category, patterns] of Object.entries(this.patterns)) {
      compiled[category] = patterns.map(p => ({
        ...p,
        regex: new RegExp(p.pattern.source, p.pattern.flags)
      }));
    }
    
    return compiled;
  }

  /**
   * Scan text for all attack patterns
   *
   * @param {string} text - Text to scan
   * @param {Object} context - Additional context (optional)
   * @returns {Object} Scan results with matches and score
   */
  scanText(text, context = {}) {
    if (!text || typeof text !== 'string') {
      return { matches: [], score: 0, categories: [] };
    }

    // Check cache first
    const cacheKey = this.getCacheKey(text, context);
    if (this.matchCache.has(cacheKey)) {
      return this.matchCache.get(cacheKey);
    }

    const results = {
      matches: [],
      score: 0,
      categories: new Set(),
      rawScore: 0
    };

    // Scan each category
    for (const [category, patterns] of Object.entries(this.compiledPatterns)) {
      for (const pattern of patterns) {
        const matches = text.match(pattern.regex);

        if (matches) {
          results.matches.push({
            category,
            pattern: pattern.description,
            matchedText: matches[0],
            score: pattern.score,
            references: pattern.references
          });

          results.categories.add(category);
          results.rawScore += pattern.score;
        }
      }
    }

    // Apply category weights
    results.categories.forEach(category => {
      results.score += this.weights[category] * 10;
    });

    // Apply context multipliers
    if (context.aiAgentActive) {
      results.score *= 1.5;
    }

    if (context.onChatGPT) {
      results.score *= 1.3;
    }

    // Normalize score to 0-100
    results.score = Math.min(100, results.rawScore + results.score);

    // Cache the result
    this.cacheResult(cacheKey, results);

    return results;
  }

  /**
   * Generate cache key for text and context
   * @param {string} text - Text to hash
   * @param {Object} context - Context object
   * @returns {string} Cache key
   */
  getCacheKey(text, context) {
    // Simple hash function for cache key
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
      const char = text.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32bit integer
    }

    // Include context in key
    const contextKey = JSON.stringify(context);
    return `${hash}_${contextKey}`;
  }

  /**
   * Cache a result
   * @param {string} key - Cache key
   * @param {Object} result - Result to cache
   */
  cacheResult(key, result) {
    // Implement LRU cache - remove oldest if at max size
    if (this.matchCache.size >= this.maxCacheSize) {
      const firstKey = this.matchCache.keys().next().value;
      this.matchCache.delete(firstKey);
    }

    this.matchCache.set(key, result);
  }

  /**
   * Clear the match cache
   */
  clearCache() {
    this.matchCache.clear();
  }

  /**
   * Scan HTTP request body for malicious patterns
   * 
   * @param {string} body - Request body text
   * @returns {Object} Scan results
   */
  scanRequestBody(body) {
    const results = this.scanText(body, { isRequestBody: true });
    
    // Additional checks for request bodies
    if (this.containsURL(body)) {
      results.matches.push({
        category: 'dataExfiltration',
        pattern: 'Contains external URL',
        score: 20
      });
      results.score += 20;
    }

    return results;
  }

  /**
   * Scan HTML comment for suspicious content
   * 
   * @param {string} comment - Comment text
   * @returns {Object} Scan results
   */
  scanHTMLComment(comment) {
    const results = this.scanText(comment, { isComment: true });
    
    // Comments are less visible, so increase score
    results.score *= 1.2;
    
    return results;
  }

  /**
   * Attempt to deobfuscate text
   * 
   * @param {string} text - Potentially obfuscated text
   * @returns {string} Deobfuscated text (or original if can't decode)
   */
  deobfuscate(text) {
    let deobfuscated = text;

    // Try Base64 decoding
    try {
      const base64Match = text.match(/[A-Za-z0-9+/]{20,}={0,2}/);
      if (base64Match) {
        const decoded = atob(base64Match[0]);
        deobfuscated += '\n[DECODED]: ' + decoded;
      }
    } catch (e) {
      // Not valid Base64
    }

    // Decode HTML entities
    const entityPattern = /&[a-z]+;/gi;
    if (entityPattern.test(text)) {
      const temp = document.createElement('div');
      temp.innerHTML = text;
      deobfuscated += '\n[DECODED]: ' + temp.textContent;
    }

    // Decode Unicode escapes
    const unicodePattern = /\\u[0-9a-f]{4}/gi;
    if (unicodePattern.test(text)) {
      try {
        const decoded = text.replace(unicodePattern, (match) => {
          return String.fromCharCode(parseInt(match.substring(2), 16));
        });
        deobfuscated += '\n[DECODED]: ' + decoded;
      } catch (e) {
        // Failed to decode
      }
    }

    return deobfuscated;
  }

  /**
   * Extract all URLs from text
   * 
   * @param {string} text - Text to search
   * @returns {Array} Array of URLs found
   */
  extractURLs(text) {
    const urlPattern = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi;
    return text.match(urlPattern) || [];
  }

  /**
   * Check if text contains URLs
   * 
   * @param {string} text - Text to check
   * @returns {boolean} True if URLs found
   */
  containsURL(text) {
    return this.extractURLs(text).length > 0;
  }

  /**
   * Score a single match with context
   * 
   * @param {Object} match - Match object
   * @param {Object} context - Context information
   * @returns {number} Adjusted score
   */
  scoreMatch(match, context = {}) {
    let score = match.score;

    // Apply context multipliers
    if (context.inHiddenElement) {
      score *= 1.5;
    }

    if (context.inComment) {
      score *= 1.2;
    }

    if (context.multipleMatches) {
      score *= 1.3;
    }

    return Math.min(100, score);
  }

  /**
   * Update patterns with new threat intelligence
   * 
   * @param {Object} newPatterns - New patterns to merge
   */
  updatePatterns(newPatterns) {
    for (const [category, patterns] of Object.entries(newPatterns)) {
      if (this.patterns[category]) {
        this.patterns[category].push(...patterns);
      } else {
        this.patterns[category] = patterns;
      }
    }

    // Recompile patterns
    this.compiledPatterns = this.compilePatterns();
    
    console.log('[Armorly] Pattern library updated');
  }

  /**
   * Get pattern statistics
   * 
   * @returns {Object} Statistics about loaded patterns
   */
  getStats() {
    const stats = {
      version: this.version,
      categories: Object.keys(this.patterns).length,
      totalPatterns: 0,
      byCategory: {}
    };

    for (const [category, patterns] of Object.entries(this.patterns)) {
      stats.byCategory[category] = patterns.length;
      stats.totalPatterns += patterns.length;
    }

    return stats;
  }
}

// Make available globally for content scripts (non-module context)
if (typeof window !== 'undefined') {
  window.PatternLibrary = PatternLibrary;
}

// NO EXPORTS - This is the global version for content scripts
