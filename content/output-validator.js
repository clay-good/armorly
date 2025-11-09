/**
 * Output Validator for Armorly
 * 
 * Validates and sanitizes AI-generated outputs BEFORE they are displayed to users.
 * Protects against LLM02: Insecure Output Handling.
 * 
 * Features:
 * - Monitors DOM mutations for AI responses
 * - Detects malicious patterns in outputs
 * - Sanitizes generated content
 * - Prevents XSS in AI responses
 * - Detects PII leakage
 * - Validates code snippets
 * 
 * @module output-validator
 * @author Armorly Security Team
 */

class OutputValidator {
  constructor() {
    /**
     * Statistics
     */
    this.stats = {
      outputsValidated: 0,
      threatsDetected: 0,
      outputsSanitized: 0,
      piiDetected: 0,
      xssBlocked: 0,
    };

    /**
     * AI Platform Detection
     * Auto-enable output validation only on AI platforms
     */
    const isAIPlatform = this.isAIPlatform();

    /**
     * Configuration
     *
     * UPDATED: Auto-enable on AI platforms only to avoid false positives.
     * This validator is designed for AI-generated content, not regular web pages.
     */
    this.config = {
      enabled: isAIPlatform, // Auto-detect AI platforms
      sanitizeOutputs: isAIPlatform,
      detectPII: isAIPlatform,
      detectXSS: isAIPlatform,
      detectCodeInjection: isAIPlatform,
      logActions: false, // Reduce console noise
    };

    /**
     * PII patterns
     */
    this.piiPatterns = {
      creditCard: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
      ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
      email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
      phone: /\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
      ipAddress: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
    };

    /**
     * XSS patterns
     */
    this.xssPatterns = [
      /<script[^>]*>.*?<\/script>/gi,
      /javascript:/gi,
      /on\w+\s*=/gi,
      /<iframe[^>]*>/gi,
      /<object[^>]*>/gi,
      /<embed[^>]*>/gi,
    ];

    /**
     * Validated elements
     */
    this.validatedElements = new WeakSet();
  }

  /**
   * Start output validation
   */
  start() {
    if (!this.config.enabled) return;

    try {
      // Monitor DOM for new content
      this.observeOutputs();

      // Validate existing content
      this.validateExistingContent();

      console.log('[Armorly OutputValidator] Started - OUTPUT VALIDATION ACTIVE');
    } catch (error) {
      console.error('[Armorly OutputValidator] Error starting:', error);
    }
  }

  /**
   * Observe new outputs being added
   */
  observeOutputs() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach(mutation => {
        mutation.addedNodes.forEach(node => {
          if (node.nodeType === Node.ELEMENT_NODE) {
            this.validateElement(node);
          } else if (node.nodeType === Node.TEXT_NODE) {
            this.validateTextNode(node);
          }
        });

        // Check for text changes
        if (mutation.type === 'characterData') {
          this.validateTextNode(mutation.target);
        }
      });
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      characterData: true,
    });
  }

  /**
   * Validate existing content
   */
  validateExistingContent() {
    // Safety check: document.body might not exist at document_start
    if (!document.body) {
      console.warn('[Armorly OutputValidator] document.body not ready, skipping initial validation');
      return;
    }

    // Validate all text nodes
    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
      null,
      false
    );

    let node;
    while ((node = walker.nextNode())) {
      this.validateTextNode(node);
    }
  }

  /**
   * Validate an element
   */
  validateElement(element) {
    if (this.validatedElements.has(element)) return;
    this.validatedElements.add(element);

    // Check for XSS in attributes
    if (this.config.detectXSS) {
      this.checkElementForXSS(element);
    }

    // Validate text content
    const textContent = element.textContent;
    if (textContent) {
      this.validateText(textContent, element);
    }

    // Validate children
    element.childNodes.forEach(child => {
      if (child.nodeType === Node.ELEMENT_NODE) {
        this.validateElement(child);
      } else if (child.nodeType === Node.TEXT_NODE) {
        this.validateTextNode(child);
      }
    });
  }

  /**
   * Validate a text node
   */
  validateTextNode(node) {
    if (!node.textContent) return;

    const threats = this.validateText(node.textContent, node.parentElement);

    if (threats.length > 0 && this.config.sanitizeOutputs) {
      // Sanitize the text
      const sanitized = this.sanitizeText(node.textContent, threats);
      if (sanitized !== node.textContent) {
        node.textContent = sanitized;
        this.stats.outputsSanitized++;
      }
    }
  }

  /**
   * Validate text content
   */
  validateText(text, element) {
    this.stats.outputsValidated++;

    const threats = [];

    // Check for PII
    if (this.config.detectPII) {
      const piiThreats = this.detectPII(text);
      threats.push(...piiThreats);
    }

    // Check for XSS
    if (this.config.detectXSS) {
      const xssThreats = this.detectXSS(text);
      threats.push(...xssThreats);
    }

    // Check for code injection
    if (this.config.detectCodeInjection) {
      const codeThreats = this.detectCodeInjection(text);
      threats.push(...codeThreats);
    }

    if (threats.length > 0) {
      this.stats.threatsDetected += threats.length;

      if (this.config.logActions) {
        console.warn('[Armorly OutputValidator] Detected threats in output:', threats);
      }
    }

    return threats;
  }

  /**
   * Detect PII in text
   */
  detectPII(text) {
    const threats = [];

    Object.entries(this.piiPatterns).forEach(([type, pattern]) => {
      const matches = text.match(pattern);
      if (matches) {
        matches.forEach(match => {
          threats.push({
            type: 'pii-disclosure',
            subtype: type,
            match: match,
            severity: 'high',
          });
          this.stats.piiDetected++;
        });
      }
    });

    return threats;
  }

  /**
   * Detect XSS in text
   */
  detectXSS(text) {
    const threats = [];

    this.xssPatterns.forEach(pattern => {
      const matches = text.match(pattern);
      if (matches) {
        matches.forEach(match => {
          threats.push({
            type: 'xss-attempt',
            match: match,
            severity: 'critical',
          });
          this.stats.xssBlocked++;
        });
      }
    });

    return threats;
  }

  /**
   * Detect code injection
   */
  detectCodeInjection(text) {
    const threats = [];

    const dangerousPatterns = [
      /eval\s*\(/gi,
      /Function\s*\(/gi,
      /setTimeout\s*\(/gi,
      /setInterval\s*\(/gi,
      /document\.write/gi,
      /innerHTML\s*=/gi,
    ];

    dangerousPatterns.forEach(pattern => {
      const matches = text.match(pattern);
      if (matches) {
        matches.forEach(match => {
          threats.push({
            type: 'code-injection',
            match: match,
            severity: 'high',
          });
        });
      }
    });

    return threats;
  }

  /**
   * Check element for XSS
   */
  checkElementForXSS(element) {
    // Check dangerous attributes
    const dangerousAttrs = [
      'onclick', 'onload', 'onerror', 'onmouseover',
      'onfocus', 'onblur', 'onchange', 'onsubmit',
    ];

    dangerousAttrs.forEach(attr => {
      if (element.hasAttribute(attr)) {
        this.stats.xssBlocked++;
        this.stats.threatsDetected++;

        if (this.config.sanitizeOutputs) {
          element.removeAttribute(attr);
          this.stats.outputsSanitized++;

          if (this.config.logActions) {
            console.warn(`[Armorly OutputValidator] Removed dangerous attribute: ${attr}`);
          }
        }
      }
    });

    // Check for javascript: URLs
    ['href', 'src', 'action'].forEach(attr => {
      const value = element.getAttribute(attr);
      if (value && value.toLowerCase().startsWith('javascript:')) {
        this.stats.xssBlocked++;
        this.stats.threatsDetected++;

        if (this.config.sanitizeOutputs) {
          element.removeAttribute(attr);
          this.stats.outputsSanitized++;

          if (this.config.logActions) {
            console.warn(`[Armorly OutputValidator] Removed javascript: URL from ${attr}`);
          }
        }
      }
    });
  }

  /**
   * Sanitize text by removing/redacting threats
   */
  sanitizeText(text, threats) {
    let sanitized = text;

    threats.forEach(threat => {
      if (threat.match) {
        if (threat.type === 'pii-disclosure') {
          // Redact PII
          const redacted = this.redactPII(threat.match, threat.subtype);
          sanitized = sanitized.replace(threat.match, redacted);
        } else {
          // Block other threats
          sanitized = sanitized.replace(threat.match, '[BLOCKED BY ARMORLY]');
        }
      }
    });

    return sanitized;
  }

  /**
   * Redact PII
   */
  redactPII(value, type) {
    switch (type) {
      case 'creditCard':
        return '****-****-****-' + value.slice(-4);
      case 'ssn':
        return '***-**-' + value.slice(-4);
      case 'email': {
        const [local, domain] = value.split('@');
        return local[0] + '***@' + domain;
      }
      case 'phone':
        return '***-***-' + value.slice(-4);
      case 'ipAddress': {
        const parts = value.split('.');
        return parts[0] + '.***.***.***';
      }
      default:
        return '[REDACTED]';
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
  window.OutputValidator = OutputValidator;
}

