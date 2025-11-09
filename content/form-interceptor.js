/**
 * Form Interceptor for Armorly
 * 
 * Intercepts and sanitizes form submissions and text inputs BEFORE they reach AI agents.
 * This is CRITICAL for preventing prompt injection attacks like Gandalf.
 * 
 * Features:
 * - Monitors all textarea and input fields
 * - Intercepts form submissions
 * - Sanitizes text BEFORE sending to AI
 * - Blocks malicious prompts
 * - Real-time input validation
 * - Context-aware detection
 * 
 * @module form-interceptor
 * @author Armorly Security Team
 */

class FormInterceptor {
  constructor() {
    /**
     * Statistics
     */
    this.stats = {
      formsMonitored: 0,
      inputsMonitored: 0,
      submissionsBlocked: 0,
      inputsSanitized: 0,
      threatsDetected: 0,
    };

    /**
     * Configuration
     */
    this.config = {
      enabled: true,
      blockMaliciousSubmissions: true,
      sanitizeInputs: true,
      monitorTextareas: true,
      monitorInputs: true,
      showWarnings: true,
      logActions: true,
    };

    /**
     * Monitored elements
     */
    this.monitoredElements = new WeakSet();

    /**
     * Blocked submissions
     */
    this.blockedSubmissions = [];
  }

  /**
   * Start form interception
   */
  start() {
    if (!this.config.enabled) return;

    try {
      // Monitor existing forms
      this.monitorExistingForms();

      // Monitor new forms
      this.observeNewForms();

      // Intercept form submissions
      this.interceptSubmissions();

      // Monitor input changes
      this.monitorInputChanges();

      console.log('[Armorly FormInterceptor] Started - INPUT PROTECTION ACTIVE');
    } catch (error) {
      console.error('[Armorly FormInterceptor] Error starting:', error);
    }
  }

  /**
   * Monitor existing forms
   */
  monitorExistingForms() {
    // Monitor all textareas
    if (this.config.monitorTextareas) {
      document.querySelectorAll('textarea').forEach(textarea => {
        this.monitorElement(textarea);
      });
    }

    // Monitor all text inputs
    if (this.config.monitorInputs) {
      document.querySelectorAll('input[type="text"], input[type="search"], input:not([type])').forEach(input => {
        this.monitorElement(input);
      });
    }

    // Monitor all forms
    document.querySelectorAll('form').forEach(form => {
      this.monitorForm(form);
    });
  }

  /**
   * Observe new forms being added
   */
  observeNewForms() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach(mutation => {
        mutation.addedNodes.forEach(node => {
          if (node.nodeType === Node.ELEMENT_NODE) {
            // Check if it's a form
            if (node.tagName === 'FORM') {
              this.monitorForm(node);
            }

            // Check if it's a textarea or input
            if (node.tagName === 'TEXTAREA' && this.config.monitorTextareas) {
              this.monitorElement(node);
            }

            if (node.tagName === 'INPUT' && this.config.monitorInputs) {
              const type = node.getAttribute('type');
              if (!type || type === 'text' || type === 'search') {
                this.monitorElement(node);
              }
            }

            // Check children
            if (this.config.monitorTextareas) {
              node.querySelectorAll?.('textarea').forEach(textarea => {
                this.monitorElement(textarea);
              });
            }

            if (this.config.monitorInputs) {
              node.querySelectorAll?.('input[type="text"], input[type="search"], input:not([type])').forEach(input => {
                this.monitorElement(input);
              });
            }

            node.querySelectorAll?.('form').forEach(form => {
              this.monitorForm(form);
            });
          }
        });
      });
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
    });
  }

  /**
   * Monitor a form
   */
  monitorForm(form) {
    if (this.monitoredElements.has(form)) return;

    this.monitoredElements.add(form);
    this.stats.formsMonitored++;

    // Intercept submit event
    form.addEventListener('submit', (event) => {
      this.handleFormSubmit(event, form);
    }, true);
  }

  /**
   * Monitor an input element
   */
  monitorElement(element) {
    if (this.monitoredElements.has(element)) return;

    this.monitoredElements.add(element);
    this.stats.inputsMonitored++;

    // Monitor input changes
    element.addEventListener('input', (event) => {
      this.handleInputChange(event, element);
    });

    // Monitor before input (can prevent)
    element.addEventListener('beforeinput', (event) => {
      this.handleBeforeInput(event, element);
    });
  }

  /**
   * Intercept all form submissions globally
   */
  interceptSubmissions() {
    // Capture phase to intercept before other handlers
    document.addEventListener('submit', (event) => {
      const form = event.target;
      if (form.tagName === 'FORM') {
        this.handleFormSubmit(event, form);
      }
    }, true);
  }

  /**
   * Monitor input changes globally
   */
  monitorInputChanges() {
    // Monitor all input events
    document.addEventListener('input', (event) => {
      const element = event.target;
      if (element.tagName === 'TEXTAREA' || element.tagName === 'INPUT') {
        this.handleInputChange(event, element);
      }
    }, true);
  }

  /**
   * Handle form submission
   */
  handleFormSubmit(event, form) {
    // Get all text inputs in the form
    const textInputs = form.querySelectorAll('textarea, input[type="text"], input[type="search"], input:not([type])');

    let hasThreats = false;
    const threats = [];

    textInputs.forEach(input => {
      const value = input.value;
      const inputThreats = this.analyzeText(value);

      if (inputThreats.length > 0) {
        hasThreats = true;
        threats.push({
          element: input,
          threats: inputThreats,
          value: value,
        });
      }
    });

    if (hasThreats) {
      if (this.config.blockMaliciousSubmissions) {
        // Block the submission
        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation();

        this.stats.submissionsBlocked++;
        this.stats.threatsDetected += threats.length;

        this.logBlockedSubmission(form, threats);

        if (this.config.showWarnings) {
          this.showWarning('Armorly blocked a potentially malicious prompt injection attempt.');
        }

        if (this.config.logActions) {
          console.warn('[Armorly FormInterceptor] Blocked form submission with threats:', threats);
        }

        return false;
      } else if (this.config.sanitizeInputs) {
        // Sanitize the inputs
        threats.forEach(({ element, threats: inputThreats }) => {
          const sanitized = this.sanitizeText(element.value, inputThreats);
          element.value = sanitized;
          this.stats.inputsSanitized++;
        });

        if (this.config.logActions) {
          console.log('[Armorly FormInterceptor] Sanitized form inputs before submission');
        }
      }
    }
  }

  /**
   * Handle input change
   */
  handleInputChange(event, element) {
    const value = element.value;
    const threats = this.analyzeText(value);

    if (threats.length > 0) {
      this.stats.threatsDetected++;

      if (this.config.sanitizeInputs) {
        // Sanitize in real-time
        const sanitized = this.sanitizeText(value, threats);
        if (sanitized !== value) {
          element.value = sanitized;
          this.stats.inputsSanitized++;

          if (this.config.logActions) {
            console.log('[Armorly FormInterceptor] Sanitized input in real-time');
          }
        }
      }
    }
  }

  /**
   * Handle before input (can prevent)
   */
  handleBeforeInput(event, element) {
    // Check if the input data contains threats
    if (event.data) {
      const threats = this.analyzeText(event.data);

      if (threats.length > 0 && this.config.blockMaliciousSubmissions) {
        // Prevent the input
        event.preventDefault();
        this.stats.threatsDetected++;

        if (this.config.showWarnings) {
          this.showWarning('Armorly blocked potentially malicious input.');
        }
      }
    }
  }

  /**
   * Analyze text for threats
   */
  analyzeText(text) {
    if (!text || typeof text !== 'string') return [];

    // Use global pattern analyzer if available
    if (typeof window.UniversalPromptPatterns?.analyzeTextForPromptInjection === 'function') {
      return window.UniversalPromptPatterns.analyzeTextForPromptInjection(text, {
        source: 'form-input',
        url: window.location.href,
      });
    }

    // Fallback: basic pattern matching
    const threats = [];
    const patterns = [
      /ignore\s+(previous|all|above|prior)\s+(instructions|prompts?|commands?)/i,
      /disregard\s+(previous|all|above|prior)\s+(instructions|prompts?|commands?)/i,
      /forget\s+(previous|all|above|prior)\s+(instructions|prompts?|commands?)/i,
      /you\s+are\s+now\s+a/i,
      /system\s*:/i,
      /\[SYSTEM\]/i,
      /override\s+(instructions|settings|rules)/i,
      /new\s+(instructions|prompt|system)/i,
    ];

    patterns.forEach((pattern, index) => {
      if (pattern.test(text)) {
        threats.push({
          type: 'prompt-injection',
          pattern: pattern.toString(),
          match: text.match(pattern)?.[0],
          severity: 'high',
        });
      }
    });

    return threats;
  }

  /**
   * Sanitize text by removing threats
   */
  sanitizeText(text, threats) {
    let sanitized = text;

    threats.forEach(threat => {
      if (threat.match) {
        sanitized = sanitized.replace(threat.match, '[BLOCKED BY ARMORLY]');
      }
    });

    return sanitized;
  }

  /**
   * Log blocked submission
   */
  logBlockedSubmission(form, threats) {
    this.blockedSubmissions.push({
      form: form.action || form.id || 'unknown',
      threats: threats.map(t => ({
        value: t.value.substring(0, 100),
        threatCount: t.threats.length,
        types: t.threats.map(th => th.type),
      })),
      timestamp: Date.now(),
    });

    // Keep only last 50
    if (this.blockedSubmissions.length > 50) {
      this.blockedSubmissions.shift();
    }
  }

  /**
   * Show warning to user
   * SILENT MODE: Disabled for background operation
   */
  showWarning(message) {
    // Silent mode - log only, no visible notifications
    console.warn('[Armorly Form Interceptor]', message);
    return;

    // Notifications disabled for silent background operation
    /* const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: #ff4444;
      color: white;
      padding: 15px 20px;
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      z-index: 999999;
      font-family: system-ui, -apple-system, sans-serif;
      font-size: 14px;
      max-width: 300px;
    `;
    notification.textContent = message;

    document.body.appendChild(notification);

    // Remove after 5 seconds
    setTimeout(() => {
      notification.remove();
    }, 5000); */
  }

  /**
   * Get statistics
   */
  getStats() {
    return { ...this.stats };
  }

  /**
   * Get blocked submissions
   */
  getBlockedSubmissions() {
    return [...this.blockedSubmissions];
  }

  /**
   * Stop monitoring
   */
  stop() {
    this.config.enabled = false;
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
  window.FormInterceptor = FormInterceptor;
}

