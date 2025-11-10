/**
 * Clipboard Protector for Armorly
 * 
 * Monitors and sanitizes clipboard operations to prevent:
 * - Clipboard hijacking
 * - Prompt injection via copy/paste
 * - Malicious content injection
 * - Data exfiltration via clipboard
 * 
 * Features:
 * - Sanitize copied content
 * - Block malicious paste operations
 * - Prevent clipboard hijacking
 * - Monitor clipboard API access
 * - Real-time threat detection
 * 
 * @module clipboard-protector
 * @author Armorly Security Team
 */

class ClipboardProtector {
  constructor() {
    /**
     * Statistics
     */
    this.stats = {
      copyEventsMonitored: 0,
      pasteEventsMonitored: 0,
      threatsBlocked: 0,
      contentSanitized: 0,
    };

    /**
     * Configuration
     */
    this.config = {
      enabled: true,
      sanitizeCopy: true,
      sanitizePaste: true,
      blockMaliciousPaste: true,
      logActions: false, // Set to true for debugging
    };

    /**
     * Original clipboard API methods (for restoration)
     */
    this.originalMethods = {
      writeText: null,
      readText: null,
      write: null,
      read: null,
    };

    /**
     * Blocked clipboard operations
     */
    this.blockedOperations = [];
  }

  /**
   * Start clipboard protection
   */
  start() {
    if (!this.config.enabled) return;

    try {
      // Monitor copy events
      document.addEventListener('copy', (e) => this.handleCopy(e), true);

      // Monitor paste events
      document.addEventListener('paste', (e) => this.handlePaste(e), true);

      // Monitor cut events
      document.addEventListener('cut', (e) => this.handleCut(e), true);

      // Intercept Clipboard API
      this.interceptClipboardAPI();

      console.log('[Armorly ClipboardProtector] Started - Clipboard protection active');
    } catch (error) {
      console.error('[Armorly ClipboardProtector] Error starting:', error);
    }
  }

  /**
   * Stop clipboard protection
   */
  stop() {
    // Restore original clipboard API
    this.restoreClipboardAPI();
    console.log('[Armorly ClipboardProtector] Stopped');
  }

  /**
   * Handle copy events
   */
  handleCopy(event) {
    this.stats.copyEventsMonitored++;

    if (!this.config.sanitizeCopy) return;

    try {
      // Get selected text
      const selection = window.getSelection();
      const selectedText = selection.toString();

      if (!selectedText) return;

      // Check for threats in copied content
      const threats = this.analyzeText(selectedText);

      if (threats.length > 0) {
        // Sanitize the copied content
        const sanitized = this.sanitizeText(selectedText, threats);

        // Replace clipboard content
        event.preventDefault();
        event.clipboardData.setData('text/plain', sanitized);

        this.stats.contentSanitized++;
        this.stats.threatsBlocked++;

        if (this.config.logActions) {
          console.log('[Armorly ClipboardProtector] Sanitized copied content:', threats);
        }
      }
    } catch (error) {
      console.error('[Armorly ClipboardProtector] Error handling copy:', error);
    }
  }

  /**
   * Handle paste events
   */
  handlePaste(event) {
    this.stats.pasteEventsMonitored++;

    if (!this.config.sanitizePaste) return;

    try {
      // Get pasted content
      const pastedText = event.clipboardData.getData('text/plain');

      if (!pastedText) return;

      // Check for threats in pasted content
      const threats = this.analyzeText(pastedText);

      if (threats.length > 0) {
        if (this.config.blockMaliciousPaste) {
          // Block the paste operation
          event.preventDefault();

          this.stats.threatsBlocked++;
          this.logBlockedOperation('paste', pastedText, threats);

          if (this.config.logActions) {
            console.log('[Armorly ClipboardProtector] Blocked malicious paste:', threats);
          }

          // Optionally show user notification
          this.showNotification('Malicious content blocked from paste');
        } else {
          // Sanitize and allow
          const sanitized = this.sanitizeText(pastedText, threats);
          event.preventDefault();

          // Insert sanitized content
          document.execCommand('insertText', false, sanitized);

          this.stats.contentSanitized++;
          this.stats.threatsBlocked++;

          if (this.config.logActions) {
            console.log('[Armorly ClipboardProtector] Sanitized pasted content');
          }
        }
      }
    } catch (error) {
      console.error('[Armorly ClipboardProtector] Error handling paste:', error);
    }
  }

  /**
   * Handle cut events
   */
  handleCut(event) {
    // Treat cut like copy
    this.handleCopy(event);
  }

  /**
   * Intercept Clipboard API
   */
  interceptClipboardAPI() {
    if (!navigator.clipboard) return;

    const self = this;

    // Store original methods
    this.originalMethods.writeText = navigator.clipboard.writeText;
    this.originalMethods.readText = navigator.clipboard.readText;
    this.originalMethods.write = navigator.clipboard.write;
    this.originalMethods.read = navigator.clipboard.read;

    // Intercept writeText
    navigator.clipboard.writeText = async function(text) {
      const threats = self.analyzeText(text);

      if (threats.length > 0) {
        const sanitized = self.sanitizeText(text, threats);
        self.stats.contentSanitized++;
        self.stats.threatsBlocked++;

        if (self.config.logActions) {
          console.log('[Armorly ClipboardProtector] Sanitized clipboard.writeText');
        }

        return self.originalMethods.writeText.call(navigator.clipboard, sanitized);
      }

      return self.originalMethods.writeText.call(navigator.clipboard, text);
    };

    // Intercept readText
    navigator.clipboard.readText = async function() {
      const text = await self.originalMethods.readText.call(navigator.clipboard);

      const threats = self.analyzeText(text);

      if (threats.length > 0) {
        const sanitized = self.sanitizeText(text, threats);
        self.stats.contentSanitized++;

        if (self.config.logActions) {
          console.log('[Armorly ClipboardProtector] Sanitized clipboard.readText');
        }

        return sanitized;
      }

      return text;
    };
  }

  /**
   * Restore original Clipboard API
   */
  restoreClipboardAPI() {
    if (!navigator.clipboard) return;

    if (this.originalMethods.writeText) {
      navigator.clipboard.writeText = this.originalMethods.writeText;
    }
    if (this.originalMethods.readText) {
      navigator.clipboard.readText = this.originalMethods.readText;
    }
  }

  /**
   * Analyze text for threats
   */
  analyzeText(text) {
    if (typeof window.UniversalPromptPatterns?.analyzeTextForPromptInjection === 'function') {
      return window.UniversalPromptPatterns.analyzeTextForPromptInjection(text, {
        source: 'clipboard',
        url: window.location.href,
      });
    }
    return [];
  }

  /**
   * Sanitize text by removing threats
   */
  sanitizeText(text, threats) {
    let sanitized = text;

    threats.forEach(threat => {
      if (threat.match) {
        // Replace threat with safe text
        sanitized = sanitized.replace(threat.match, '[BLOCKED BY ARMORLY]');
      }
    });

    return sanitized;
  }

  /**
   * Log blocked operation
   */
  logBlockedOperation(operation, content, threats) {
    this.blockedOperations.push({
      operation,
      content: content.substring(0, 100),
      threats: threats.map(t => t.type),
      timestamp: Date.now(),
    });

    // Keep only last 50
    if (this.blockedOperations.length > 50) {
      this.blockedOperations.shift();
    }
  }

  /**
   * Show notification to user
   * SILENT MODE: Disabled for background operation
   */
  showNotification(message) {
    // Silent mode - log only, no visible notifications
    console.warn('[Armorly Clipboard Protector]', message);
    return;

    // Notifications disabled for silent background operation
    /* const notification = document.createElement('div');
    notification.textContent = `Armorly: ${message}`;
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: #ef4444;
      color: white;
      padding: 12px 20px;
      border-radius: 8px;
      font-family: system-ui, -apple-system, sans-serif;
      font-size: 14px;
      z-index: 999999;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      animation: slideIn 0.3s ease-out;
    `;

    document.body.appendChild(notification);

    // Remove after 3 seconds
    setTimeout(() => {
      notification.style.animation = 'slideOut 0.3s ease-out';
      setTimeout(() => notification.remove(), 300);
    }, 3000); */
  }

  /**
   * Get statistics
   */
  getStats() {
    return { ...this.stats };
  }

  /**
   * Get blocked operations
   */
  getBlockedOperations() {
    return [...this.blockedOperations];
  }

  /**
   * Enable/disable
   */
  setEnabled(enabled) {
    this.config.enabled = enabled;
    if (!enabled) {
      this.stop();
    } else {
      this.start();
    }
  }
}

// Export for use in content script
if (typeof window !== 'undefined') {
  window.ClipboardProtector = ClipboardProtector;
}

