/**
 * DOM Mutation Blocker for Armorly
 * 
 * Intercepts DOM mutations and sanitizes content BEFORE it's rendered.
 * Prevents post-load prompt injection attacks.
 * 
 * Features:
 * - Monitors all DOM changes
 * - Sanitizes new nodes before rendering
 * - Blocks malicious dynamic content
 * - Prevents JavaScript-based injections
 * - Protects against timing attacks
 * 
 * @module mutation-blocker
 * @author Armorly Security Team
 */

// Use global sanitizer
const getSanitizer = () => window.armorlySanitizer;

class MutationBlocker {
  constructor() {
    /**
     * MutationObserver instance
     */
    this.observer = null;

    /**
     * Statistics
     */
    this.stats = {
      mutationsObserved: 0,
      nodesBlocked: 0,
      attributesBlocked: 0,
      totalBlocked: 0,
    };

    /**
     * Configuration
     */
    this.config = {
      enabled: true,
      observeAttributes: true,
      observeChildList: true,
      observeSubtree: true,
      logActions: false, // Set to true for debugging
    };

    /**
     * Blocked mutations (for debugging)
     */
    this.blockedMutations = [];
  }

  /**
   * Start monitoring DOM mutations
   */
  start() {
    if (!this.config.enabled) return;
    if (this.observer) return; // Already started

    this.observer = new MutationObserver((mutations) => {
      this.handleMutations(mutations);
    });

    // Start observing
    this.observer.observe(document.documentElement, {
      childList: this.config.observeChildList,
      subtree: this.config.observeSubtree,
      attributes: this.config.observeAttributes,
      attributeOldValue: true,
      characterData: true,
      characterDataOldValue: true,
    });

    console.log('[Armorly MutationBlocker] Started monitoring DOM mutations');
  }

  /**
   * Stop monitoring
   */
  stop() {
    if (this.observer) {
      this.observer.disconnect();
      this.observer = null;
      console.log('[Armorly MutationBlocker] Stopped monitoring');
    }
  }

  /**
   * Handle mutations
   */
  handleMutations(mutations) {
    this.stats.mutationsObserved += mutations.length;

    mutations.forEach(mutation => {
      try {
        if (mutation.type === 'childList') {
          this.handleChildListMutation(mutation);
        } else if (mutation.type === 'attributes') {
          this.handleAttributeMutation(mutation);
        } else if (mutation.type === 'characterData') {
          this.handleCharacterDataMutation(mutation);
        }
      } catch (error) {
        console.error('[Armorly MutationBlocker] Error handling mutation:', error);
      }
    });
  }

  /**
   * Handle child list mutations (new nodes added)
   */
  handleChildListMutation(mutation) {
    const addedNodes = Array.from(mutation.addedNodes);

    addedNodes.forEach(node => {
      // Skip text nodes and already processed nodes
      if (node.nodeType === Node.TEXT_NODE) return;
      if (node.hasAttribute && node.hasAttribute('data-armorly-sanitized')) return;

      // Check if node or its children contain threats
      const shouldBlock = this.shouldBlockNode(node);

      if (shouldBlock) {
        this.blockNode(node, 'malicious-content');
      } else {
        // Sanitize the node
        this.sanitizeNode(node);
      }
    });
  }

  /**
   * Handle attribute mutations
   */
  handleAttributeMutation(mutation) {
    const element = mutation.target;
    const attributeName = mutation.attributeName;
    const newValue = element.getAttribute(attributeName);

    // Check if attribute is dangerous
    const dangerousAttributes = [
      'onclick', 'onload', 'onerror', 'onmouseover', 'onmouseout',
      'onfocus', 'onblur', 'onchange', 'onsubmit',
    ];

    if (dangerousAttributes.includes(attributeName)) {
      element.removeAttribute(attributeName);
      this.stats.attributesBlocked++;
      this.stats.totalBlocked++;

      if (this.config.logActions) {
        console.log(`[Armorly MutationBlocker] Blocked dangerous attribute: ${attributeName}`);
      }
      return;
    }

    // Check if attribute value contains injection
    if (newValue && typeof newValue === 'string') {
      const threats = this.analyzeText(newValue);
      
      if (threats.length > 0) {
        element.removeAttribute(attributeName);
        this.stats.attributesBlocked++;
        this.stats.totalBlocked++;

        if (this.config.logActions) {
          console.log(`[Armorly MutationBlocker] Blocked malicious attribute: ${attributeName}="${newValue}"`);
        }
      }
    }
  }

  /**
   * Handle character data mutations (text changes)
   */
  handleCharacterDataMutation(mutation) {
    const node = mutation.target;
    const newText = node.textContent;

    if (newText && newText.length > 10) {
      const threats = this.analyzeText(newText);

      if (threats.length > 0) {
        // Replace with safe text
        node.textContent = '[BLOCKED BY ARMORLY]';
        this.stats.nodesBlocked++;
        this.stats.totalBlocked++;

        if (this.config.logActions) {
          console.log('[Armorly MutationBlocker] Blocked malicious text change:', newText.substring(0, 50));
        }
      }
    }
  }

  /**
   * Check if node should be blocked
   */
  shouldBlockNode(node) {
    // Check if node is hidden with suspicious content
    if (this.isHidden(node)) {
      const text = node.textContent?.trim() || '';
      
      if (text.length > 10) {
        const threats = this.analyzeText(text);
        return threats.length > 0;
      }
    }

    // Check for malicious iframes
    if (node.tagName === 'IFRAME') {
      const src = node.getAttribute('src');
      if (src) {
        const threats = this.analyzeText(src);
        return threats.length > 0;
      }
    }

    // Check for script tags with suspicious content
    if (node.tagName === 'SCRIPT') {
      const content = node.textContent || '';
      const threats = this.analyzeText(content);
      return threats.length > 0;
    }

    return false;
  }

  /**
   * Block a node
   */
  blockNode(node, reason) {
    if (this.config.logActions) {
      console.log(`[Armorly MutationBlocker] Blocking node (${reason}):`, node);
    }

    // Store for debugging
    this.blockedMutations.push({
      node: node.cloneNode(true),
      reason,
      timestamp: Date.now(),
    });

    // Remove the node
    if (node.parentNode) {
      node.parentNode.removeChild(node);
    }

    this.stats.nodesBlocked++;
    this.stats.totalBlocked++;
  }

  /**
   * Sanitize a node
   */
  sanitizeNode(node) {
    const sanitizer = getSanitizer();
    if (!sanitizer) return;

    // Mark as sanitized to avoid re-processing
    if (node.setAttribute) {
      node.setAttribute('data-armorly-sanitized', 'true');
    }

    // Sanitize attributes
    if (node.attributes) {
      const dangerousAttributes = [
        'onclick', 'onload', 'onerror', 'onmouseover', 'onmouseout',
        'onfocus', 'onblur', 'onchange', 'onsubmit',
      ];

      dangerousAttributes.forEach(attr => {
        if (node.hasAttribute(attr)) {
          node.removeAttribute(attr);
        }
      });
    }

    // Recursively sanitize children
    if (node.childNodes) {
      Array.from(node.childNodes).forEach(child => {
        if (child.nodeType === Node.ELEMENT_NODE) {
          this.sanitizeNode(child);
        }
      });
    }
  }

  /**
   * Check if node is hidden
   */
  isHidden(node) {
    if (!node.getBoundingClientRect) return false;

    const style = window.getComputedStyle(node);
    const rect = node.getBoundingClientRect();

    return (
      style.display === 'none' ||
      style.visibility === 'hidden' ||
      style.opacity === '0' ||
      rect.width === 0 ||
      rect.height === 0 ||
      rect.top < -1000 ||
      rect.left < -1000
    );
  }

  /**
   * Analyze text for threats
   */
  analyzeText(text) {
    if (typeof window.UniversalPromptPatterns?.analyzeTextForPromptInjection === 'function') {
      return window.UniversalPromptPatterns.analyzeTextForPromptInjection(text, {
        source: 'mutation',
        url: window.location.href,
      });
    }
    return [];
  }

  /**
   * Get statistics
   */
  getStats() {
    return { ...this.stats };
  }

  /**
   * Reset statistics
   */
  resetStats() {
    this.stats = {
      mutationsObserved: 0,
      nodesBlocked: 0,
      attributesBlocked: 0,
      totalBlocked: 0,
    };
  }

  /**
   * Enable/disable
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
if (typeof window !== 'undefined') {
  window.MutationBlocker = MutationBlocker;
}

