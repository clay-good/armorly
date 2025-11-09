/**
 * Content Sanitizer for Armorly
 * 
 * BLOCKS and REMOVES malicious content from the DOM before AI agents can read it.
 * This is the core blocking engine that transforms Armorly from detection to prevention.
 * 
 * Features:
 * - Removes hidden elements with prompt injections
 * - Neutralizes invisible text
 * - Strips malicious HTML comments
 * - Sanitizes attributes and event handlers
 * - Cleans iframes and embeds
 * - Filters text content for injection patterns
 * 
 * @module content-sanitizer
 * @author Armorly Security Team
 */

// Use global universal prompt injection patterns
const analyzeTextForPromptInjection = window.UniversalPromptPatterns?.analyzeTextForPromptInjection || function() { return []; };
const isNodeHidden = window.UniversalPromptPatterns?.isNodeHidden || function() { return false; };

class ContentSanitizer {
  constructor() {
    /**
     * Statistics
     */
    this.stats = {
      elementsRemoved: 0,
      textSanitized: 0,
      attributesCleaned: 0,
      commentsRemoved: 0,
      totalThreatsBlocked: 0,
    };

    /**
     * Configuration
     */
    this.config = {
      enabled: true,
      aggressiveMode: false, // More aggressive blocking
      removeComments: true,
      sanitizeAttributes: true,
      blockHiddenContent: true,
      logActions: false, // Reduced console noise - set to true for debugging
    };

    /**
     * Whitelist - REMOVED FOR SECURITY
     *
     * Previously had a whitelist for "trusted" sites (GitHub, Stack Overflow, etc.)
     * but this was a security vulnerability because:
     * 1. These sites can contain user-generated malicious content
     * 2. AI agents reading compromised repos/answers can still be attacked
     * 3. No user control over what gets whitelisted
     *
     * If users want to disable protection on specific sites, they should use
     * browser extension controls or we should add per-site toggles in the popup.
     */
    this.whitelist = [];

    /**
     * Dangerous attributes to remove
     */
    this.dangerousAttributes = [
      'onclick', 'onload', 'onerror', 'onmouseover', 'onmouseout',
      'onfocus', 'onblur', 'onchange', 'onsubmit', 'onkeydown',
      'onkeyup', 'onkeypress', 'ondblclick', 'oncontextmenu',
    ];

    /**
     * Elements removed (for potential restoration)
     */
    this.removedElements = [];
  }

  /**
   * Check if current site is whitelisted
   *
   * NOTE: Whitelist functionality removed for security reasons.
   * This method is kept for backwards compatibility but always returns false.
   */
  isWhitelisted() {
    // Whitelist removed - see comment in constructor
    return false;
  }

  /**
   * Main sanitization entry point
   * Called on page load and for dynamic content
   */
  sanitizePage() {
    if (!this.config.enabled) return;
    // Whitelist check removed - protection now active on all sites

    const startTime = performance.now();

    try {
      // 1. Remove malicious comments
      if (this.config.removeComments) {
        this.removeComments();
      }

      // 2. Sanitize hidden elements
      if (this.config.blockHiddenContent) {
        this.sanitizeHiddenElements();
      }

      // 3. Clean attributes
      if (this.config.sanitizeAttributes) {
        this.sanitizeAttributes();
      }

      // 4. Sanitize text nodes
      this.sanitizeTextNodes();

      // 5. Clean iframes
      this.sanitizeIframes();

      const elapsed = performance.now() - startTime;
      
      if (this.config.logActions && this.stats.totalThreatsBlocked > 0) {
        console.log(`[Armorly Sanitizer] Blocked ${this.stats.totalThreatsBlocked} threats in ${elapsed.toFixed(2)}ms`);
        console.log('[Armorly Sanitizer] Stats:', this.stats);
      }
    } catch (error) {
      console.error('[Armorly Sanitizer] Error during sanitization:', error);
    }
  }

  /**
   * Remove HTML comments containing prompt injections
   */
  removeComments() {
    // Safety check: document.body might not exist at document_start
    if (!document.body) {
      console.warn('[Armorly Sanitizer] document.body not ready, skipping comment removal');
      return;
    }

    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_COMMENT,
      null,
      false
    );

    const commentsToRemove = [];
    let node;

    while ((node = walker.nextNode())) {
      const comment = node.textContent.trim();
      
      // Check if comment contains prompt injection patterns
      const threats = analyzeTextForPromptInjection(comment, {
        source: 'html-comment',
        url: window.location.href,
      });

      if (threats.length > 0) {
        commentsToRemove.push(node);
        this.stats.commentsRemoved++;
        this.stats.totalThreatsBlocked++;
      }
    }

    // Remove malicious comments
    commentsToRemove.forEach(comment => {
      try {
        if (this.config.logActions) {
          console.log('[Armorly Sanitizer] Removed malicious comment:', comment.textContent.substring(0, 100));
        }
        comment.remove();
      } catch (error) {
        console.error('[Armorly Sanitizer] Failed to remove comment:', error);
      }
    });
  }

  /**
   * Sanitize hidden elements with suspicious content
   */
  sanitizeHiddenElements() {
    const allElements = document.querySelectorAll('*');
    const elementsToRemove = [];

    allElements.forEach(element => {
      // Skip if already processed
      if (element.hasAttribute('data-armorly-sanitized')) return;

      // Check if element is hidden
      const hidden = isNodeHidden(element);
      
      if (hidden) {
        const text = element.textContent?.trim() || '';
        
        if (text.length > 10) {
          // Check for prompt injection in hidden text
          const threats = analyzeTextForPromptInjection(text, {
            source: 'hidden-element',
            url: window.location.href,
          });

          if (threats.length > 0) {
            elementsToRemove.push({
              element,
              reason: 'hidden-with-injection',
              text: text.substring(0, 100),
            });
            this.stats.elementsRemoved++;
            this.stats.totalThreatsBlocked++;
          }
        }
      }

      // Mark as processed
      element.setAttribute('data-armorly-sanitized', 'true');
    });

    // Remove malicious hidden elements
    elementsToRemove.forEach(({ element, reason, text }) => {
      try {
        if (this.config.logActions) {
          console.log(`[Armorly Sanitizer] Removed ${reason}:`, text);
        }

        // Store for potential restoration
        this.removedElements.push({
          element: element.cloneNode(true),
          parent: element.parentNode,
          reason,
          timestamp: Date.now(),
        });

        element.remove();
      } catch (error) {
        console.error(`[Armorly Sanitizer] Failed to remove element (${reason}):`, error);
      }
    });
  }

  /**
   * Sanitize dangerous attributes
   */
  sanitizeAttributes() {
    const allElements = document.querySelectorAll('*');

    allElements.forEach(element => {
      let cleaned = false;

      // Remove dangerous event handlers
      this.dangerousAttributes.forEach(attr => {
        if (element.hasAttribute(attr)) {
          element.removeAttribute(attr);
          cleaned = true;
          this.stats.attributesCleaned++;
        }
      });

      // Check data attributes for injections
      Array.from(element.attributes).forEach(attr => {
        if (attr.name.startsWith('data-')) {
          const threats = analyzeTextForPromptInjection(attr.value, {
            source: 'data-attribute',
            url: window.location.href,
          });

          if (threats.length > 0) {
            element.removeAttribute(attr.name);
            cleaned = true;
            this.stats.attributesCleaned++;
            this.stats.totalThreatsBlocked++;
          }
        }
      });

      if (cleaned && this.config.logActions) {
        console.log('[Armorly Sanitizer] Cleaned attributes on:', element.tagName);
      }
    });
  }

  /**
   * Sanitize text nodes for prompt injections
   */
  sanitizeTextNodes() {
    // Safety check: document.body might not exist at document_start
    if (!document.body) {
      console.warn('[Armorly Sanitizer] document.body not ready, skipping text node sanitization');
      return;
    }

    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
      null,
      false
    );

    let node;
    const nodesToSanitize = [];

    while ((node = walker.nextNode())) {
      const text = node.textContent?.trim() || '';
      
      if (text.length < 10) continue;

      // Check for prompt injection
      const threats = analyzeTextForPromptInjection(text, {
        source: 'text-node',
        url: window.location.href,
      });

      if (threats.length > 0) {
        nodesToSanitize.push({ node, threats });
      }
    }

    // Sanitize text nodes
    nodesToSanitize.forEach(({ node, threats }) => {
      let sanitizedText = node.textContent;

      // Remove or neutralize injection patterns
      threats.forEach(threat => {
        if (threat.match) {
          // Replace injection with safe text
          sanitizedText = sanitizedText.replace(threat.match, '[BLOCKED BY ARMORLY]');
          this.stats.textSanitized++;
          this.stats.totalThreatsBlocked++;
        }
      });

      if (sanitizedText !== node.textContent) {
        if (this.config.logActions) {
          console.log('[Armorly Sanitizer] Sanitized text node:', node.textContent.substring(0, 50));
        }
        node.textContent = sanitizedText;
      }
    });
  }

  /**
   * Sanitize iframes
   */
  sanitizeIframes() {
    const iframes = document.querySelectorAll('iframe');

    iframes.forEach(iframe => {
      try {
        const src = iframe.getAttribute('src');

        if (src) {
          // Check if iframe src contains injection patterns
          const threats = analyzeTextForPromptInjection(src, {
            source: 'iframe-src',
            url: window.location.href,
          });

          if (threats.length > 0) {
            if (this.config.logActions) {
              console.log('[Armorly Sanitizer] Blocked malicious iframe:', src);
            }
            iframe.remove();
            this.stats.elementsRemoved++;
            this.stats.totalThreatsBlocked++;
          }
        }
      } catch (error) {
        console.error('[Armorly Sanitizer] Failed to remove iframe:', error);
      }
    });
  }

  /**
   * Get sanitization statistics
   */
  getStats() {
    return { ...this.stats };
  }

  /**
   * Reset statistics
   */
  resetStats() {
    this.stats = {
      elementsRemoved: 0,
      textSanitized: 0,
      attributesCleaned: 0,
      commentsRemoved: 0,
      totalThreatsBlocked: 0,
    };
  }

  /**
   * Enable/disable sanitization
   */
  setEnabled(enabled) {
    this.config.enabled = enabled;
  }
}

// Export for use in content script
if (typeof window !== 'undefined') {
  window.ContentSanitizer = ContentSanitizer;
}

