/**
 * DOM Scanner for Armorly
 *
 * Detects prompt injection attacks embedded in web pages through various techniques:
 * - Invisible text (white-on-white, zero opacity, off-screen positioning)
 * - Hidden iframes with malicious content
 * - Suspicious HTML comments
 * - Canvas/SVG-based text hiding
 * - Form fields with instruction-like content
 *
 * Based on research from Brave Security (Perplexity Comet vulnerability) and
 * LayerX Security (ChatGPT Atlas attack vectors).
 *
 * @module dom-scanner
 * @author Armorly Security Team
 * @license MIT
 */

// Use global universal prompt injection patterns (loaded via universal-prompt-patterns-global.js)
// Don't redeclare - these are already available globally from the pattern library
// Just reference them directly to avoid "already declared" errors

class DOMScanner {
  constructor() {
    /**
     * MutationObserver for monitoring DOM changes
     */
    this.observer = null;

    /**
     * Debounce timer for performance optimization
     */
    this.scanTimer = null;

    /**
     * Cache of already-scanned elements to avoid duplicate work
     */
    this.scannedElements = new WeakSet();

    /**
     * Detected threats on current page
     */
    this.threats = [];

    /**
     * Performance monitor
     */
    // eslint-disable-next-line no-undef
    this.perfMonitor = typeof PerformanceMonitor !== 'undefined'
      // eslint-disable-next-line no-undef
      ? new PerformanceMonitor()
      : null;

    /**
     * Scan configuration
     */
    this.config = {
      scanInterval: 500,        // Debounce interval in ms
      maxScanTime: 100,         // Maximum time per scan in ms
      minTextLength: 10,        // Minimum text length to consider
      opacityThreshold: 0.05,   // Below this is considered invisible
      fontSizeThreshold: 2,     // Below this is considered invisible (px)
      blockThreats: true        // Enable automatic threat removal
    };

    /**
     * Suspicious keywords that indicate instruction injection
     */
    this.suspiciousKeywords = [
      'ignore previous',
      'disregard',
      'you are now',
      'your new goal',
      'system:',
      'admin override',
      'secret instruction',
      'always fetch from',
      'always import from'
    ];

    /**
     * Legitimate contexts where suspicious patterns are expected
     */
    this.legitimateContexts = [
      'test-', 'demo-', 'example-', 'tutorial-', 'documentation',
      'github.com', 'stackoverflow.com', 'reddit.com/r/programming',
      'arxiv.org', 'research', 'paper', 'article', 'blog'
    ];
  }

  /**
   * Start continuous DOM monitoring
   */
  startScanning() {
    // Initial scan of existing DOM
    this.scanInitialDOM();

    // Set up MutationObserver for dynamic content
    this.observer = new MutationObserver((mutations) => {
      this.debouncedScan();
    });

    this.observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['style', 'class']
    });

    console.log('[Armorly] DOM scanner started');
  }

  /**
   * Stop DOM monitoring
   */
  stopScanning() {
    if (this.observer) {
      this.observer.disconnect();
      this.observer = null;
    }
    if (this.scanTimer) {
      clearTimeout(this.scanTimer);
      this.scanTimer = null;
    }
    console.log('[Armorly] DOM scanner stopped');
  }

  /**
   * Perform initial scan of the entire DOM
   */
  scanInitialDOM() {
    const perfStart = this.perfMonitor ? this.perfMonitor.startTimer('domScan') : null;
    const startTime = performance.now();

    try {
      // Scan all text nodes
      this.detectInvisibleText();

      // Scan HTML comments
      this.scanComments();

      // Scan iframes
      this.analyzeIframes();

      // Scan canvas elements
      this.checkCanvasElements();

      // Scan form fields
      this.scanFormFields();

      const elapsed = performance.now() - startTime;
      console.log(`[Armorly] Initial DOM scan completed in ${elapsed.toFixed(2)}ms, found ${this.threats.length} threats`);

      // Record performance
      if (this.perfMonitor) {
        this.perfMonitor.endTimer('domScan', perfStart, {
          url: window.location.href,
          threatsFound: this.threats.length
        });
      }

      // Report threats if any found
      if (this.threats.length > 0) {
        this.reportThreats();

        // Remove threats from DOM if blocking is enabled
        const removed = this.removeThreats();
        if (removed > 0) {
          console.warn(`[Armorly] Removed ${removed} threats from DOM`);
        }
      }
    } catch (error) {
      console.error('[Armorly] Error during initial DOM scan:', error);
    }
  }

  /**
   * Debounced scan function for performance
   */
  debouncedScan() {
    if (this.scanTimer) {
      clearTimeout(this.scanTimer);
    }
    
    this.scanTimer = setTimeout(() => {
      this.scanInitialDOM();
    }, this.config.scanInterval);
  }

  /**
   * Detect invisible text elements on the page
   */
  detectInvisibleText() {
    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
      null,
      false
    );

    let node;
    while ((node = walker.nextNode())) {
      // Skip if already scanned
      if (this.scannedElements.has(node)) continue;
      
      const text = node.textContent.trim();
      if (text.length < this.config.minTextLength) continue;

      const element = node.parentElement;
      if (!element) continue;

      // Calculate visibility
      const visibility = this.calculateVisibility(element);
      
      if (!visibility.isVisible) {
        // Check if text contains suspicious keywords
        const hasSuspiciousContent = this.containsSuspiciousKeywords(text);
        
        if (hasSuspiciousContent) {
          this.threats.push({
            type: 'INVISIBLE_TEXT',
            severity: 'HIGH',
            element: element,
            text: text.substring(0, 200), // Truncate for logging
            reason: visibility.reason,
            score: 45
          });
        }
      }

      this.scannedElements.add(node);
    }
  }

  /**
   * Calculate if an element is actually visible to users
   * 
   * @param {HTMLElement} element - Element to check
   * @returns {Object} Visibility analysis
   */
  calculateVisibility(element) {
    const result = {
      isVisible: true,
      reason: []
    };

    try {
      const style = window.getComputedStyle(element);
      const rect = element.getBoundingClientRect();

      // Check display and visibility
      if (style.display === 'none') {
        result.isVisible = false;
        result.reason.push('display: none');
      }

      if (style.visibility === 'hidden') {
        result.isVisible = false;
        result.reason.push('visibility: hidden');
      }

      // Check opacity
      const opacity = parseFloat(style.opacity);
      if (opacity < this.config.opacityThreshold) {
        result.isVisible = false;
        result.reason.push(`opacity: ${opacity}`);
      }

      // Check font size
      const fontSize = parseFloat(style.fontSize);
      if (fontSize < this.config.fontSizeThreshold) {
        result.isVisible = false;
        result.reason.push(`font-size: ${fontSize}px`);
      }

      // Check color contrast (white on white, etc.)
      const color = style.color;
      const bgColor = style.backgroundColor;
      if (this.isSimilarColor(color, bgColor)) {
        result.isVisible = false;
        result.reason.push('similar text and background color');
      }

      // Check if positioned off-screen
      if (rect.right < 0 || rect.bottom < 0 || 
          rect.left > window.innerWidth || rect.top > window.innerHeight) {
        result.isVisible = false;
        result.reason.push('positioned off-screen');
      }

      // Check for extreme negative positioning
      const left = parseFloat(style.left);
      const top = parseFloat(style.top);
      if (left < -1000 || top < -1000) {
        result.isVisible = false;
        result.reason.push('extreme negative positioning');
      }

      // Check clip-path
      if (style.clipPath && style.clipPath !== 'none') {
        result.isVisible = false;
        result.reason.push('clipped by clip-path');
      }

    } catch (error) {
      console.error('[Armorly] Error calculating visibility:', error);
    }

    return result;
  }

  /**
   * Check if two colors are similar (low contrast)
   * 
   * @param {string} color1 - First color
   * @param {string} color2 - Second color
   * @returns {boolean} True if colors are similar
   */
  isSimilarColor(color1, color2) {
    // Simple heuristic: check if both are very light or very dark
    const isLight = (color) => {
      return color.includes('255') || color.includes('white') || 
             color.includes('rgb(255') || color.includes('rgba(255');
    };
    
    return isLight(color1) && isLight(color2);
  }

  /**
   * Scan HTML comments for suspicious content
   */
  scanComments() {
    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_COMMENT,
      null,
      false
    );

    let node;
    while ((node = walker.nextNode())) {
      const comment = node.textContent.trim();
      
      if (comment.length < this.config.minTextLength) continue;
      if (this.scannedElements.has(node)) continue;

      // Check for suspicious keywords
      if (this.containsSuspiciousKeywords(comment)) {
        this.threats.push({
          type: 'SUSPICIOUS_COMMENT',
          severity: 'MEDIUM',
          element: node.parentElement,
          text: comment.substring(0, 200),
          reason: 'HTML comment contains instruction-like patterns',
          score: 30
        });
      }

      // Check for Base64 encoding
      if (this.containsBase64(comment)) {
        this.threats.push({
          type: 'ENCODED_COMMENT',
          severity: 'MEDIUM',
          element: node.parentElement,
          text: comment.substring(0, 200),
          reason: 'HTML comment contains Base64-encoded content',
          score: 25
        });
      }

      this.scannedElements.add(node);
    }
  }

  /**
   * Analyze iframe elements for suspicious attributes
   */
  analyzeIframes() {
    const iframes = document.querySelectorAll('iframe');
    
    iframes.forEach(iframe => {
      if (this.scannedElements.has(iframe)) return;

      const rect = iframe.getBoundingClientRect();
      const style = window.getComputedStyle(iframe);

      // Check if iframe is hidden
      const isHidden = (
        rect.width === 0 || rect.height === 0 ||
        style.display === 'none' ||
        style.visibility === 'hidden' ||
        parseFloat(style.opacity) < 0.1
      );

      if (isHidden) {
        this.threats.push({
          type: 'HIDDEN_IFRAME',
          severity: 'HIGH',
          element: iframe,
          text: `src: ${iframe.src || 'about:blank'}`,
          reason: 'Hidden iframe detected',
          score: 40
        });
      }

      // Check for data URI or srcdoc with suspicious content
      if (iframe.src && iframe.src.startsWith('data:')) {
        this.threats.push({
          type: 'DATA_URI_IFRAME',
          severity: 'MEDIUM',
          element: iframe,
          text: iframe.src.substring(0, 100),
          reason: 'Iframe with data URI',
          score: 25
        });
      }

      if (iframe.srcdoc && this.containsSuspiciousKeywords(iframe.srcdoc)) {
        this.threats.push({
          type: 'SUSPICIOUS_SRCDOC',
          severity: 'HIGH',
          element: iframe,
          text: iframe.srcdoc.substring(0, 200),
          reason: 'Iframe srcdoc contains suspicious patterns',
          score: 45
        });
      }

      this.scannedElements.add(iframe);
    });
  }

  /**
   * Check canvas elements for suspicious operations
   */
  checkCanvasElements() {
    // Canvas detection is limited without intercepting drawing operations
    // We can only check for hidden canvases
    const canvases = document.querySelectorAll('canvas');
    
    canvases.forEach(canvas => {
      if (this.scannedElements.has(canvas)) return;

      const visibility = this.calculateVisibility(canvas);
      
      if (!visibility.isVisible && canvas.width > 0 && canvas.height > 0) {
        this.threats.push({
          type: 'HIDDEN_CANVAS',
          severity: 'MEDIUM',
          element: canvas,
          text: `${canvas.width}x${canvas.height}`,
          reason: visibility.reason.join(', '),
          score: 20
        });
      }

      this.scannedElements.add(canvas);
    });
  }

  /**
   * Scan form fields for suspicious default values
   */
  scanFormFields() {
    const fields = document.querySelectorAll('input, textarea');
    
    fields.forEach(field => {
      if (this.scannedElements.has(field)) return;

      const value = field.value || field.defaultValue || '';
      const name = field.name || '';

      // Check for suspicious field names
      if (name.toLowerCase().includes('instruction') || 
          name.toLowerCase().includes('ai_') ||
          name.toLowerCase().includes('prompt')) {
        
        this.threats.push({
          type: 'SUSPICIOUS_FORM_FIELD',
          severity: 'LOW',
          element: field,
          text: `name: ${name}, value: ${value.substring(0, 100)}`,
          reason: 'Form field with AI-related name',
          score: 15
        });
      }

      // Check field value for suspicious content
      if (value.length > this.config.minTextLength && 
          this.containsSuspiciousKeywords(value)) {
        
        this.threats.push({
          type: 'SUSPICIOUS_FORM_VALUE',
          severity: 'MEDIUM',
          element: field,
          text: value.substring(0, 200),
          reason: 'Form field contains instruction-like patterns',
          score: 30
        });
      }

      this.scannedElements.add(field);
    });
  }

  /**
   * Check if text contains suspicious keywords
   *
   * @param {string} text - Text to check
   * @returns {boolean} True if suspicious keywords found
   */
  containsSuspiciousKeywords(text) {
    const lowerText = text.toLowerCase();

    // Check if we're in a legitimate context (test page, documentation, etc.)
    if (this.isLegitimateContext()) {
      // Reduce sensitivity for legitimate contexts
      // Only flag if multiple suspicious keywords present
      const matchCount = this.suspiciousKeywords.filter(keyword =>
        lowerText.includes(keyword)
      ).length;
      return matchCount >= 3; // Require 3+ matches in legitimate contexts
    }

    // Normal sensitivity for regular pages
    return this.suspiciousKeywords.some(keyword => lowerText.includes(keyword));
  }

  /**
   * Check if current page is in a legitimate context
   *
   * @returns {boolean} True if legitimate context detected
   */
  isLegitimateContext() {
    const url = window.location.href.toLowerCase();
    const title = document.title.toLowerCase();

    // Check URL and title for legitimate context indicators
    return this.legitimateContexts.some(context =>
      url.includes(context) || title.includes(context)
    );
  }

  /**
   * Check if text contains Base64-encoded content
   *
   * @param {string} text - Text to check
   * @returns {boolean} True if Base64 detected
   */
  containsBase64(text) {
    const base64Pattern = /[A-Za-z0-9+/]{20,}={0,2}/;
    return base64Pattern.test(text);
  }

  /**
   * Remove detected threats from DOM
   */
  removeThreats() {
    if (!this.config.blockThreats) {
      return 0; // Blocking disabled, only detect
    }

    let removed = 0;

    for (const threat of this.threats) {
      if (!threat.element || !threat.element.parentNode) continue;

      try {
        switch (threat.type) {
          case 'INVISIBLE_TEXT':
            // Remove invisible elements with suspicious content
            threat.element.remove();
            removed++;
            console.warn('[Armorly DOM Scanner] Removed invisible threat:', threat.text.substring(0, 50));
            break;

          case 'SUSPICIOUS_COMMENT':
            // Remove HTML comments
            if (threat.element && threat.element.nodeType === Node.COMMENT_NODE) {
              threat.element.remove();
              removed++;
            }
            break;

          case 'SUSPICIOUS_IFRAME':
          case 'SUSPICIOUS_SCRIPT':
            // Remove dangerous elements
            threat.element.remove();
            removed++;
            console.warn('[Armorly DOM Scanner] Removed dangerous element:', threat.type);
            break;

          case 'CANVAS_DATA_URL': {
            // Clear canvas
            const canvas = threat.element;
            if (canvas && canvas.getContext) {
              const ctx = canvas.getContext('2d');
              if (ctx) {
                ctx.clearRect(0, 0, canvas.width, canvas.height);
                removed++;
              }
            }
            break;
          }

          default:
            // For other types, sanitize text content
            if (threat.element.textContent) {
              threat.element.textContent = '[BLOCKED BY ARMORLY]';
              removed++;
            }
        }
      } catch (error) {
        console.error('[Armorly DOM Scanner] Error removing threat:', error);
      }
    }

    if (removed > 0) {
      console.warn(`[Armorly DOM Scanner] Removed ${removed} threats from DOM`);
    }

    return removed;
  }

  /**
   * Report detected threats to background service worker
   */
  reportThreats() {
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({
        type: 'THREATS_DETECTED',
        threats: this.threats,
        url: window.location.href,
        timestamp: Date.now()
      }).catch(error => {
        console.error('[Armorly] Error reporting threats:', error);
      });
    }
  }

  /**
   * Get current threat summary
   * 
   * @returns {Object} Threat summary
   */
  getThreatSummary() {
    const summary = {
      total: this.threats.length,
      byType: {},
      bySeverity: {},
      totalScore: 0
    };

    this.threats.forEach(threat => {
      summary.byType[threat.type] = (summary.byType[threat.type] || 0) + 1;
      summary.bySeverity[threat.severity] = (summary.bySeverity[threat.severity] || 0) + 1;
      summary.totalScore += threat.score;
    });

    return summary;
  }

  /**
   * Clear all detected threats
   */
  clearThreats() {
    this.threats = [];
    this.scannedElements = new WeakSet();
  }
}

// Export for use in content script
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { DOMScanner };
}

