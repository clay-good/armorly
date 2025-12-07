/**
 * Armorly - Hidden Content Blocker
 *
 * Blocks prompt injection attacks hidden in invisible elements:
 * - White text on white background
 * - Zero opacity elements
 * - Off-screen positioned content
 * - Font-size: 0 content
 * - Hidden overflow content
 *
 * These are NEVER legitimate - no false positive risk.
 * A website has no reason to hide text from users but show it to AI.
 */

(function() {
  'use strict';

  // =========================================================================
  // DETECTION FUNCTIONS
  // =========================================================================

  /**
   * Check if an element is visually hidden but contains text
   */
  function isHiddenElement(element) {
    if (!element || element.nodeType !== Node.ELEMENT_NODE) {
      return false;
    }

    const style = window.getComputedStyle(element);
    const rect = element.getBoundingClientRect();

    // Check various hiding techniques
    return (
      isZeroOpacity(style) ||
      isOffScreen(rect, style) ||
      isZeroSize(style) ||
      isClippedAway(style) ||
      isWhiteOnWhite(element, style)
    );
  }

  /**
   * Zero opacity
   */
  function isZeroOpacity(style) {
    return parseFloat(style.opacity) === 0;
  }

  /**
   * Positioned off-screen
   */
  function isOffScreen(rect, style) {
    // Check for negative positioning
    const left = parseFloat(style.left);
    const top = parseFloat(style.top);
    const marginLeft = parseFloat(style.marginLeft);
    const marginTop = parseFloat(style.marginTop);

    if (left < -1000 || top < -1000 || marginLeft < -1000 || marginTop < -1000) {
      return true;
    }

    // Check if element is outside viewport
    if (rect.right < 0 || rect.bottom < 0) {
      return true;
    }

    // Check for transform translations that move element off-screen
    const transform = style.transform;
    if (transform && transform !== 'none') {
      const match = transform.match(/translate[XY]?\(([^)]+)\)/);
      if (match) {
        const value = parseFloat(match[1]);
        if (Math.abs(value) > 1000) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Zero or near-zero size
   */
  function isZeroSize(style) {
    const fontSize = parseFloat(style.fontSize);
    const width = parseFloat(style.width);
    const height = parseFloat(style.height);
    const maxWidth = parseFloat(style.maxWidth);
    const maxHeight = parseFloat(style.maxHeight);

    return (
      fontSize === 0 ||
      (width === 0 && height === 0) ||
      maxWidth === 0 ||
      maxHeight === 0 ||
      (style.width === '1px' && style.height === '1px' && style.overflow === 'hidden')
    );
  }

  /**
   * Clipped away with clip or clip-path
   */
  function isClippedAway(style) {
    // Check clip property (deprecated but still used)
    if (style.clip === 'rect(0px, 0px, 0px, 0px)' || style.clip === 'rect(0, 0, 0, 0)') {
      return true;
    }

    // Check clip-path
    if (style.clipPath === 'inset(100%)' || style.clipPath === 'polygon(0 0, 0 0, 0 0)') {
      return true;
    }

    return false;
  }

  /**
   * White text on white background (or same color as background)
   */
  function isWhiteOnWhite(element, style) {
    const color = style.color;
    const bgColor = style.backgroundColor;

    // Parse colors to compare
    const textColor = parseColor(color);
    const backgroundColor = parseColor(bgColor);

    if (!textColor || !backgroundColor) {
      return false;
    }

    // Check if colors are nearly identical
    const threshold = 30; // Allow small differences
    return (
      Math.abs(textColor.r - backgroundColor.r) < threshold &&
      Math.abs(textColor.g - backgroundColor.g) < threshold &&
      Math.abs(textColor.b - backgroundColor.b) < threshold
    );
  }

  /**
   * Parse CSS color to RGB values
   */
  function parseColor(colorStr) {
    if (!colorStr || colorStr === 'transparent' || colorStr === 'rgba(0, 0, 0, 0)') {
      return null;
    }

    // Handle rgb/rgba format
    const rgbMatch = colorStr.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
    if (rgbMatch) {
      return {
        r: parseInt(rgbMatch[1], 10),
        g: parseInt(rgbMatch[2], 10),
        b: parseInt(rgbMatch[3], 10)
      };
    }

    return null;
  }

  /**
   * Check if element contains text that looks like prompt injection
   */
  function containsPromptInjection(text) {
    if (!text || text.length < 10) {
      return false;
    }

    // Patterns commonly used in prompt injection
    const injectionPatterns = [
      /ignore\s+(?:all\s+)?(?:previous|above|prior)/i,
      /disregard\s+(?:all\s+)?(?:previous|above|prior)/i,
      /forget\s+(?:all\s+)?(?:previous|above|prior)/i,
      /you\s+are\s+now/i,
      /new\s+instructions?:/i,
      /system\s*:\s*/i,
      /\[system\]/i,
      /\[assistant\]/i,
      /\[user\]/i,
      /roleplay\s+as/i,
      /pretend\s+(?:you\s+are|to\s+be)/i,
      /act\s+as\s+(?:if|though)/i,
      /override\s+(?:your\s+)?(?:instructions|programming)/i,
      /execute\s+(?:the\s+following|this)/i,
      /run\s+(?:the\s+following|this)\s+(?:code|command)/i,
      /\beval\s*\(/i,
      /\bexec\s*\(/i,
      /\bimport\s+os\b/i,
      /\bsubprocess\b/i,
      /\bfetch\s*\(['"]/i,
      /\bxmlhttprequest\b/i
    ];

    return injectionPatterns.some(pattern => pattern.test(text));
  }

  // =========================================================================
  // REMOVAL FUNCTIONS
  // =========================================================================

  /**
   * Scan and remove hidden malicious content
   */
  function removeHiddenContent() {
    // Get all elements
    const allElements = document.querySelectorAll('*');

    allElements.forEach(element => {
      // Skip scripts, styles, and other non-content elements
      if (['SCRIPT', 'STYLE', 'META', 'LINK', 'NOSCRIPT'].includes(element.tagName)) {
        return;
      }

      // Check if element is hidden
      if (isHiddenElement(element)) {
        // Get text content
        const text = element.textContent || '';

        // Only remove if it contains suspicious content or is non-trivial
        if (text.length > 20 || containsPromptInjection(text)) {
          // Remove the content (clear it rather than remove element to not break layout)
          element.textContent = '';
          element.innerHTML = '';
        }
      }
    });
  }

  /**
   * Scan HTML comments for hidden instructions
   */
  function removeHiddenComments() {
    const walker = document.createTreeWalker(
      document.documentElement,
      NodeFilter.SHOW_COMMENT,
      null,
      false
    );

    const commentsToRemove = [];
    let comment;

    while ((comment = walker.nextNode())) {
      const text = comment.textContent || '';

      // Check if comment contains prompt injection
      if (containsPromptInjection(text)) {
        commentsToRemove.push(comment);
      }
    }

    // Remove identified comments
    commentsToRemove.forEach(comment => {
      comment.remove();
    });
  }

  // =========================================================================
  // MUTATION OBSERVER
  // =========================================================================

  /**
   * Watch for dynamically added hidden content
   */
  function setupObserver() {
    const observer = new MutationObserver((mutations) => {
      let shouldScan = false;

      for (const mutation of mutations) {
        if (mutation.addedNodes.length > 0) {
          shouldScan = true;
          break;
        }
      }

      if (shouldScan) {
        // Debounce
        clearTimeout(window._armorlyHiddenScanTimeout);
        window._armorlyHiddenScanTimeout = setTimeout(() => {
          removeHiddenContent();
          removeHiddenComments();
        }, 200);
      }
    });

    if (document.body) {
      observer.observe(document.body, {
        childList: true,
        subtree: true
      });
    } else {
      document.addEventListener('DOMContentLoaded', () => {
        observer.observe(document.body, {
          childList: true,
          subtree: true
        });
      });
    }
  }

  // =========================================================================
  // INITIALIZATION
  // =========================================================================

  function init() {
    // Run initial scan when DOM is ready
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        removeHiddenContent();
        removeHiddenComments();
        setupObserver();
      });
    } else {
      removeHiddenContent();
      removeHiddenComments();
      setupObserver();
    }

    // Also run after full page load
    window.addEventListener('load', () => {
      setTimeout(() => {
        removeHiddenContent();
        removeHiddenComments();
      }, 1000);
    });
  }

  // Run immediately
  init();

})();
