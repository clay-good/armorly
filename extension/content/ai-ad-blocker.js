/**
 * Armorly - AI Ad Blocker
 *
 * Blocks AI-native advertising from all major ad networks:
 * - Koah, Monetzly, Sponsored.so, Grok/X, Imprezia, Google AdSense
 *
 * Methods:
 * 1. SDK interception (block init/monetize calls before they run)
 * 2. DOM-based ad removal (sponsored labels, product cards)
 * 3. Affiliate link cleaning (strip tracking parameters)
 *
 * Silent operation - no UI, no logging, just blocking.
 */

(function() {
  'use strict';

  // Wait for patterns library to load
  if (typeof window.ArmorlyAdPatterns === 'undefined') {
    return;
  }

  const patterns = window.ArmorlyAdPatterns;

  // =========================================================================
  // 1. AI AD SDK INTERCEPTION (All Networks)
  // =========================================================================

  /**
   * Create a no-op proxy that absorbs all SDK method calls
   */
  function createSDKProxy() {
    return new Proxy({}, {
      get: function(target, prop) {
        // Return no-op functions for all SDK methods
        return function() {
          return Promise.resolve();
        };
      },
      set: function() {
        return true;
      }
    });
  }

  /**
   * Block all AI ad SDKs by intercepting their initialization
   */
  function blockAllAdSDKs() {
    const sdkProxy = createSDKProxy();

    // Get all SDK function names from patterns
    const sdkFunctions = patterns.getAllSDKFunctions();

    sdkFunctions.forEach(funcName => {
      try {
        Object.defineProperty(window, funcName, {
          get: function() {
            return sdkProxy;
          },
          set: function() {
            return true;
          },
          configurable: false
        });
      } catch {
        // Property may already be defined, skip
      }
    });
  }

  /**
   * Block ad SDK scripts from loading
   */
  function blockAdScripts() {
    const scriptPatterns = patterns.getAllScriptPatterns();

    // Intercept appendChild
    const originalAppendChild = Node.prototype.appendChild;
    Node.prototype.appendChild = function(child) {
      if (child.tagName === 'SCRIPT' && child.src) {
        const src = child.src.toLowerCase();
        if (scriptPatterns.some(p => p.test(src))) {
          return child; // Block silently
        }
      }
      return originalAppendChild.call(this, child);
    };

    // Intercept insertBefore
    const originalInsertBefore = Node.prototype.insertBefore;
    Node.prototype.insertBefore = function(newNode, referenceNode) {
      if (newNode.tagName === 'SCRIPT' && newNode.src) {
        const src = newNode.src.toLowerCase();
        if (scriptPatterns.some(p => p.test(src))) {
          return newNode; // Block silently
        }
      }
      return originalInsertBefore.call(this, newNode, referenceNode);
    };

    // Intercept document.write (some SDKs use this)
    const originalWrite = document.write;
    document.write = function(content) {
      if (typeof content === 'string') {
        const lowerContent = content.toLowerCase();
        if (scriptPatterns.some(p => p.test(lowerContent))) {
          return; // Block silently
        }
      }
      return originalWrite.call(this, content);
    };
  }

  // =========================================================================
  // 2. DOM-BASED AD REMOVAL
  // =========================================================================

  /**
   * Remove ad elements from the DOM
   */
  function removeAdElements() {
    const selectors = patterns.getSelectorsForPlatform();

    selectors.forEach(selector => {
      try {
        const elements = document.querySelectorAll(selector);
        elements.forEach(el => {
          el.remove();
        });
      } catch {
        // Invalid selector, skip
      }
    });
  }

  /**
   * Find and remove elements containing ad labels
   */
  function removeAdLabeledElements() {
    const walker = document.createTreeWalker(
      document.body || document.documentElement,
      NodeFilter.SHOW_TEXT,
      null,
      false
    );

    const elementsToRemove = new Set();
    let node;

    while ((node = walker.nextNode())) {
      const text = node.textContent.trim();

      // Skip empty or very short text
      if (text.length < 2 || text.length > 50) continue;

      // Check for ad labels
      if (patterns.containsAdLabel(text)) {
        // Find the containing ad element (usually a few levels up)
        let container = node.parentElement;
        for (let i = 0; i < 5 && container; i++) {
          const classes = container.className || '';
          const role = container.getAttribute('role') || '';

          if (
            classes.match(/sponsored|ad-|promoted|product-card|recommendation|koah|monetzly/i) ||
            role === 'complementary' ||
            container.tagName === 'ASIDE' ||
            container.hasAttribute('data-ad-provider')
          ) {
            elementsToRemove.add(container);
            break;
          }

          // If this is just a small label, remove just the label
          if (container.offsetHeight < 50 && container.offsetWidth < 200) {
            elementsToRemove.add(container);
            break;
          }

          container = container.parentElement;
        }
      }
    }

    elementsToRemove.forEach(el => {
      el.remove();
    });
  }

  // =========================================================================
  // 3. AFFILIATE LINK CLEANING
  // =========================================================================

  /**
   * Clean affiliate tracking from all links
   */
  function cleanAffiliateLinks() {
    const links = document.querySelectorAll('a[href]');

    links.forEach(link => {
      const href = link.href;

      // Check if URL has affiliate parameters
      if (patterns.hasAffiliateParams(href)) {
        link.href = patterns.cleanUrl(href);
      }

      // Check if it's a known affiliate redirect domain
      if (patterns.isAffiliateDomain(href)) {
        link.setAttribute('data-armorly-affiliate', 'true');
      }
    });
  }

  // =========================================================================
  // 4. MUTATION OBSERVER (Watch for dynamic content)
  // =========================================================================

  /**
   * Set up observer to catch dynamically added ads
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
        clearTimeout(window._armorlyScanTimeout);
        window._armorlyScanTimeout = setTimeout(() => {
          removeAdElements();
          removeAdLabeledElements();
          cleanAffiliateLinks();
        }, 100);
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
    // Block all SDKs before they can load
    blockAllAdSDKs();
    blockAdScripts();

    // Initial scan when DOM is ready
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        removeAdElements();
        removeAdLabeledElements();
        cleanAffiliateLinks();
        setupObserver();
      });
    } else {
      removeAdElements();
      removeAdLabeledElements();
      cleanAffiliateLinks();
      setupObserver();
    }

    // Also run on full page load (catches late-loading ads)
    window.addEventListener('load', () => {
      setTimeout(() => {
        removeAdElements();
        removeAdLabeledElements();
        cleanAffiliateLinks();
      }, 500);
    });
  }

  // Run immediately
  init();

})();
