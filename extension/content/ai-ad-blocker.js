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
 *
 * NOTE: We do NOT intercept appendChild/insertBefore/document.write
 * because this breaks many legitimate sites. Instead we rely on:
 * - SDK global name interception (prevents SDK from initializing)
 * - DOM removal (removes ad elements after they appear)
 */

(function() {
  'use strict';

  // =========================================================================
  // DOMAIN ALLOWLIST - Skip sites that are NOT AI chatbots
  // =========================================================================

  const SKIP_DOMAINS = [
    'mail.google.com',
    'calendar.google.com',
    'docs.google.com',
    'sheets.google.com',
    'slides.google.com',
    'drive.google.com',
    'meet.google.com',
    'chat.google.com',
    'contacts.google.com',
    'keep.google.com',
    'tasks.google.com',
    'photos.google.com',
    'youtube.com',
    'www.youtube.com',
    'music.youtube.com',
    'github.com',
    'gitlab.com',
    'bitbucket.org',
    'stackoverflow.com',
    'reddit.com',
    'twitter.com',
    'facebook.com',
    'instagram.com',
    'linkedin.com',
    'amazon.com',
    'ebay.com',
    'netflix.com',
    'spotify.com'
  ];

  // Check if we should skip this domain
  const hostname = window.location.hostname.toLowerCase();
  if (SKIP_DOMAINS.some(domain => hostname === domain || hostname.endsWith('.' + domain))) {
    console.log('[Armorly] Skipping non-AI site:', hostname);
    return;
  }

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
   * This prevents SDK global objects from being usable even if script loads
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
   * CONSERVATIVE: Only removes elements with CLEAR ad-specific attributes
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

          // ONLY remove if element has CLEAR ad-specific indicators
          // Be very conservative to avoid false positives
          if (
            classes.match(/\bsponsored\b|\bkoah\b|\bmonetzly\b|\bpplx-sponsored\b/i) ||
            container.hasAttribute('data-ad-provider') ||
            container.hasAttribute('data-koah-ad') ||
            container.hasAttribute('data-monetzly-ad') ||
            container.hasAttribute('data-sponsored')
          ) {
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
    // Log activation for debugging/screenshots
    console.log('[Armorly] AI ad blocker active');
    console.log('[Armorly] Blocking SDKs:', patterns.getAllSDKFunctions().slice(0, 10).join(', '), '...');

    // Block SDK globals (makes SDK objects unusable even if script loads)
    blockAllAdSDKs();

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
