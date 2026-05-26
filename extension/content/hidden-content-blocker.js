/**
 * Armorly - Hidden Content Blocker
 *
 * Blocks prompt injection attacks hidden in invisible elements.
 * ONLY removes content that BOTH:
 *   1. Is hidden using suspicious techniques
 *   2. Contains known prompt injection patterns
 *
 * This is intentionally conservative to avoid breaking sites.
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
    return; // Skip silently for hidden content blocker
  }

  // =========================================================================
  // PROMPT INJECTION PATTERNS (Required for removal)
  // =========================================================================

  /**
   * Check if text contains known prompt injection patterns
   * This is the CRITICAL check - we only remove hidden content if it matches these
   */
  function containsPromptInjection(text) {
    if (!text || text.length < 15) {
      return false;
    }

    // Only match clear, unambiguous prompt injection attempts
    const injectionPatterns = [
      /ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions/i,
      /disregard\s+(?:all\s+)?(?:previous|above|prior)\s+instructions/i,
      /forget\s+(?:all\s+)?(?:previous|above|prior)\s+instructions/i,
      /you\s+are\s+now\s+(?:a|an|in)\s+/i,
      /new\s+instructions?:\s*\S/i,
      /\[SYSTEM\]:\s*\S/i,
      /\[INST\]:\s*\S/i,
      /roleplay\s+as\s+(?:a|an)\s+/i,
      /pretend\s+(?:you\s+are|to\s+be)\s+(?:a|an)\s+/i,
      /override\s+(?:your\s+)?(?:instructions|programming|rules)/i,
      /jailbreak/i,
      /DAN\s+mode/i,
      /developer\s+mode\s+enabled/i
    ];

    return injectionPatterns.some(pattern => pattern.test(text));
  }

  // =========================================================================
  // HIDDEN ELEMENT DETECTION
  // =========================================================================

  /**
   * Check if element uses deceptive hiding (not legitimate accessibility hiding)
   */
  function isDeceptivelyHidden(element) {
    if (!element || element.nodeType !== Node.ELEMENT_NODE) {
      return false;
    }

    // Skip common legitimate hidden element patterns
    const tagName = element.tagName;
    if (['SCRIPT', 'STYLE', 'META', 'LINK', 'NOSCRIPT', 'TEMPLATE'].includes(tagName)) {
      return false;
    }

    // Skip elements with accessibility roles (screen reader content is legitimate)
    const role = element.getAttribute('role');
    if (role === 'status' || role === 'alert' || role === 'log') {
      return false;
    }

    // Skip elements with aria-live (accessibility announcements)
    if (element.hasAttribute('aria-live')) {
      return false;
    }

    // Skip visually-hidden classes (legitimate accessibility pattern)
    const className = element.className || '';
    if (typeof className === 'string') {
      if (/sr-only|visually-hidden|screen-reader|a11y/i.test(className)) {
        return false;
      }
    }

    const style = window.getComputedStyle(element);

    // Check for deceptive hiding techniques
    return (
      isWhiteOnWhite(style) ||
      isZeroSizeWithContent(element, style)
    );
  }

  /**
   * White/same-color text on same-color background (classic prompt injection technique)
   */
  function isWhiteOnWhite(style) {
    const color = style.color;
    const bgColor = style.backgroundColor;

    const textColor = parseColor(color);
    const backgroundColor = parseColor(bgColor);

    if (!textColor || !backgroundColor) {
      return false;
    }

    // Colors must be nearly identical AND both light (white-on-white style attack)
    const threshold = 15;
    const colorsMatch = (
      Math.abs(textColor.r - backgroundColor.r) < threshold &&
      Math.abs(textColor.g - backgroundColor.g) < threshold &&
      Math.abs(textColor.b - backgroundColor.b) < threshold
    );

    // Only flag if colors match AND it's light colored (white-ish)
    const isLight = (textColor.r + textColor.g + textColor.b) > 600;

    return colorsMatch && isLight;
  }

  /**
   * Zero-size element that still contains substantial text
   */
  function isZeroSizeWithContent(element, style) {
    const fontSize = parseFloat(style.fontSize);

    // font-size: 0 is a known prompt injection technique
    if (fontSize === 0) {
      return true;
    }

    return false;
  }

  /**
   * Parse CSS color to RGB values
   */
  function parseColor(colorStr) {
    if (!colorStr || colorStr === 'transparent' || colorStr === 'rgba(0, 0, 0, 0)') {
      return null;
    }

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

  // =========================================================================
  // REMOVAL FUNCTIONS
  // =========================================================================

  // Total injection blocks observed during this page's lifetime. The toast
  // (v2.5.0) reads this to decide whether to surface anything to the user.
  let injectionBlockCount = 0;

  function notifyInjectionBlocked() {
    injectionBlockCount++;
    maybeShowInjectionToast();
  }

  /**
   * Scan and remove ONLY hidden content containing prompt injection
   */
  function removeHiddenPromptInjections() {
    const allElements = document.querySelectorAll('*');

    allElements.forEach(element => {
      // Must be deceptively hidden
      if (!isDeceptivelyHidden(element)) {
        return;
      }

      const text = element.textContent || '';

      // MUST contain prompt injection pattern to be removed
      if (containsPromptInjection(text)) {
        element.textContent = '';
        notifyInjectionBlocked();
      }
    });
  }

  /**
   * Scan HTML comments for prompt injection
   */
  function removeInjectionComments() {
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

      // Only remove if it contains prompt injection
      if (containsPromptInjection(text)) {
        commentsToRemove.push(comment);
      }
    }

    commentsToRemove.forEach(comment => {
      comment.remove();
      notifyInjectionBlocked();
    });
  }

  // =========================================================================
  // TOAST UI (v2.4.0): make the silent block visible once per page
  // =========================================================================

  let toastShownOnPage = false;
  let toastDismissedForHost = null; // null = unknown; true/false once resolved

  // Resolve dismissal state up front so the toast handler doesn't have to
  // await storage on every block notification.
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get({ dismissed_injection_toast: [] }, (data) => {
      const list = Array.isArray(data.dismissed_injection_toast) ? data.dismissed_injection_toast : [];
      toastDismissedForHost = list.includes(hostname);
      // If we already blocked something before storage resolved, retry.
      if (injectionBlockCount > 0) maybeShowInjectionToast();
    });
  } else {
    toastDismissedForHost = false;
  }

  function maybeShowInjectionToast() {
    if (toastShownOnPage) return;
    if (toastDismissedForHost === null) return; // wait for storage resolve
    if (toastDismissedForHost) return;
    // Don't try to attach a toast before there is a body to attach to.
    if (!document.body) {
      document.addEventListener('DOMContentLoaded', maybeShowInjectionToast, { once: true });
      return;
    }
    toastShownOnPage = true;
    renderInjectionToast();
  }

  function rememberDismissForHost() {
    if (!chrome.storage || !chrome.storage.local) return;
    chrome.storage.local.get({ dismissed_injection_toast: [] }, (data) => {
      const list = Array.isArray(data.dismissed_injection_toast) ? data.dismissed_injection_toast : [];
      if (!list.includes(hostname)) {
        list.push(hostname);
        chrome.storage.local.set({ dismissed_injection_toast: list });
      }
    });
  }

  function renderInjectionToast() {
    // Use a shadow root so the page's CSS can't restyle (or hide) us, and
    // pin to fixed position so it works on overflow-hidden layouts.
    const host = document.createElement('div');
    host.style.cssText = 'all: initial; position: fixed; right: 16px; bottom: 16px; z-index: 2147483647;';
    const shadow = host.attachShadow({ mode: 'closed' });

    const style = document.createElement('style');
    style.textContent = `
      .toast {
        font: 13px/1.4 -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        color: #fff;
        background: #0f0f0f;
        border: 1px solid #2a2a2a;
        border-radius: 8px;
        padding: 10px 12px;
        max-width: 320px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.35);
        display: flex;
        align-items: flex-start;
        gap: 10px;
      }
      .icon { font-size: 16px; line-height: 1; flex-shrink: 0; padding-top: 1px; }
      .body { flex: 1; }
      .title { font-weight: 600; margin-bottom: 2px; }
      .sub { color: #9ca3af; font-size: 11px; }
      .close {
        background: none;
        border: 0;
        color: #888;
        font-size: 16px;
        line-height: 1;
        cursor: pointer;
        padding: 0 4px;
      }
      .close:hover { color: #fff; }
    `;
    shadow.appendChild(style);

    const wrap = document.createElement('div');
    wrap.className = 'toast';
    wrap.innerHTML = `
      <div class="icon">🛡️</div>
      <div class="body">
        <div class="title">Armorly blocked a hidden prompt injection</div>
        <div class="sub">on this page. Click the toolbar icon for details.</div>
      </div>
      <button class="close" aria-label="Dismiss">&times;</button>
    `;
    shadow.appendChild(wrap);

    const dismiss = (remember) => {
      if (remember) rememberDismissForHost();
      host.remove();
    };
    shadow.querySelector('.close').addEventListener('click', () => dismiss(true));
    // Auto-dismiss after 8 seconds, without recording a per-site preference.
    setTimeout(() => dismiss(false), 8000);

    document.body.appendChild(host);
  }

  // =========================================================================
  // MUTATION OBSERVER
  // =========================================================================

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
        clearTimeout(window._armorlyHiddenScanTimeout);
        window._armorlyHiddenScanTimeout = setTimeout(() => {
          removeHiddenPromptInjections();
          removeInjectionComments();
        }, 500);
      }
    });

    if (document.body) {
      observer.observe(document.body, {
        childList: true,
        subtree: true
      });
    } else {
      document.addEventListener('DOMContentLoaded', () => {
        if (document.body) {
          observer.observe(document.body, {
            childList: true,
            subtree: true
          });
        }
      });
    }
  }

  // =========================================================================
  // INITIALIZATION
  // =========================================================================

  function init() {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        removeHiddenPromptInjections();
        removeInjectionComments();
        setupObserver();
      });
    } else {
      removeHiddenPromptInjections();
      removeInjectionComments();
      setupObserver();
    }
  }

  // Honour the per-site whitelist set in the popup (v2.2.0). Mirror the gate
  // in ai-ad-blocker.js so disabling Armorly on a site disables both
  // protections atomically.
  function isDisabledForHost(disabledDomains) {
    if (!Array.isArray(disabledDomains)) return false;
    return disabledDomains.some(d => hostname === d || hostname.endsWith('.' + d));
  }

  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get({ disabled_domains: [] }, (data) => {
      if (isDisabledForHost(data.disabled_domains)) return;
      init();
    });
  } else {
    init();
  }

})();
