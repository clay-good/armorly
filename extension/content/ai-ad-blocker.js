/**
 * Armorly - AI Ad Blocker
 *
 * Blocks AI-native advertising from all major ad networks:
 * - Koah, Imprezia, Kontext, Gravity, Thrad, ZeroClick, Lulu, ChatAds,
 *   EarnLayer, Monetzly (network only), Grok/X, Google AdSense
 * - Server-side / OpenRTB ads stitched into a chatbot's own responses
 *   (see 2b below and content/payload-shield.js)
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
  // STATS TRACKING (for popup display)
  // =========================================================================

  const stats = {
    sdksBlocked: 0,
    linksCleaned: 0,
    elementsRemoved: 0,
    active: true
  };

  // Deltas since last persistence flush. Reset on every successful flush so
  // we never double-count across tabs that share the same lifetime totals.
  const lifetimeDelta = {
    sdksBlocked: 0,
    linksCleaned: 0,
    elementsRemoved: 0
  };

  function bumpStat(key) {
    stats[key]++;
    if (key in lifetimeDelta) lifetimeDelta[key]++;
  }

  // Listen for stats requests from popup
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.type === 'GET_STATS') {
        sendResponse(stats);
      }
      return true;
    });
  }

  // Periodically flush deltas to chrome.storage.local so the popup can show
  // cumulative numbers since install. We read-modify-write the whole record
  // because chrome.storage.local has no atomic increment. Single-tab contention
  // is fine; cross-tab contention can lose at most one flush window of counts.
  function flushLifetimeStats() {
    if (!chrome.storage || !chrome.storage.local) return;
    if (
      lifetimeDelta.sdksBlocked === 0 &&
      lifetimeDelta.linksCleaned === 0 &&
      lifetimeDelta.elementsRemoved === 0
    ) {
      return;
    }
    const delta = { ...lifetimeDelta };
    lifetimeDelta.sdksBlocked = 0;
    lifetimeDelta.linksCleaned = 0;
    lifetimeDelta.elementsRemoved = 0;
    chrome.storage.local.get({ lifetime: { sdksBlocked: 0, linksCleaned: 0, elementsRemoved: 0 } }, (data) => {
      const next = {
        sdksBlocked: (data.lifetime.sdksBlocked || 0) + delta.sdksBlocked,
        linksCleaned: (data.lifetime.linksCleaned || 0) + delta.linksCleaned,
        elementsRemoved: (data.lifetime.elementsRemoved || 0) + delta.elementsRemoved
      };
      chrome.storage.local.set({ lifetime: next });
    });
  }

  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    setInterval(flushLifetimeStats, 5000);
    // Also flush on page hide so short visits still contribute.
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'hidden') flushLifetimeStats();
    });
  }

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
  const signatures = window.ArmorlyAdSignatures || null;

  // Control channel to the MAIN-world payload shield. Both scripts run at
  // document_start before any page script; whichever runs first writes a
  // random key on <html>, the other reads and removes it. Messages we send
  // to the MAIN world carry the key, so a page can't forge them.
  const BRIDGE_ATTR = 'data-armorly-bridge';
  let bridgeKey = null;
  try {
    const rootEl = document.documentElement;
    if (rootEl) {
      if (rootEl.hasAttribute(BRIDGE_ATTR)) {
        bridgeKey = rootEl.getAttribute(BRIDGE_ATTR);
        rootEl.removeAttribute(BRIDGE_ATTR);
      } else {
        const buf = new Uint32Array(4);
        crypto.getRandomValues(buf);
        bridgeKey = Array.from(buf, n => n.toString(36)).join('');
        rootEl.setAttribute(BRIDGE_ATTR, bridgeKey);
      }
    }
  } catch (_) { /* noop */ }

  function sendToMainWorld(message) {
    try {
      window.postMessage(Object.assign({ source: 'armorly', key: bridgeKey }, message), '*');
    } catch (_) { /* noop */ }
  }

  // =========================================================================
  // 1. AI AD SDK INTERCEPTION (Page-world, via sdk-blocker.js)
  //
  // The actual proxy installation runs in the MAIN content-script world
  // (extension/content/sdk-blocker.js). That script can't access chrome.*
  // APIs, so when it absorbs an SDK call it postMessages back here and
  // we bump the stats counter on its behalf.
  //
  // Why split worlds: content scripts in the default ISOLATED world get a
  // different `window` from the page, so any property defined on `window`
  // here is invisible to page scripts — making the previous in-line
  // interceptor a no-op in production. Phase 2 tests caught this.
  // =========================================================================

  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (data && data.source === 'armorly' && (data.type === 'sdk-blocked' || data.type === 'shield-blocked')) {
      // shield-blocked: an ad payload, ad tracker or browser ad-API call
      // stopped by content/payload-shield.js. Counted with SDK blocks as
      // "ads blocked" in the popup.
      bumpStat('sdksBlocked');
    }
  });

  // =========================================================================
  // 2. DOM-BASED AD REMOVAL
  // =========================================================================

  /**
   * Hide an ad element. We hide rather than remove: chat apps are mostly
   * React, and deleting a node React still owns makes its next re-render
   * throw (`removeChild ... not a child of this node`) and blank the whole
   * app. An inline `display: none !important` keeps React's tree intact.
   * Returns false if the element was already hidden by us.
   */
  function hideAd(el) {
    if (el.hasAttribute('data-armorly-hidden')) return false;
    el.style.setProperty('display', 'none', 'important');
    el.setAttribute('data-armorly-hidden', '');
    return true;
  }

  /**
   * Remove ad elements from the page
   */
  function removeAdElements() {
    // Sponsored links woven into the AI's own answer (e.g. Imprezia's
    // `${link-X}` placeholders): drop the link but keep the word so the
    // sentence still reads. This content is set via innerHTML, so React
    // doesn't own these nodes and replacing them is safe.
    (patterns.inlineAdLinks || []).forEach(selector => {
      try {
        document.querySelectorAll(selector).forEach(link => {
          link.replaceWith(document.createTextNode(link.textContent));
          bumpStat('elementsRemoved');
        });
      } catch {
        // Invalid selector, skip
      }
    });

    const selectors = patterns.getSelectorsForPlatform();
    const roots = collectRoots();

    selectors.forEach(selector => {
      try {
        const elements = roots.flatMap(r => Array.from(r.querySelectorAll(selector)));
        elements.forEach(el => {
          if (hideAd(el)) bumpStat('elementsRemoved');
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

      // Skip ads we've already hidden
      if (node.parentElement && node.parentElement.closest('[data-armorly-hidden]')) continue;

      // Check for ad labels
      if (patterns.containsAdLabel(text)) {
        // Find the containing ad element (usually a few levels up)
        let container = node.parentElement;
        for (let i = 0; i < 5 && container; i++) {
          const classes = container.className || '';

          // ONLY remove if element has CLEAR ad-specific indicators
          // Be very conservative to avoid false positives
          if (
            classes.match(/\bsponsored\b|\bkoah\b|\bpplx-sponsored\b|\bimprezia-card\b|\bimprezia-cta-container\b/i) ||
            container.hasAttribute('data-ad-provider') ||
            container.hasAttribute('data-koah-ad') ||
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
      if (!hideAd(el)) return;
      bumpStat('elementsRemoved');
    });
  }


  // =========================================================================
  // 2b. DISCLOSED AD CARDS (server-side / OpenRTB ads rendered into a chat)
  //
  // A server-stitched ad arrives on the chatbot's own domain with no SDK,
  // no ad-network script and no ad-specific class names. What it must
  // carry is a disclosure label ("Sponsored", "Ad", "Promoted"...) — US FTC
  // and EU DSA rules require one. We find elements whose ENTIRE text is
  // such a label (lib/ad-signatures.js; zero-width characters and
  // lookalike letters normalized away), then climb to the smallest
  // enclosing card that also holds a link or button, and hide it.
  //
  // Guard rails, all deterministic:
  //   - the label can't itself be a link/button (footer "Ads" links),
  //   - the card stops growing when its parent would add other content,
  //     hold a second label, or exceed MAX_CARD_TEXT characters,
  //   - never hide <body>, main/log/feed regions, forms, or anything
  //     that contains a text input (the chat composer).
  // Hidden, not removed: frameworks like React crash when nodes they own
  // disappear. display:none + aria-hidden + inert also takes the ad out of
  // the accessibility tree that browser agents read.
  // =========================================================================

  const MAX_CARD_TEXT = 1200;
  const LABEL_MAX = 80;
  const ACTION_SELECTOR = 'a[href], button, [role="button"], [role="link"]';
  const CONTROL_SELECTOR = 'a, button, select, option, label, summary, [role="button"], [role="link"], [role="tab"], [role="option"], [role="menuitem"]';
  const BOUNDARY_SELECTOR = 'html, body, main, form, dialog, [role="main"], [role="log"], [role="feed"], [role="dialog"], [role="application"]';
  const EDITABLE_SELECTOR = 'textarea, input:not([type="hidden"]):not([type="checkbox"]):not([type="radio"]):not([type="button"]):not([type="submit"]):not([type="reset"]), [contenteditable=""], [contenteditable="true"], [contenteditable="plaintext-only"]';

  function textLen(el) {
    return (el.textContent || '').replace(/\s+/g, '').length;
  }

  // Open and closed shadow roots, so ad web-components can't hide from us.
  const observedRoots = new WeakSet();
  function shadowRootOf(el) {
    if (el.shadowRoot) return el.shadowRoot;
    try {
      if (chrome.dom && chrome.dom.openOrClosedShadowRoot) return chrome.dom.openOrClosedShadowRoot(el) || null;
    } catch (_) { /* noop */ }
    return null;
  }
  let rootsCache = null; // valid for the duration of one scanAll()

  function collectRoots() {
    if (rootsCache) return rootsCache;
    const roots = [document];
    for (let i = 0; i < roots.length; i++) {
      const all = roots[i].querySelectorAll('*');
      for (const el of all) {
        // Closed roots are flagged by payload-shield.js (MAIN world) with
        // data-armorly-shadow; open ones expose .shadowRoot.
        if (!el.shadowRoot && !el.localName.includes('-') && !el.hasAttribute('data-armorly-shadow')) continue;
        const sr = shadowRootOf(el);
        if (sr && !roots.includes(sr)) roots.push(sr);
      }
    }
    return roots;
  }

  function parentAcrossShadow(el) {
    if (el.parentElement) return el.parentElement;
    const root = el.getRootNode && el.getRootNode();
    return root && root.host ? root.host : null;
  }

  function isBoundary(el) {
    if (el.matches(BOUNDARY_SELECTOR)) return true;
    if (el.isContentEditable) return true;
    return !!el.querySelector(EDITABLE_SELECTOR);
  }

  /** Label is the whole text of a link/button (e.g. a footer "Ads" link). */
  function isControlText(labelEl) {
    const control = labelEl.closest(CONTROL_SELECTOR);
    return !!control && textLen(control) <= textLen(labelEl);
  }

  function findDisclosureLabels(root, prefixed) {
    const found = new Set();
    const start = root.body || root;
    const walker = document.createTreeWalker(start, NodeFilter.SHOW_TEXT);
    let node;
    while ((node = walker.nextNode())) {
      const raw = node.nodeValue;
      if (!raw || !raw.trim()) continue;
      const parentTag = node.parentElement && node.parentElement.localName;
      if (parentTag === 'script' || parentTag === 'style' || parentTag === 'noscript' || parentTag === 'template') continue;
      if (raw.length > LABEL_MAX) {
        // "Sponsored: Try Acme…" glued to the start of a paragraph.
        if (signatures.isDisclosurePrefix(raw)) prefixed.add(node.parentElement);
        continue;
      }
      if (signatures.isDisclosurePrefix(raw) && !signatures.isDisclosureLabel(raw)) {
        prefixed.add(node.parentElement);
        continue;
      }
      // The label may be split across inline elements ("Spon<b>sored</b>"),
      // so test the text node's parent and a couple of ancestors.
      let el = node.parentElement;
      for (let i = 0; i < 3 && el; i++) {
        const t = el.textContent;
        if (t.length > LABEL_MAX) break;
        if (signatures.isDisclosureLabel(t)) { found.add(el); break; }
        el = el.parentElement;
      }
    }
    for (const el of root.querySelectorAll('[aria-label], [title]')) {
      const t = el.getAttribute('aria-label') || el.getAttribute('title');
      if (signatures.isDisclosureLabel(t) && textLen(el) === 0) found.add(el);
    }
    // Keep the outermost element of nested matches (<span><b>Ad</b></span>).
    return Array.from(found).filter(el => !Array.from(found).some(o => o !== el && o.contains(el)));
  }

  function cardFor(labelEl, allLabels) {
    if (isControlText(labelEl)) return null;
    let node = labelEl;
    let card = null;
    for (let i = 0; i < 15; i++) {
      const parent = parentAcrossShadow(node);
      if (!parent || isBoundary(parent)) break;
      const pLen = textLen(parent);
      if (pLen > MAX_CARD_TEXT) break;
      // Once we have a card, only climb through pure wrappers.
      if (card && pLen > textLen(card)) break;
      if (allLabels.some(l => l !== labelEl && parent.contains(l))) break;
      node = parent;
      if (card) card = node;
      else if (node.matches(ACTION_SELECTOR) || node.querySelector(ACTION_SELECTOR)) {
        // A card must hold more than the label itself. Checked here, not
        // at the end: a shadow host's textContent excludes its shadow
        // content, so wrappers further up can read as empty.
        if (textLen(node) - textLen(labelEl) < 3) return null;
        card = node;
      }
    }
    return card;
  }

  function hideAdElement(el, reason) {
    if (el.hasAttribute('data-armorly-ad') || el.hasAttribute('data-armorly-hidden')) return false;
    el.setAttribute('data-armorly-ad', reason);
    el.setAttribute('aria-hidden', 'true');
    el.inert = true;
    el.style.setProperty('display', 'none', 'important');
    return true;
  }

  const BLOCK_SELECTOR = 'p, li, blockquote, div, section, aside, article, dd, figure';

  /** The block a "Sponsored: …" prefix opens, if the prefix starts it. */
  function prefixedBlock(el) {
    const block = el && el.closest(BLOCK_SELECTOR);
    if (!block || isBoundary(block) || textLen(block) > MAX_CARD_TEXT) return null;
    if (!signatures.isDisclosurePrefix(block.textContent.trim())) return null;
    if (!(block.matches(ACTION_SELECTOR) || block.querySelector(ACTION_SELECTOR))) return null;
    return block;
  }

  function hideDisclosedAdCards() {
    if (!signatures) return;
    for (const root of collectRoots()) {
      const prefixed = new Set();
      const labels = findDisclosureLabels(root, prefixed);
      for (const label of labels) {
        if (label.closest('[data-armorly-ad], [data-armorly-hidden]')) continue;
        const card = cardFor(label, labels);
        if (card && hideAdElement(card, 'disclosure')) bumpStat('elementsRemoved');
      }
      for (const el of prefixed) {
        if (!el || el.closest('[data-armorly-ad], [data-armorly-hidden]')) continue;
        const block = prefixedBlock(el);
        if (block && hideAdElement(block, 'disclosure-prefix')) bumpStat('elementsRemoved');
      }
    }
  }

  // =========================================================================
  // 2c. AD CLICK + VIEW REPORTING ON LINKS
  //
  // ping="" (hyperlink auditing) and attributionsrc (Attribution Reporting)
  // only exist to tell an advertiser about a click/view. Ad click-redirects
  // (tracker host or /aclk-style path + destination param) are rewritten
  // straight to the destination so no paid click is recorded.
  // =========================================================================

  function isAdHost(hostname) {
    const h = hostname.toLowerCase();
    const hosts = patterns.getAllSDKDomains().concat(patterns.verificationDomains || []);
    return hosts.some(d => h === d || h.endsWith('.' + d));
  }

  function neutralizeAdLinks() {
    for (const root of collectRoots()) {
      for (const el of root.querySelectorAll('[ping], [attributionsrc]')) {
        el.removeAttribute('ping');
        el.removeAttribute('attributionsrc');
      }
      if (!signatures) continue;
      for (const link of root.querySelectorAll('a[href]')) {
        if (link.hasAttribute('data-armorly-unwrapped')) continue;
        const dest = signatures.unwrapClickRedirect(link.href, isAdHost);
        if (dest) {
          link.href = dest;
          link.setAttribute('data-armorly-unwrapped', 'true');
          bumpStat('linksCleaned');
        }
      }
    }
  }

  function scanAll() {
    rootsCache = null;
    rootsCache = collectRoots();
    try {
      removeAdElements();
      removeAdLabeledElements();
      hideDisclosedAdCards();
      neutralizeAdLinks();
      cleanAffiliateLinks();
      observeShadowRoots();
    } finally {
      rootsCache = null;
    }
  }

  // =========================================================================
  // 3. AFFILIATE LINK CLEANING
  // =========================================================================

  /**
   * Clean affiliate tracking from all links
   */
  function cleanAffiliateLinks() {
    const links = collectRoots().flatMap(r => Array.from(r.querySelectorAll('a[href]')));

    links.forEach(link => {
      const href = link.href;

      // Skip already processed links
      if (link.hasAttribute('data-armorly-cleaned')) {
        return;
      }

      // Check if URL has affiliate parameters
      if (patterns.hasAffiliateParams(href)) {
        link.href = patterns.cleanUrl(href);
        link.setAttribute('data-armorly-cleaned', 'true');
        bumpStat('linksCleaned');
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
  let observer = null;

  function setupObserver() {
    observer = new MutationObserver((mutations) => {
      let shouldScan = false;

      for (const mutation of mutations) {
        // characterData: chat answers stream in as text edits to an
        // existing node, so a label can appear without a node being added.
        if (mutation.addedNodes.length > 0 || mutation.type === 'characterData') {
          shouldScan = true;
          break;
        }
      }

      if (shouldScan) {
        clearTimeout(window._armorlyScanTimeout);
        window._armorlyScanTimeout = setTimeout(scanAll, 100);
      }
    });

    if (document.body) {
      observer.observe(document.body, OBSERVE_OPTIONS);
    } else {
      document.addEventListener('DOMContentLoaded', () => {
        observer.observe(document.body, OBSERVE_OPTIONS);
      });
    }
  }

  const OBSERVE_OPTIONS = { childList: true, subtree: true, characterData: true };

  function observeShadowRoots() {
    if (!observer) return;
    for (const root of collectRoots()) {
      if (root === document || observedRoots.has(root)) continue;
      observedRoots.add(root);
      observer.observe(root, OBSERVE_OPTIONS);
    }
  }

  // =========================================================================
  // INITIALIZATION
  // =========================================================================

  function init() {
    // Log activation for debugging/screenshots
    console.log('[Armorly] AI ad blocker active');
    console.log('[Armorly] Blocking SDKs:', patterns.getAllSDKFunctions().slice(0, 10).join(', '), '...');

    // SDK globals are blocked by content/sdk-blocker.js in the MAIN world.
    // We only handle DOM/affiliate work here.

    // Initial scan when DOM is ready
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        setupObserver();
        scanAll();
      });
    } else {
      setupObserver();
      scanAll();
    }

    // Also run on full page load (catches late-loading ads)
    window.addEventListener('load', () => {
      setTimeout(scanAll, 500);
    });
  }

  // Per-site whitelist (v2.2.0): if the user has flipped Armorly off for this
  // hostname in the popup, bail before doing any work — the SDK interceptor
  // must NOT run on disabled sites, otherwise users can't recover from false
  // positives. chrome.storage.local is async, but ad SDKs typically don't
  // initialize for tens-to-hundreds of ms after document_start, so even with
  // the small async gap we still block the vast majority of cases.
  function isDisabledForHost(disabledDomains) {
    if (!Array.isArray(disabledDomains)) return false;
    return disabledDomains.some(d => hostname === d || hostname.endsWith('.' + d));
  }

  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get({ disabled_domains: [], cached_patterns: null }, (data) => {
      if (isDisabledForHost(data.disabled_domains)) {
        stats.active = false;
        console.log('[Armorly] Disabled for this site by user setting:', hostname);
        // Tell the MAIN-world SDK interceptor to tear down its proxies too.
        // Without this, flipping "Protect this site" off only stops DOM
        // removal — `window.Koah` etc. would still resolve to the no-op
        // proxy and a legit page using one of those names as a non-ad
        // global would stay broken.
        sendToMainWorld({ type: 'disable-site' });
        return;
      }
      // Phase 4.4: apply any newer pattern snapshot fetched by the background
      // service worker. Bundled patterns are the floor; this can only ADD.
      if (data.cached_patterns && typeof patterns.mergeCachedPatterns === 'function') {
        const applied = patterns.mergeCachedPatterns(data.cached_patterns);
        if (applied) {
          console.log('[Armorly] Using cached patterns', patterns.version);
          // Push the updated SDK function list to the MAIN-world sdk-blocker
          // so newly-named SDKs from the daily refresh also get proxied.
          // Without this hop, auto-update only covers DOM selectors and
          // affiliate params — the actual interceptor stayed bundled-only.
          sendToMainWorld({
            type: 'update-sdk-list',
            functions: patterns.getAllSDKFunctions(),
            domains: patterns.getAllSDKDomains()
          });
        }
      }
      init();
    });
  } else {
    init();
  }

})();
