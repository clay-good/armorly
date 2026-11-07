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
  // Ad-manager consoles list ads as data; the DOM layer stays off there too.
  if (typeof patterns.isSkippedHost === 'function' && patterns.isSkippedHost(hostname)) return;
  const signatures = window.ArmorlyAdSignatures || null;

  // Control channel to the MAIN-world payload shield. Both scripts run at
  // document_start before any page script; whichever runs first writes
  // three random keys on <html>, the other reads and removes them. One key
  // per message type (see payload-shield.js): [0] pattern updates,
  // [1] disable-site, [2] learned trackers. Seeing one message never lets
  // a page forge another.
  const BRIDGE_ATTR = 'data-armorly-bridge';
  let bridgeKeys = null;
  try {
    const rootEl = document.documentElement;
    if (rootEl) {
      if (rootEl.hasAttribute(BRIDGE_ATTR)) {
        bridgeKeys = rootEl.getAttribute(BRIDGE_ATTR).split('.');
        rootEl.removeAttribute(BRIDGE_ATTR);
      } else {
        bridgeKeys = [0, 1, 2].map(() => {
          const buf = new Uint32Array(4);
          crypto.getRandomValues(buf);
          return Array.from(buf, n => n.toString(36)).join('');
        });
        rootEl.setAttribute(BRIDGE_ATTR, bridgeKeys.join('.'));
      }
    }
  } catch (_) { /* noop */ }

  const BRIDGE_KEY_INDEX = { 'update-sdk-list': 0, 'disable-site': 1 };

  function sendToMainWorld(message) {
    const key = bridgeKeys && bridgeKeys[BRIDGE_KEY_INDEX[message.type]];
    if (!key) return;
    try {
      window.postMessage(Object.assign({ source: 'armorly', key }, message), '*');
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
    } else if (data && data.source === 'armorly' && data.type === 'shield-learned' &&
               bridgeKeys && data.key === bridgeKeys[2] && Array.isArray(data.urls)) {
      // Tracker URLs the shield learned from ads it removed. The background
      // worker turns them into block rules scoped to this tab, which also
      // catches pixels created by HTML parsing (no JS hook sees those).
      const urls = data.urls
        .filter(u => u && typeof u.url === 'string' && u.url.length <= 2048 && /^https?:\/\//.test(u.url))
        .slice(0, 50)
        .map(u => ({ url: u.url, firstParty: !!u.firstParty }));
      if (urls.length) {
        sendToBackground({ type: 'ARMORLY_LEARNED_TRACKERS', urls });
      }
    }
  });

  function sendToBackground(message) {
    try {
      const p = chrome.runtime.sendMessage(message);
      if (p && typeof p.catch === 'function') p.catch(() => {});
    } catch (_) { /* noop */ }
  }

  // A new top-level page starts with no learned trackers.
  if (window === window.top) sendToBackground({ type: 'ARMORLY_PAGE_START' });

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
  function removeAdElements(scopes) {
    // Sponsored links woven into the AI's own answer (e.g. Imprezia's
    // `${link-X}` placeholders): the link is neutralized in place so the
    // sentence still reads and React's nodes stay where it put them.
    (patterns.inlineAdLinks || []).forEach(selector => {
      try {
        for (const r of scopes) for (const link of r.querySelectorAll(selector)) {
          if (neutralizeLink(link)) bumpStat('elementsRemoved');
        }
      } catch {
        // Invalid selector, skip
      }
    });

    const selectors = patterns.getSelectorsForPlatform();

    selectors.forEach(selector => {
      try {
        for (const r of scopes) {
          if (r.nodeType === 1 && r.matches(selector) && hideAd(r)) bumpStat('elementsRemoved');
          for (const el of r.querySelectorAll(selector)) {
            if (hideAd(el)) bumpStat('elementsRemoved');
          }
        }
      } catch {
        // Invalid selector, skip
      }
    });
  }

  /**
   * Find and remove elements containing ad labels
   * CONSERVATIVE: Only removes elements with CLEAR ad-specific attributes
   */
  function removeAdLabeledElements(scopes) {
    const elementsToRemove = new Set();
    for (const scope of scopes) {
      const start = scope.body || scope;
      const walker = document.createTreeWalker(start, NodeFilter.SHOW_TEXT, null, false);
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
            const classes = typeof container.className === 'string' ? container.className : '';

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
  // carry is a disclosure label ("Sponsored", "Ad", "Gesponsert", "広告"...)
  // — US FTC, EU DSA and similar rules require one. We find elements whose
  // ENTIRE text is such a label (lib/ad-signatures.js; zero-width
  // characters, lookalike letters, spacing and RTL tricks normalized away;
  // also labels drawn by CSS ::before/::after, img alt and aria
  // attributes), then climb to the smallest enclosing card that also holds
  // a link or other clickable element, and hide it.
  //
  // Guard rails, all deterministic:
  //   - the label can't itself be a link/button (footer "Ads" links), a
  //     heading, a table header or code,
  //   - once a card is found it only grows through single-child wrappers,
  //     never into the chat message container, so an answer that streams in
  //     after the ad isn't swallowed (and a card that keeps growing after
  //     we hid it is un-hidden and re-checked),
  //   - the card stops growing when its parent would hold a second label,
  //     more than a handful of paragraphs, or too much text,
  //   - never hide <body>, main/log/feed regions, forms, settings toggles,
  //     or anything that contains a text input (the chat composer).
  // Hidden, not removed: frameworks like React crash when nodes they own
  // disappear. display:none + aria-hidden + inert also takes the ad out of
  // the accessibility tree that browser agents read.
  // =========================================================================

  const MAX_CARD_TEXT = 1200;
  const MAX_SEARCH_TEXT = 3000;
  const MAX_CARD_BLOCKS = 6;
  const LABEL_MAX = 80;
  const ACTION_SELECTOR = 'a[href], button, [role="button"], [role="link"], [onclick], [data-href], [data-url], [tabindex]:not([tabindex="-1"]), [style*="cursor: pointer"], [style*="cursor:pointer"]';
  // A card's own wrapper link ("the whole ad is one <a>").
  const WRAPPER_LINK_SELECTOR = 'a[href], [role="link"], [onclick], [data-href]';
  // Ad chrome: menu/close/"why this ad" controls are not the ad's action.
  const AD_CHROME = /\b(ad options|ad choices|adchoices|why (this|am i seeing this) ad|about this ad|hide (this )?ad|report (this )?ad|close|dismiss|more options|menu)\b/i;
  const CONTROL_SELECTOR = 'a, button, select, option, label, [role="button"], [role="link"], [role="tab"], [role="option"], [role="menuitem"], [role="switch"]';
  const BOUNDARY_SELECTOR = 'html, body, main, form, dialog, [role="main"], [role="log"], [role="feed"], [role="dialog"], [role="application"]';
  const EDITABLE_SELECTOR = 'textarea, input:not([type="hidden"]):not([type="radio"]):not([type="button"]):not([type="submit"]):not([type="reset"]), [contenteditable=""], [contenteditable="true"], [contenteditable="plaintext-only"], [role="switch"], [role="textbox"]';
  // Chat-message containers the card must never grow into.
  const MESSAGE_SELECTOR = '[data-message-author-role], [data-message-id], [data-testid^="conversation-turn"], .markdown, .prose';
  // Labels in these are about ads (answers explaining advertising), not ads.
  const NOT_A_LABEL_SELECTOR = 'h1, h2, h3, th, code, pre, kbd, samp, textarea';
  const BLOCK_COUNT_SELECTOR = 'p, li, h1, h2, h3, h4, h5, h6, pre, table, tr';
  const HIDDEN_SELECTOR = '[data-armorly-ad], [data-armorly-hidden]';
  // Where an inline rel="sponsored" link counts as an injected ad: inside a
  // chat answer or an embedded (MCP-app) frame. Elsewhere it's a site's own
  // affiliate link and out of scope.
  const CHAT_CONTEXT_SELECTOR = '[role="log"], [aria-live], [data-message-author-role], [data-message-id], [data-testid*="message" i], [class*="message" i], [class*="markdown" i], [class*="prose" i], [class*="chat" i], [class*="answer" i], [class*="response" i]';
  const IN_FRAME = window !== window.top;

  let errorsLogged = 0;
  function reportError(err) {
    if (errorsLogged++ < 3) console.warn('[Armorly] scan error:', err && err.message);
  }

  function textLen(el) {
    return (el.textContent || '').replace(/\s+/g, '').length;
  }

  function langOf(el) {
    const host = el.closest && el.closest('[lang]');
    return (host && host.getAttribute('lang')) || document.documentElement.getAttribute('lang') || '';
  }

  // Open and closed shadow roots, so ad web-components can't hide from us.
  const observedRoots = new WeakSet();
  const knownRoots = new Set();
  function shadowRootOf(el) {
    if (el.shadowRoot) return el.shadowRoot;
    try {
      if (chrome.dom && chrome.dom.openOrClosedShadowRoot) return chrome.dom.openOrClosedShadowRoot(el) || null;
    } catch (_) { /* noop */ }
    return null;
  }

  /** Shadow roots under `scope` (and theirs, recursively). */
  function discoverShadowRoots(scope) {
    const found = [];
    const queue = [scope];
    const seen = new Set(queue);
    for (let i = 0; i < queue.length; i++) {
      for (const el of queue[i].querySelectorAll('*')) {
        // Closed roots are flagged by payload-shield.js (MAIN world) with
        // data-armorly-shadow; open ones expose .shadowRoot.
        if (!el.shadowRoot && !el.localName.includes('-') && !el.hasAttribute('data-armorly-shadow')) continue;
        const sr = shadowRootOf(el);
        if (sr && !seen.has(sr)) { seen.add(sr); queue.push(sr); found.push(sr); }
      }
    }
    for (const sr of found) {
      knownRoots.add(sr);
      if (observer && !observedRoots.has(sr)) { observedRoots.add(sr); observer.observe(sr, OBSERVE_OPTIONS); }
    }
    return found;
  }

  function collectRoots() {
    discoverShadowRoots(document);
    for (const r of knownRoots) if (!r.host || !r.host.isConnected) knownRoots.delete(r);
    return [document].concat(Array.from(knownRoots));
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

  function isAdChrome(control) {
    const t = (control.getAttribute('aria-label') || control.getAttribute('title') || control.textContent || '').trim();
    return t.length <= 40 && AD_CHROME.test(t);
  }

  function hasAction(el) {
    if (el.matches(ACTION_SELECTOR) && !isAdChrome(el)) return true;
    for (const a of el.querySelectorAll(ACTION_SELECTOR)) if (!isAdChrome(a)) return true;
    return false;
  }

  /** Label is the whole text of a link/button (e.g. a footer "Ads" link). */
  function isControlText(labelEl) {
    const control = labelEl.closest(CONTROL_SELECTOR);
    return !!control && textLen(control) <= textLen(labelEl);
  }

  // ---- labels drawn by CSS: .x::before { content: "Sponsored" } ----------

  const sheetCache = new WeakMap(); // CSSStyleSheet -> [{ selector, attr, text }]

  function pseudoRulesOf(sheet) {
    if (sheetCache.has(sheet)) return sheetCache.get(sheet);
    const out = [];
    const walk = rules => {
      for (const rule of rules) {
        if (rule.cssRules && rule.cssRules.length && !rule.selectorText) { walk(rule.cssRules); continue; }
        const sel = rule.selectorText;
        if (!sel || !/::?(before|after)/i.test(sel) || !rule.style) continue;
        const content = rule.style.getPropertyValue('content');
        if (!content || content === 'none' || content === 'normal') continue;
        const base = sel.split(',').filter(p => /::?(before|after)/i.test(p)).map(p => p.replace(/::?(before|after)/gi, '').trim() || '*').join(', ');
        const attr = /attr\(\s*([\w-]+)\s*\)/i.exec(content);
        const literal = content.replace(/^["']|["']$/g, '');
        if (attr) out.push({ selector: base, attr: attr[1], text: null });
        else if (signatures.isDisclosureLabel(literal)) out.push({ selector: base, attr: null, text: literal });
      }
    };
    try { walk(sheet.cssRules); } catch (_) { /* cross-origin sheet */ }
    sheetCache.set(sheet, out);
    return out;
  }

  function pseudoLabels(root, scope, found) {
    const sheets = [];
    try {
      const owner = root.styleSheets ? root : document;
      for (const sh of owner.styleSheets) sheets.push(sh);
      if (root.adoptedStyleSheets) for (const sh of root.adoptedStyleSheets) sheets.push(sh);
    } catch (_) { return; }
    for (const sheet of sheets) {
      for (const rule of pseudoRulesOf(sheet)) {
        let els;
        try { els = scope.querySelectorAll(rule.selector); } catch (_) { continue; }
        for (const el of els) {
          const t = rule.attr ? el.getAttribute(rule.attr) : rule.text;
          if (t && signatures.isDisclosureLabel(t, langOf(el))) found.add(el);
        }
      }
    }
  }

  // ---- finding labels --------------------------------------------------

  const SKIP_TEXT_PARENTS = new Set(['script', 'style', 'noscript', 'template', 'pre', 'code', 'math']);

  /**
   * A whole ad we (or a selector) already hid. A selector-hidden LABEL
   * (e.g. [data-koah="sponsored"]) doesn't count: it still tells us where
   * the rest of the card is.
   */
  function isHiddenCard(el) {
    if (el.hasAttribute('data-armorly-ad')) return true;
    return el.hasAttribute('data-armorly-hidden') && el.textContent.length > LABEL_MAX;
  }

  function insideHiddenCard(el) {
    for (let p = el; p; p = p.parentElement) if (p.nodeType === 1 && p.matches(HIDDEN_SELECTOR) && isHiddenCard(p)) return true;
    return false;
  }

  function newTextWalker(start) {
    return document.createTreeWalker(start, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT, {
      acceptNode(n) {
        if (n.nodeType === 1) {
          if (SKIP_TEXT_PARENTS.has(n.localName) || (n.matches(HIDDEN_SELECTOR) && isHiddenCard(n))) return NodeFilter.FILTER_REJECT;
          return NodeFilter.FILTER_SKIP;
        }
        return NodeFilter.FILTER_ACCEPT;
      }
    });
  }

  function findDisclosureLabels(root, scope, prefixed) {
    const found = new Set();
    const start = scope.body || scope;
    const walker = newTextWalker(start);
    let node;
    while ((node = walker.nextNode())) {
      const raw = node.nodeValue;
      if (!raw || !raw.trim()) continue;
      const parent = node.parentElement;
      if (!parent) continue;
      if (raw.length > LABEL_MAX) {
        // "Sponsored: Try Acme…" glued to the start of a paragraph.
        if (signatures.isDisclosurePrefix(raw)) prefixed.add(parent);
        continue;
      }
      const lang = langOf(parent);
      if (signatures.isDisclosurePrefix(raw) && !signatures.isDisclosureLabel(raw, lang)) {
        prefixed.add(parent);
        continue;
      }
      // The label may be split across inline elements ("Spon<b>sored</b>"),
      // so test the text node's parent and a couple of ancestors.
      let el = parent;
      for (let i = 0; i < 3 && el; i++) {
        if (found.has(el)) break;
        const t = el.textContent;
        if (t.length > LABEL_MAX) break;
        if (signatures.isDisclosureLabel(t, lang)) { found.add(el); break; }
        el = el.parentElement;
      }
    }
    const attrScope = scope.querySelectorAll ? scope : root;
    for (const el of attrScope.querySelectorAll('[aria-label], [title], img[alt], [aria-labelledby]')) {
      if (insideHiddenCard(el)) continue;
      let t = el.getAttribute('aria-label') || el.getAttribute('title') || (el.localName === 'img' ? el.getAttribute('alt') : null);
      if (!t && el.hasAttribute('aria-labelledby')) {
        const owner = el.getRootNode();
        t = el.getAttribute('aria-labelledby').split(/\s+/)
          .map(id => (owner.getElementById ? owner.getElementById(id) : document.getElementById(id)))
          .filter(Boolean).map(n => n.textContent).join(' ');
        if (signatures.isDisclosureLabel(t, langOf(el))) found.add(el);
        continue;
      }
      if (signatures.isDisclosureLabel(t, langOf(el)) && textLen(el) === 0) found.add(el);
    }
    pseudoLabels(root, attrScope, found);
    // Keep the outermost element of nested matches (<span><b>Ad</b></span>).
    const list = Array.from(found);
    return list.filter(el => {
      for (let p = el.parentElement; p; p = p.parentElement) if (found.has(p)) return false;
      return !el.closest(NOT_A_LABEL_SELECTOR);
    });
  }

  /** Disclosure labels inside `el`, ignoring ones already hidden. */
  function countLabels(el, limit) {
    let n = 0;
    const walker = newTextWalker(el);
    let node;
    const seen = new Set();
    while ((node = walker.nextNode())) {
      const raw = node.nodeValue;
      if (!raw || raw.length > LABEL_MAX || !raw.trim()) continue;
      let p = node.parentElement;
      for (let i = 0; i < 3 && p && el.contains(p); i++) {
        if (seen.has(p)) break;
        if (p.textContent.length > LABEL_MAX) break;
        if (signatures.isDisclosureLabel(p.textContent, langOf(p))) { seen.add(p); if (++n >= limit) return n; break; }
        p = p.parentElement;
      }
    }
    return n;
  }

  /** May the card grow from `node` into `parent` (a pure wrapper)? */
  function isWrapperOf(parent, node) {
    if (parent.matches(MESSAGE_SELECTOR)) return false;
    if (node.parentElement === parent) return parent.childElementCount === 1;
    const root = node.getRootNode && node.getRootNode();
    return !!(root && root.host === parent && root.childElementCount === 1);
  }

  function cardFor(labelEl) {
    // <details><summary>Sponsored</summary>…</details>
    const summary = labelEl.closest('summary');
    if (summary && textLen(summary) <= textLen(labelEl)) {
      const details = summary.closest('details');
      if (details && !isBoundary(details) && textLen(details) <= MAX_CARD_TEXT && textLen(details) - textLen(labelEl) >= 3) return details;
      return null;
    }
    if (isControlText(labelEl)) return null;
    // <section aria-labelledby="h"> where h reads "Sponsored": the
    // labelled element is the ad.
    if (labelEl.hasAttribute('aria-labelledby') && textLen(labelEl) > 0) {
      if (!isBoundary(labelEl) && !labelEl.matches(MESSAGE_SELECTOR) && textLen(labelEl) <= MAX_CARD_TEXT && hasAction(labelEl)) return labelEl;
      return null;
    }
    let node = labelEl;
    let card = null;
    // The whole ad is one link/clickable wrapper around the label.
    const wrapper = labelEl.closest(WRAPPER_LINK_SELECTOR);
    if (wrapper && wrapper !== labelEl && !isBoundary(wrapper) && !wrapper.matches(MESSAGE_SELECTOR) &&
        // (Several labels inside one wrapper link are still one ad:
        // "Sponsored" in the header plus a "Paid placement" note.)
        textLen(wrapper) - textLen(labelEl) >= 3 && textLen(wrapper) <= MAX_CARD_TEXT &&
        wrapper.querySelectorAll(BLOCK_COUNT_SELECTOR).length <= MAX_CARD_BLOCKS) {
      node = card = wrapper;
    }
    for (let i = 0; i < 15; i++) {
      const parent = parentAcrossShadow(node);
      // Never into the chat message itself: a short answer that mentions
      // "Sponsored" and links somewhere is not an ad.
      if (!parent || isBoundary(parent) || parent.matches(MESSAGE_SELECTOR)) break;
      const pLen = textLen(parent);
      if (pLen > (card ? MAX_CARD_TEXT : MAX_SEARCH_TEXT)) break;
      // Once we have a card, only climb through pure wrappers.
      if (card && (pLen > textLen(card) || !isWrapperOf(parent, node))) break;
      if (countLabels(parent, 2) > 1) break;
      if (parent.querySelectorAll(BLOCK_COUNT_SELECTOR).length > MAX_CARD_BLOCKS) break;
      node = parent;
      if (card) card = node;
      else if (hasAction(node)) {
        // A card must hold more than the label itself. Checked here, not
        // at the end: a shadow host's textContent excludes its shadow
        // content, so wrappers further up can read as empty.
        if (textLen(node) - textLen(labelEl) < 3) return null;
        if (textLen(node) > MAX_CARD_TEXT) return null;
        card = node;
      }
    }
    return card;
  }

  /**
   * The whole frame is the ad: an MCP-app / srcdoc / ad iframe whose body
   * holds a disclosure label and a link and nothing else of substance.
   */
  function frameAdBody(labelEl) {
    if (!IN_FRAME || !document.body || !document.body.contains(labelEl)) return null;
    if (isControlText(labelEl) || labelEl.closest(NOT_A_LABEL_SELECTOR)) return null;
    const body = document.body;
    if (body.isContentEditable || body.querySelector(EDITABLE_SELECTOR)) return null;
    if (textLen(body) > MAX_CARD_TEXT || !hasAction(body)) return null;
    if (countLabels(body, 2) > 1) return null;
    return body;
  }

  // Cards we hid by label, with their text length at the time, so a card
  // that keeps growing (an answer streaming into a wrapper we misjudged)
  // can be un-hidden and re-checked.
  const labelCards = [];

  function hideAdElement(el, reason) {
    if (el.hasAttribute('data-armorly-ad')) return false;
    if (el.hasAttribute('data-armorly-hidden') && isHiddenCard(el)) return false;
    el.setAttribute('data-armorly-ad', reason);
    el.setAttribute('data-armorly-prev-display', el.style.getPropertyValue('display') + '|' + el.style.getPropertyPriority('display'));
    el.setAttribute('aria-hidden', 'true');
    el.inert = true;
    el.style.setProperty('display', 'none', 'important');
    if (reason.startsWith('disclosure')) labelCards.push({ el, len: textLen(el) });
    return true;
  }

  function unhideAdElement(el) {
    const [display, priority] = (el.getAttribute('data-armorly-prev-display') || '|').split('|');
    if (display) el.style.setProperty('display', display, priority);
    else el.style.removeProperty('display');
    el.removeAttribute('data-armorly-ad');
    el.removeAttribute('data-armorly-prev-display');
    el.removeAttribute('aria-hidden');
    el.inert = false;
  }

  /** Returns cards that grew after hiding; they are un-hidden for a re-check. */
  function revalidateLabelCards() {
    const regrown = [];
    for (let i = labelCards.length - 1; i >= 0; i--) {
      const { el, len } = labelCards[i];
      if (!el.isConnected) { labelCards.splice(i, 1); continue; }
      if (textLen(el) > len + 20) {
        labelCards.splice(i, 1);
        unhideAdElement(el);
        regrown.push(el);
      }
    }
    return regrown;
  }

  const BLOCK_SELECTOR = 'p, li, blockquote, div, section, aside, article, dd, figure';
  // "Term: definition" — a short term, a colon, then a space.
  const GLOSSARY_TEXT = /^\s*[^\s:][^:\n]{0,40}:\s/;

  /** Starts like a glossary entry: <strong>Term:</strong> … or "Term: …". */
  function looksLikeTerm(block) {
    let first = block.firstChild;
    while (first && first.nodeType === 3 && !first.nodeValue.trim()) first = first.nextSibling;
    if (!first) return false;
    if (first.nodeType === 1) {
      if (!first.matches('strong, b, em, dfn, dt, code, kbd')) return false;
      const t = first.textContent.trim();
      return t.length <= 40 && /:$/.test(t);
    }
    return first.nodeType === 3 && GLOSSARY_TEXT.test(first.nodeValue);
  }

  /** `block` is one entry in a run of "Term: definition" entries. */
  function isGlossaryEntry(block) {
    if (!block.parentElement || !looksLikeTerm(block)) return false;
    const siblings = Array.from(block.parentElement.children).filter(c => c !== block);
    return siblings.filter(looksLikeTerm).length >= 2;
  }

  /** The block a "Sponsored: …" prefix opens, if the prefix starts it. */
  function prefixedBlock(el) {
    const block = el && el.closest(BLOCK_SELECTOR);
    if (!block || isBoundary(block) || block.matches(MESSAGE_SELECTOR) || textLen(block) > MAX_CARD_TEXT) return null;
    if (!signatures.isDisclosurePrefix(block.textContent.trim())) return null;
    if (!hasAction(block)) return null;
    // A glossary ("AD: …", "Ad: …", "CPM: …") is a run of "Term:" blocks.
    if (isGlossaryEntry(block)) return null;
    return block;
  }

  /** <a>Acme</a><sup>Ad</sup>: neutralize the link, hide just the marker. */
  function inlineMarkerLink(labelEl) {
    if (!labelEl.matches('sup, sub, small, span, em, i, b, strong, mark')) return null;
    if (!labelEl.parentElement || !labelEl.parentElement.matches('p, li, td, dd, span, em, strong, blockquote')) return null;
    const adjacent = (start, dir) => {
      let n = start[dir];
      while (n && n.nodeType === 3 && !n.nodeValue.trim()) n = n[dir];
      return n && n.nodeType === 1 && n.matches('a[href]') ? n : null;
    };
    return adjacent(labelEl, 'previousSibling') || adjacent(labelEl, 'nextSibling');
  }

  function processLabels(labels, retry) {
    for (const label of labels) {
      try {
        processLabel(label, retry);
      } catch (err) {
        // One odd ad must not stop detection for every label after it.
        reportError(err);
      }
    }
  }

  function processLabel(label, retry) {
    {
      if (!label.isConnected || insideHiddenCard(label)) return;
      const marker = inlineMarkerLink(label);
      if (marker) {
        neutralizeLink(marker);
        if (hideAdElement(label, 'disclosure-marker')) bumpStat('elementsRemoved');
        return;
      }
      let card = cardFor(label) || frameAdBody(label);
      if (card && card !== document.body && isGlossaryEntry(card)) card = null;
      if (card) {
        if (card === document.body) {
          for (const child of Array.from(card.children)) hideAdElement(child, 'disclosure-frame');
          bumpStat('elementsRemoved');
        } else if (hideAdElement(card, 'disclosure')) {
          bumpStat('elementsRemoved');
        }
      } else if (retry) {
        retry.push(label);
      }
    }
  }

  // ╭─ Sponsored ──╮ boxes drawn in a code block (CLI/MCP tool output).
  const BOX_CHARS = /[╭╮╰╯┌┐└┘├┤─━═│┃|+=*#\s-]+/g;
  function hideBoxDrawnAds(scope) {
    for (const pre of scope.querySelectorAll('pre')) {
      if (insideHiddenCard(pre) || textLen(pre) > MAX_CARD_TEXT || !pre.querySelector('a[href]')) continue;
      const first = (pre.textContent.split('\n').find(l => l.trim()) || '');
      if (!/[╭┌─━═]/.test(first)) continue;
      if (signatures.isDisclosureLabel(first.replace(BOX_CHARS, ' ').trim(), langOf(pre)) && hideAdElement(pre, 'disclosure-box')) {
        bumpStat('elementsRemoved');
      }
    }
  }

  // "the <a>Nike Pegasus</a> is a solid pick (sponsored)": a marker in the
  // text right after a link makes that link paid.
  // Case-sensitive "(ad)"/"(Ad)": "(AD)" is an abbreviation (Alzheimer's
  // disease, Active Directory). Only inside chat answers and embedded
  // frames: on ordinary sites "(affiliate link)" is the site's own business.
  const INLINE_MARKER = /[(\[]\s*([Ss]ponsored|SPONSORED|[Aa]d|[Pp]aid( link)?|[Aa]ffiliate( link)?|[Pp]romoted|[Aa]dvertisement)\s*[)\]]/;
  function neutralizeMarkedLinks(scope) {
    for (const a of scope.querySelectorAll('a[href]')) {
      const next = a.nextSibling;
      if (!next || next.nodeType !== 3) continue;
      if (!IN_FRAME && !a.closest(CHAT_CONTEXT_SELECTOR)) continue;
      const head = next.nodeValue.slice(0, 80);
      const m = INLINE_MARKER.exec(head);
      // The marker must come before the sentence ends.
      if (m && !/[.!?]\s/.test(head.slice(0, m.index)) && neutralizeLink(a)) bumpStat('linksCleaned');
    }
  }

  function hideDisclosedAdCards(scopes) {
    if (!signatures) return;
    for (const scope of scopes) {
      try { hideBoxDrawnAds(scope); } catch (err) { reportError(err); }
      try { neutralizeMarkedLinks(scope); } catch (err) { reportError(err); }
      const root = scope.nodeType === 11 || scope.nodeType === 9 ? scope : (scope.getRootNode ? scope.getRootNode() : document);
      const prefixed = new Set();
      const labels = findDisclosureLabels(root, scope, prefixed);
      // Two passes: a carousel header ("Sponsored") only resolves to its
      // shell once the per-card labels inside it are hidden.
      const retry = [];
      processLabels(labels, retry);
      if (retry.length) processLabels(retry, null);
      for (const el of prefixed) {
        if (!el || insideHiddenCard(el)) continue;
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
  // straight to the destination so no paid click is recorded. Paid links in
  // a chat answer (rel="sponsored", the HTML standard marker) keep their
  // words but lose the link.
  // =========================================================================

  let adHostList = null;
  function isAdHost(hostname) {
    if (!adHostList) adHostList = patterns.getAllSDKDomains().concat(patterns.verificationDomains || []).map(d => d.toLowerCase());
    const h = hostname.toLowerCase();
    return adHostList.some(d => h === d || h.endsWith('.' + d));
  }

  /** Strip a paid link to its words, React-safely (no node is replaced). */
  function neutralizeLink(link) {
    if (link.hasAttribute('data-armorly-neutralized')) return false;
    link.setAttribute('data-armorly-neutralized', link.getAttribute('href') || '');
    link.removeAttribute('href');
    link.removeAttribute('ping');
    link.removeAttribute('attributionsrc');
    link.style.setProperty('pointer-events', 'none', 'important');
    link.style.setProperty('color', 'inherit', 'important');
    link.style.setProperty('text-decoration', 'none', 'important');
    link.style.setProperty('cursor', 'text', 'important');
    return true;
  }

  const linkSeen = new WeakMap(); // link -> href last processed

  function neutralizeAdLinks(scopes) {
    for (const scope of scopes) {
      for (const el of scope.querySelectorAll('[ping], [attributionsrc]')) {
        el.removeAttribute('ping');
        el.removeAttribute('attributionsrc');
      }
      for (const link of scope.querySelectorAll('a[rel~="sponsored" i][href]')) {
        if (link.closest(HIDDEN_SELECTOR)) continue;
        // A card-shaped sponsored link (image, blocks, or a paragraph of
        // copy) is an ad unit: hide it anywhere. An inline one in a chat
        // answer keeps its words and loses the link.
        // Only in chat answers and embedded frames: on an ordinary site a
        // rel="sponsored" link is the site's own affiliate link.
        if (!IN_FRAME && !link.closest(CHAT_CONTEXT_SELECTOR)) continue;
        const cardLike = link.querySelector('img, picture, video, div, p, h1, h2, h3, h4, h5, h6, ul, ol') || textLen(link) > 80;
        if (cardLike && !isBoundary(link)) {
          if (hideAdElement(link, 'sponsored-link')) bumpStat('elementsRemoved');
        } else if (neutralizeLink(link)) {
          bumpStat('linksCleaned');
        }
      }
      if (!signatures) continue;
      for (const link of scope.querySelectorAll('a[href]')) {
        const href = link.href;
        if (linkSeen.get(link) === href) continue;
        linkSeen.set(link, href);
        const dest = signatures.unwrapClickRedirect(href, isAdHost);
        if (dest) {
          link.href = dest;
          linkSeen.set(link, link.href);
          link.setAttribute('data-armorly-unwrapped', 'true');
          bumpStat('linksCleaned');
        }
      }
    }
  }

  // =========================================================================
  // SCAN SCHEDULING
  //
  // Full scans on load and when the page goes quiet; while an answer is
  // streaming, scans every <=300ms limited to the subtrees that changed.
  // =========================================================================

  /** Drop scopes contained in other scopes. */
  function topmost(nodes) {
    const list = Array.from(nodes).filter(n => n && n.isConnected);
    return list.filter(n => !list.some(o => o !== n && o.contains(n)));
  }

  function scanScopes(scopes) {
    const regrown = revalidateLabelCards();
    // New shadow roots inside changed subtrees join the scan.
    const extra = [];
    for (const s of scopes) if (s.nodeType === 1) extra.push(...discoverShadowRoots(s));
    const all = topmost(scopes.concat(regrown)).concat(extra);
    for (const pass of [removeAdElements, removeAdLabeledElements, hideDisclosedAdCards, neutralizeAdLinks, cleanAffiliateLinks]) {
      try { pass(all); } catch (err) { reportError(err); }
    }
  }

  function scanAll() {
    scanScopes(collectRoots());
  }

  // =========================================================================
  // 3. AFFILIATE LINK CLEANING
  // =========================================================================

  /**
   * Clean affiliate tracking from all links
   */
  function cleanAffiliateLinks(scopes) {
    const links = (scopes || collectRoots()).flatMap(r => Array.from(r.querySelectorAll('a[href]')));

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

  let observer = null;
  const dirty = new Set();      // changed since the last mid-burst scan
  const burstDirty = new Set(); // changed since the burst began
  let quietTimer = null;
  let burstStart = 0;
  const QUIET_MS = 100;
  const MAX_WAIT_MS = 300;

  let fullScanPending = false;

  function flushDirty() {
    burstStart = 0;
    const scopes = Array.from(dirty);
    dirty.clear();
    // A page that never goes quiet (tickers, live logs) must not grow the
    // burst set forever: drop detached nodes, and past a cap fall back to
    // one full scan when it does go quiet.
    for (const n of burstDirty) if (!n.isConnected) burstDirty.delete(n);
    if (burstDirty.size > 2000) { burstDirty.clear(); fullScanPending = true; }
    // Runs even with nothing new: it re-checks hidden cards that grew.
    scanScopes(scopes);
  }

  // When the page goes quiet, rescan everything that changed in the burst
  // (a whole streamed answer at once: labels split across mid-burst scans
  // are seen whole). Full-page scans run only on load.
  function onQuiet() {
    quietTimer = null;
    burstStart = 0;
    const scopes = Array.from(burstDirty);
    burstDirty.clear();
    dirty.clear();
    if (fullScanPending) { fullScanPending = false; scanAll(); return; }
    scanScopes(scopes);
  }

  /**
   * Set up observer to catch dynamically added ads
   */
  function setupObserver() {
    observer = new MutationObserver((mutations) => {
      let changed = false;
      for (const mutation of mutations) {
        // characterData: chat answers stream in as text edits to an
        // existing node, so a label can appear without a node being added.
        if (mutation.type === 'characterData' || mutation.addedNodes.length > 0) {
          const t = mutation.target.nodeType === 1 ? mutation.target : mutation.target.parentElement;
          if (!t) continue;
          // Inside a card we hid: no rescan of that subtree, but the scan
          // still runs, which re-checks whether the card kept growing.
          if (!t.closest(HIDDEN_SELECTOR)) { dirty.add(t); burstDirty.add(t); }
          changed = true;
        }
      }
      if (!changed) return;
      const now = Date.now();
      if (!burstStart) burstStart = now;
      clearTimeout(quietTimer);
      quietTimer = setTimeout(onQuiet, QUIET_MS);
      // A stream never goes quiet for 100ms; don't let the ad sit there.
      if (now - burstStart >= MAX_WAIT_MS) flushDirty();
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
