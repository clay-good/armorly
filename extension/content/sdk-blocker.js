/**
 * Armorly - Page-world SDK interceptor.
 *
 * Runs in the MAIN content-script world so that proxies installed on
 * `window.Koah` etc. are visible to page-level scripts. (The old
 * combined ai-ad-blocker.js ran in the default ISOLATED world, whose
 * `window` is *not* the page's window — so SDK calls coming from page
 * scripts never hit the proxy. That bug was caught by Phase 2 tests.)
 *
 * This file MUST NOT reference any `chrome.*` API: MAIN-world scripts
 * don't have extension privileges. It depends only on `window.ArmorlyAdPatterns`,
 * which lib/ad-patterns.js installs in the same world via an IIFE.
 *
 * For every blocked SDK call, we postMessage back to the page so the
 * isolated-world ai-ad-blocker.js can bump its stats counter.
 */

(function () {
  'use strict';

  if (!window.ArmorlyAdPatterns) return;

  // Names we've already installed proxies for. Used to ignore duplicates
  // when the isolated-world script later pushes an updated list pulled
  // from cached_patterns (chrome.storage.local). See message listener below.
  const installed = new Set();

  function createProxy() {
    return new Proxy({}, {
      get: function () {
        return function () {
          try {
            window.postMessage({ source: 'armorly', type: 'sdk-blocked' }, '*');
          } catch (_) { /* noop */ }
          return Promise.resolve();
        };
      },
      set: function () {
        return true;
      }
    });
  }

  function installProxiesFor(names) {
    if (!Array.isArray(names)) return;
    for (const name of names) {
      if (typeof name !== 'string' || installed.has(name)) continue;
      try {
        const proxy = createProxy();
        Object.defineProperty(window, name, {
          get: function () { return proxy; },
          set: function () { return true; },
          // `configurable: true` so we can tear the proxy down if the user
          // disables Armorly for this site (see `disable-site` handler).
          // The cost is that a hostile page could `delete window.<name>`
          // to evade us; the AI ad SDKs we target don't do this, and the
          // page-side recovery is what makes the per-site disable actually
          // work end to end.
          configurable: true
        });
        installed.add(name);
      } catch (_) {
        // Property may already be defined non-configurable on the page; skip.
      }
    }
  }

  // First pass: install from the bundled patterns. Runs synchronously at
  // document_start so the proxy lands before any inline ad-SDK call.
  installProxiesFor(window.ArmorlyAdPatterns.getAllSDKFunctions());

  // Second pass: when ai-ad-blocker.js (isolated world) finishes its
  // chrome.storage.local lookup and merges cached_patterns, it postMessages
  // the updated function list to us so we can proxy any names the daily
  // background refresh added since the bundle was packaged.
  window.addEventListener('message', function (event) {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.source !== 'armorly') return;
    if (data.type === 'update-sdk-list' && Array.isArray(data.functions)) {
      installProxiesFor(data.functions);
    } else if (data.type === 'disable-site') {
      // User toggled "Protect this site" off in the popup. Tear down every
      // proxy we installed so the page sees the original globals again
      // (typically undefined). Delivered from ai-ad-blocker.js after its
      // chrome.storage.local lookup.
      for (const name of installed) {
        try { delete window[name]; } catch (_) { /* noop */ }
      }
      installed.clear();
    }
  });
})();
