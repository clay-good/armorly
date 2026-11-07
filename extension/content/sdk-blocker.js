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

  // Later passes (auto-updated SDK names) and the per-site disable switch
  // arrive through payload-shield.js, which owns the authenticated channel
  // to the isolated world. We hand it our controls via a one-shot global
  // that it deletes before any page script runs. (Previously we listened
  // for a plain window.postMessage, which any page could forge to switch
  // Armorly off on itself.)
  try {
    Object.defineProperty(window, '__armorlySdkControl', {
      configurable: true,
      value: {
        install: installProxiesFor,
        disable: function () {
          // User toggled "Protect this site" off: tear down every proxy so
          // the page sees the original globals again (typically undefined).
          for (const name of installed) {
            try { delete window[name]; } catch (_) { /* noop */ }
          }
          installed.clear();
        }
      }
    });
  } catch (_) { /* noop */ }
})();
