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
  const sdkFunctions = window.ArmorlyAdPatterns.getAllSDKFunctions();

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

  sdkFunctions.forEach(function (name) {
    try {
      const proxy = createProxy();
      Object.defineProperty(window, name, {
        get: function () { return proxy; },
        set: function () { return true; },
        configurable: false
      });
    } catch (_) {
      // Property may already be defined non-configurable. Skip.
    }
  });
})();
