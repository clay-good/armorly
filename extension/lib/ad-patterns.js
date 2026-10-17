/**
 * Armorly - AI Ad Patterns Library
 *
 * Detection patterns for AI-native advertising networks and SDKs.
 * Blocks ads from: Grok/X, Koah, Imprezia, Kontext, Gravity, Thrad, and others.
 *
 * This file is designed to be easily updatable as ad networks evolve.
 */

(function() {
  'use strict';

  // Bumped when the bundled data changes; used to decide whether a cached
  // remote copy is newer. Keep in lockstep with the `version` field in the
  // sibling extension/lib/ad-patterns.json — the build script verifies they
  // match before packaging.
  const BUNDLED_VERSION = '2026-10-17';

  // Expose patterns globally for content scripts
  window.ArmorlyAdPatterns = {
    version: BUNDLED_VERSION,

    // =========================================================================
    // AI AD SDK DETECTION (Alphabetical order)
    // =========================================================================

    adSDKs: {
      // Grok/X - Elon Musk's AI chatbot ads
      grok: {
        functions: ['GrokAds', 'grokAds', 'XAds', 'xAds'],
        methods: ['init', 'show', 'display', 'track', 'impression'],
        scriptPatterns: [
          /grok\.x\.com/i,
          /ads\.x\.com/i,
          /grok-ads/i,
          /x-promoted/i
        ],
        domainPatterns: [
          'grok.x.com',
          'ads.x.com'
        ]
      },

      // Koah - $5M funded, serving ads in Luzia, Liner, DeepAI
      koah: {
        functions: ['Koah', 'koah', 'KoahAds'],
        methods: ['init', 'showAd', 'displayAd', 'trackImpression', 'trackClick', 'monetize'],
        scriptPatterns: [
          /koah\.io/i,
          /koah\.ai/i,
          /koah-sdk/i,
          /koah\.js/i
        ],
        domainPatterns: [
          'koah.io',
          'koah.ai',
          'api.koah.io',
          'sdk.koah.io',
          'app.koah.ai'
        ]
      },

      // Monetzly - server-side only (rewrites the LLM stream; the publisher
      // renders the text), so there is no browser global or markup to match.
      // Only its API host is blocked.
      monetzly: {
        functions: [],
        methods: [],
        scriptPatterns: [
          /monetzly\.com/i
        ],
        domainPatterns: [
          'monetzly.com',
          'api.monetzly.com'
        ]
      },

      // Imprezia - Y Combinator backed AI ad network
      imprezia: {
        functions: ['Imprezia', 'imprezia'],
        methods: ['init', 'monetize', 'showAd', 'trackImpression', 'trackClick'],
        scriptPatterns: [
          /imprezia\.ai/i,
          /imprezia\.js/i,
          /imprezia-sdk/i
        ],
        domainPatterns: [
          'imprezia.ai',
          'api.imprezia.ai',
          'sdk.imprezia.ai',
          'imprezia.net',
          'r.imprezia.net'
        ]
      },

      // Kontext (kontext.so) - inline ad iframes served from server.megabrain.co
      kontext: {
        functions: [],
        methods: ['addMessage', 'render'],
        scriptPatterns: [
          /megabrain\.co/i,
          /kontext\.so/i,
          /@kontextso/i
        ],
        domainPatterns: [
          'kontext.so',
          'megabrain.co',
          'server.megabrain.co'
        ]
      },

      // Gravity (trygravity.ai) - per-turn ads + gravityPixel tracker
      gravity: {
        functions: ['gravityPixel', 'GravityAd'],
        methods: ['track', 'getSessionId'],
        scriptPatterns: [
          /trygravity\.(?:ai|com)/i,
          /@gravity-ai/i,
          /gravity-ad\.js/i
        ],
        domainPatterns: [
          'trygravity.ai',
          'server.trygravity.ai',
          'api.trygravity.ai',
          'trygravity.com'
        ]
      },

      // Thrad (thrad.ai) - native ads under AI replies, sdk.thrad.ai/sdk.js
      thrad: {
        functions: ['thrad'],
        methods: ['render'],
        scriptPatterns: [
          /thrads?\.ai/i
        ],
        domainPatterns: [
          'thrad.ai',
          'sdk.thrad.ai',
          'cdn.thrad.ai',
          'thrads.ai'
        ]
      },

      // ZeroClick - offer links woven into model output, tracked by
      // cdn.zeroclick.ai/scripts/mcp-*.js (zeroclick.io is payments, not ads)
      zeroclick: {
        functions: [],
        methods: [],
        scriptPatterns: [
          /zeroclick\.(?:ai|dev)/i,
          /zero\.click/i
        ],
        domainPatterns: [
          'zeroclick.ai',
          'mcp.zeroclick.ai',
          'cdn.zeroclick.ai',
          'zeroclick.dev',
          'zero.click'
        ]
      },

      // EarnLayer - contextual chat ads. The service is defunct (its API
      // hosts don't resolve; earnlayerai.com is now an unrelated site), so
      // only its still-installable npm components are matched, by markup.
      earnlayer: {
        functions: [],
        methods: [],
        scriptPatterns: [
          /api\.earnlayer(?:ai)?\.com/i
        ],
        domainPatterns: [
          'api.earnlayerai.com',
          'api.earnlayer.com'
        ]
      },

      // Lulu (getlulu.dev) - sponsored slots in MCP tool output
      lulu: {
        functions: [],
        methods: [],
        scriptPatterns: [
          /getlulu\.dev/i
        ],
        domainPatterns: [
          'getlulu.dev',
          'ads.getlulu.dev'
        ]
      },

      // ChatAds (getchatads.com)
      chatads: {
        functions: [],
        methods: [],
        scriptPatterns: [
          /getchatads\.com/i
        ],
        domainPatterns: [
          'getchatads.com',
          'api.getchatads.com'
        ]
      },

      // Google AdSense in chatbots
      adsense: {
        functions: ['adsbygoogle'],
        methods: ['push'],
        scriptPatterns: [
          /pagead2\.googlesyndication\.com/i,
          /adservice\.google/i
        ],
        domainPatterns: [
          'pagead2.googlesyndication.com',
          'adservice.google.com'
        ]
      }
    },

    // =========================================================================
    // COMBINED SDK PATTERNS (for easy iteration)
    // =========================================================================

    /**
     * Get all SDK function names to intercept
     */
    getAllSDKFunctions: function() {
      const functions = [];
      Object.values(this.adSDKs).forEach(sdk => {
        functions.push(...sdk.functions);
      });
      return [...new Set(functions)];
    },

    /**
     * Get all SDK script URL patterns
     */
    getAllScriptPatterns: function() {
      const patterns = [];
      Object.values(this.adSDKs).forEach(sdk => {
        patterns.push(...sdk.scriptPatterns);
      });
      return patterns;
    },

    /**
     * Get all SDK domains to block
     */
    getAllSDKDomains: function() {
      const domains = [];
      Object.values(this.adSDKs).forEach(sdk => {
        domains.push(...sdk.domainPatterns);
      });
      return [...new Set(domains)];
    },

    // =========================================================================
    // AD LABEL PATTERNS (FTC-required disclosure)
    // =========================================================================

    adLabels: {
      // Exact matches (case-insensitive) - ONLY clear ad indicators
      exact: [
        'sponsored',
        'sponsored by',
        'advertisement',
        'promoted',
        'paid partnership',
        'paid promotion'
      ],

      // Regex patterns for variations/obfuscation attempts - CONSERVATIVE
      patterns: [
        /\bsponsored\b/i,
        /\bsp[o0]ns[o0]red\b/i,  // Obfuscation: sp0nsored
        /\badvertisement\b/i,
        /\bpromoted\s+(?:content|post|result)\b/i,
        /\bpaid\s+(?:partnership|promotion)\b/i,
        /\bin\s+partnership\s+with\b/i,
        /\bbrought\s+to\s+you\s+by\b/i
      ]
    },

    // =========================================================================
    // AFFILIATE/TRACKING LINK PATTERNS
    // =========================================================================

    affiliateParams: [
      'utm_source',
      'utm_medium',
      'utm_campaign',
      'utm_content',
      'utm_term',
      'ref',
      'aff',
      'affiliate',
      'partner_id',
      'partner',
      'tracking_id',
      'click_id',
      'campaign_id',
      'source',
      'tag'  // Amazon affiliate
    ],

    affiliateDomains: [
      'amzn.to',
      'bit.ly',
      't.co',
      'geni.us',
      'rstyle.me',
      'shopstyle.it',
      'go.redirectingat.com',
      'anrdoezrs.net',
      'awin1.com',
      'tkqlhce.com',
      'jdoqocy.com',
      'dpbolvw.net',
      'kqzyfj.com',
      'commission-junction.com',
      'shareasale.com',
      'pjatr.com',
      'pjtra.com',
      'pntrac.com',
      'pntrs.com'
    ],

    // Known commercial/booking domains often used in AI ads
    commercialDomains: [
      'booking.com',
      'trip.com',
      'expedia.com',
      'hotels.com',
      'airbnb.com',
      'vrbo.com',
      'kayak.com',
      'tripadvisor.com',
      'agoda.com',
      'hostelworld.com',
      'skyscanner.com'
    ],

    // =========================================================================
    // PLATFORM-SPECIFIC AD SELECTORS
    // =========================================================================

    // NOTE: Selectors must be SPECIFIC to avoid false positives.
    // Avoid broad patterns like [class*="ad-"] which match "grad-text", "header-ad", etc.

    platformSelectors: {
      // Grok/X - Only exact ad-related patterns
      grok: [
        '[data-testid="promotedIndicator"]',
        '[data-testid="promotedTweet"]',
        '.promoted-tweet',
        '.grok-ad-container',
        '.grok-sponsored-content'
      ],

      // Perplexity AI - Specific sponsored content selectors
      perplexity: [
        '[data-testid="sponsored-question"]',
        '.sponsored-followup',
        '.pplx-sponsored'
      ],

      // ChatGPT (expected patterns based on leaked code)
      chatgpt: [
        '[data-testid="shopping-card"]',
        '[data-testid="product-recommendation"]',
        '.chatgpt-sponsored',
        '.openai-ad',
        // Live ChatGPT ad units, mirrored from EasyList's and uBlock's chatgpt.com rules
        'aside[data-assistant-ads-unit]',
        'div[data-assistant-ads]',
        '[class*="_assistantAds"]',
        'div[data-message-supplement]:has(aside[data-partial-island="assistant-ads"])',
        '[data-testid="bazaar-v2-elevated-box"]',
        'div[data-testid="bazaar-single-card-container"]',
        'section:has(> [aria-label="Sponsored"])',
        '.border-token-border-default.mt-2.border-t:has(button[aria-label="Ad options"])',
        'div.opacity-100.transition-opacity.ease-out:has(button[aria-label="Sponsored options"], button[aria-label="Ad options"])',
        'div[role="complementary"]:has(a[href*="oppref="])',
        'a[rel][target="_blank"][href*="?utm_"][href*="&oppref="]',
        '.wm-app-threadContent aside[aria-label^="Sponsored"]',
        'div[class]:has(> div.flex > button[aria-label="Ad options"])',
        'div[data-testid] div[class^="max-"] > div[data-ad-card-root]',
        'div[data-testid] div[class^="max-"] > div[data-testid="image-card-v2"]:has(button[aria-label="Sponsored options"])',
        'div[data-testid] div[class^="relative max-"]:has(> div[data-testid="image-card-v2"] + .pointer-events-none button[aria-label="Sponsored options"])'
      ],

      // Microsoft Copilot (copilot.microsoft.com)
      copilot: [
        'div[data-testid="ads-card"]',
        '.b_ad',
        'div[data-ads-rg]'
      ],

      // You.com
      youcom: [
        '[data-testid="microsoft-ads"]',
        'div[data-testid="youchat-ads"]'
      ],

      // Character.ai (EasyList)
      characterai: [
        '.z-40.max-w-\\[970px\\]'
      ],


      // Koah-powered apps (Luzia, Liner, DeepAI)
      koah: [
        '[data-koah-ad]',
        '[data-ad-provider="koah"]',
        '.koah-ad-container',
        '.koah-sponsored',
        // Root of every Koah web SDK format (seen in real renders)
        '[data-koah="root"]'
      ],

      // Imprezia-powered apps. Publishers usually bundle the SDK (no
      // window global) and route it through a same-origin proxy, so the
      // rendered card is the only reliable hook.
      imprezia: [
        '[data-imprezia-viewability-gate]',
        '.imprezia-card',
        '.imprezia-card-banner-html',
        '.imprezia-cta-container',
        'a.imprezia-cta-link',
        'a.imprezia-cta-button',
        '.imprezia-cta-sponsored'
      ],

      // Kontext, Gravity, EarnLayer and Lulu markup, taken from their
      // published npm SDKs (@kontextso/sdk-js, @gravity-ai/react + embed,
      // @earnlayer/chat-ads, lulu-ads).
      kontext: [
        '.kontextso-ad-container',
        'iframe.kontextso-ad-iframe',
        'iframe.kontextso-modal-iframe',
        // @kontextso/sdk-react emits no classes; match its fixed title+testid pair
        'iframe[data-testid="ad-iframe"][title="ad-iframe"]',
        'iframe[data-testid="modal-ad-iframe"][title="modal-ad-iframe"]',
        'div:has(> iframe[data-testid="ad-iframe"][title="ad-iframe"])',
        'div[data-testid^="inline-ad-"]:has(> .kontextso-ad-container)'
      ],

      gravity: [
        '[data-gravity-ad]',
        '[data-gravity-frame]',
        '[data-gravity-leadform-overlay]',
        // @gravity-ai/embed's GravityAd.mount() marks the publisher's slot with
        // state+variant only; React's contextual/suggestion/tooltip wrap the ad
        // in a theme root with lead-in copy
        '[data-gravity-state="loaded"][data-gravity-variant]',
        'a[data-gravity-ad-link]',
        '[data-gravity-theme-root]:has(> a[data-gravity-ad])',
        'section[data-gravity-leadform-card]'
      ],

      earnlayer: [
        '.earnlayer-ad',
        '.earnlayer-mcp-ads',
        'a.earnlayer-mcp-ad-link',
        // @earnlayer/ai-ads-sdk
        'div.managed-ad-component[class*="ad-type-"]'
      ],

      // Thrad JS SDK wrapper (sdk.thrad.ai/sdk.js)
      thrad: [
        'div.adsdk-container[data-thrad-format]'
      ],

      // ZeroClick offer links inside the AI's answer. Hidden, not unwrapped:
      // chat UIs usually render these anchors with React.
      zeroclick: [
        'a[href*="mcp.zeroclick.ai/api/v1/offers/"]',
        'a[href*="mcp.zeroclick.ai/offers/"]',
        'a[href*="zeroclick.dev/api/v2/clicks"]',
        'a[href^="https://zero.click/"]'
      ],

      lulu: [
        'a[href*="ads.getlulu.dev/c/"]',
        // MCP-app widget documents (the CTA is a button[data-url], not a link)
        'body:has(> #lulu-ads-opts) > #root',
        // Sponsor strip inside tool-result frames
        '#card.lw-card > .lw-strip',
        '#card.lw-card > .lw-strip-flip',
        // README / page sponsor badges
        'a[href*="getlulu.dev/api/mcps/sponsor-click/"]',
        // Text sponsor card / suffix printed into the answer: the block that
        // carries the click link is the ad
        'pre:has(a[href*="ads.getlulu.dev/c/"])',
        'p:has(> a[href*="ads.getlulu.dev/c/"])'
      ],

      // Generic patterns - ONLY very specific ad indicators
      generic: [
        '[data-ad-provider]',
        '[data-sponsored="true"]',
        '[data-promoted="true"]',
        '[aria-label="Sponsored"]',
        '[aria-label="Advertisement"]'
      ]
    },

    // Sponsored links inside the AI's answer text. These are unwrapped to
    // plain text (not hidden) so the sentence around them still reads.
    inlineAdLinks: [
      'a.imprezia-link',
      // ChatAds widget: affiliate links in the bot's answer (its own-site
      // links carry rel="noopener" only)
      'a.chataside-inline-link[rel~="sponsored"]'
    ],

    // =========================================================================
    // COMMERCIAL INTENT SIGNALS (for scoring, not blocking)
    // =========================================================================

    commercialIntent: {
      // Call-to-action phrases
      cta: [
        /\bbook\s+now\b/i,
        /\bsign\s+up\b/i,
        /\bget\s+started\b/i,
        /\blearn\s+more\b/i,
        /\bshop\s+now\b/i,
        /\bbuy\s+now\b/i,
        /\bclick\s+here\b/i,
        /\bvisit\s+(?:our\s+)?(?:site|website)\b/i,
        /\buse\s+code\b/i,
        /\bpromo\s+code\b/i
      ],

      // Urgency language
      urgency: [
        /\blimited\s+time\b/i,
        /\bexclusive\s+(?:offer|deal)\b/i,
        /\btoday\s+only\b/i,
        /\bwhile\s+supplies\s+last\b/i,
        /\bdont\s+miss\b/i,
        /\bhurry\b/i,
        /\bact\s+now\b/i
      ],

      // Discount language
      discount: [
        /\b\d+%\s+off\b/i,
        /\bsave\s+\$?\d+/i,
        /\bdiscount\b/i,
        /\bcoupon\b/i,
        /\bpromo\b/i,
        /\bfree\s+shipping\b/i,
        /\bspecial\s+offer\b/i
      ]
    },

    // =========================================================================
    // HELPER FUNCTIONS
    // =========================================================================

    /**
     * Check if a URL contains affiliate tracking parameters
     */
    hasAffiliateParams: function(url) {
      try {
        const urlObj = new URL(url);
        return this.affiliateParams.some(param => urlObj.searchParams.has(param));
      } catch {
        return false;
      }
    },

    /**
     * Check if a URL is from a known affiliate domain
     */
    isAffiliateDomain: function(url) {
      try {
        const hostname = new URL(url).hostname.toLowerCase();
        return this.affiliateDomains.some(domain => hostname.includes(domain));
      } catch {
        return false;
      }
    },

    /**
     * Check if a URL matches any AI ad SDK domain
     */
    isAdSDKDomain: function(url) {
      try {
        const hostname = new URL(url).hostname.toLowerCase();
        return this.getAllSDKDomains().some(domain => hostname.includes(domain));
      } catch {
        return false;
      }
    },

    /**
     * Check if text contains ad labels
     */
    containsAdLabel: function(text) {
      const lowerText = text.toLowerCase().trim();

      // Check exact matches
      if (this.adLabels.exact.some(label => lowerText.includes(label))) {
        return true;
      }

      // Check regex patterns
      return this.adLabels.patterns.some(pattern => pattern.test(text));
    },

    /**
     * Calculate commercial intent score (0-100)
     */
    getCommercialIntentScore: function(text) {
      let score = 0;

      // CTA phrases (+15 each, max 45)
      const ctaMatches = this.commercialIntent.cta.filter(p => p.test(text)).length;
      score += Math.min(ctaMatches * 15, 45);

      // Urgency language (+20 each, max 40)
      const urgencyMatches = this.commercialIntent.urgency.filter(p => p.test(text)).length;
      score += Math.min(urgencyMatches * 20, 40);

      // Discount language (+10 each, max 30)
      const discountMatches = this.commercialIntent.discount.filter(p => p.test(text)).length;
      score += Math.min(discountMatches * 10, 30);

      return Math.min(score, 100);
    },

    /**
     * Get all ad selectors for current platform
     */
    getSelectorsForPlatform: function() {
      const hostname = window.location.hostname.toLowerCase();
      // Generic selectors go last: they match small inner labels, and removing
      // those first would stop container rules like `section:has(> [aria-label
      // ="Sponsored"])` from matching, leaving an empty ad shell behind.
      let selectors = [];

      if (hostname.includes('x.com') || hostname.includes('twitter.com')) {
        selectors = selectors.concat(this.platformSelectors.grok);
      } else if (hostname.includes('perplexity')) {
        selectors = selectors.concat(this.platformSelectors.perplexity);
      } else if (hostname.includes('chatgpt') || hostname.includes('openai')) {
        selectors = selectors.concat(this.platformSelectors.chatgpt);
      } else if (hostname === 'copilot.microsoft.com') {
        selectors = selectors.concat(this.platformSelectors.copilot);
      } else if (hostname === 'you.com' || hostname.endsWith('.you.com')) {
        selectors = selectors.concat(this.platformSelectors.youcom);
      } else if (hostname === 'character.ai' || hostname.endsWith('.character.ai')) {
        selectors = selectors.concat(this.platformSelectors.characterai);
      }

      // Always include SDK-specific selectors
      selectors = selectors.concat(this.platformSelectors.koah);
      selectors = selectors.concat(this.platformSelectors.imprezia);
      selectors = selectors.concat(this.platformSelectors.kontext);
      selectors = selectors.concat(this.platformSelectors.gravity);
      selectors = selectors.concat(this.platformSelectors.earnlayer);
      selectors = selectors.concat(this.platformSelectors.lulu);
      selectors = selectors.concat(this.platformSelectors.thrad);
      selectors = selectors.concat(this.platformSelectors.zeroclick);
      selectors = selectors.concat(this.platformSelectors.generic);

      return [...new Set(selectors)]; // Remove duplicates
    },

    /**
     * Strip affiliate parameters from URL
     */
    cleanUrl: function(url) {
      try {
        const urlObj = new URL(url);
        this.affiliateParams.forEach(param => {
          urlObj.searchParams.delete(param);
        });
        return urlObj.toString();
      } catch {
        return url;
      }
    },

    /**
     * Merge an auto-updated pattern snapshot fetched by the background
     * service worker (Phase 4.4). Only flat data fields are merged —
     * regex-driven detection (scriptPatterns, adLabels.patterns,
     * commercialIntent.*) stays bundled to avoid having to round-trip
     * regex through JSON.
     *
     * Semantics: bundled values are a floor. We take the union of bundled
     * + cached, so a compromised remote can ADD spurious selectors (which
     * would only cause self-DoS via over-removal) but cannot REMOVE
     * protections shipped with the extension.
     */
    mergeCachedPatterns: function(cached) {
      if (!cached || typeof cached !== 'object') return false;
      if (typeof cached.version !== 'string') return false;
      // Bundled is the floor; only apply newer.
      if (cached.version <= BUNDLED_VERSION) return false;

      const unionStrings = (a, b) => {
        const arr = Array.isArray(a) ? a.slice() : [];
        if (Array.isArray(b)) {
          for (const v of b) if (typeof v === 'string' && !arr.includes(v)) arr.push(v);
        }
        return arr;
      };

      if (cached.adSDKs && typeof cached.adSDKs === 'object') {
        for (const [name, sdk] of Object.entries(cached.adSDKs)) {
          if (!sdk || typeof sdk !== 'object') continue;
          const target = this.adSDKs[name] || (this.adSDKs[name] = { functions: [], methods: [], scriptPatterns: [], domainPatterns: [] });
          target.functions = unionStrings(target.functions, sdk.functions);
          target.methods = unionStrings(target.methods, sdk.methods);
          target.domainPatterns = unionStrings(target.domainPatterns, sdk.domainPatterns);
        }
      }

      this.affiliateParams = unionStrings(this.affiliateParams, cached.affiliateParams);
      this.affiliateDomains = unionStrings(this.affiliateDomains, cached.affiliateDomains);

      if (cached.platformSelectors && typeof cached.platformSelectors === 'object') {
        for (const [name, list] of Object.entries(cached.platformSelectors)) {
          this.platformSelectors[name] = unionStrings(this.platformSelectors[name], list);
        }
      }

      this.version = cached.version;
      return true;
    }
  };

})();
