/**
 * Armorly - AI Ad Patterns Library
 *
 * Detection patterns for AI-native advertising networks and SDKs.
 * Blocks ads from: Grok/X, Koah, Monetzly, Sponsored.so, Imprezia, and others.
 *
 * This file is designed to be easily updatable as ad networks evolve.
 */

(function() {
  'use strict';

  // Bumped when the bundled data changes; used to decide whether a cached
  // remote copy is newer. Keep in lockstep with the `version` field in the
  // sibling extension/lib/ad-patterns.json — the build script verifies they
  // match before packaging.
  const BUNDLED_VERSION = '2026-05-26';

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
          'sdk.koah.io'
        ]
      },

      // Monetzly - "Google Ads for AI conversations"
      monetzly: {
        functions: ['Monetzly', 'monetzly', 'MonetzlyAds'],
        methods: ['init', 'displayAd', 'monetize', 'showAd', 'trackImpression', 'trackClick'],
        scriptPatterns: [
          /monetzly\.com/i,
          /monetzly\.io/i,
          /monetzly-sdk/i,
          /monetzly\.js/i
        ],
        domainPatterns: [
          'monetzly.com',
          'monetzly.io',
          'api.monetzly.com',
          'sdk.monetzly.com'
        ]
      },

      // Sponsored.so - Native AI ad platform
      sponsoredso: {
        functions: ['Sponsored', 'sponsored', 'SponsoredAds', 'SponsoredSo'],
        methods: ['init', 'show', 'display', 'track', 'impression', 'click'],
        scriptPatterns: [
          /sponsored\.so/i,
          /sponsored-sdk/i,
          /sponsoredso/i
        ],
        domainPatterns: [
          'sponsored.so',
          'api.sponsored.so',
          'sdk.sponsored.so'
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
          'sdk.imprezia.ai'
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
        '.openai-ad'
      ],

      // Koah-powered apps (Luzia, Liner, DeepAI)
      koah: [
        '[data-koah-ad]',
        '[data-ad-provider="koah"]',
        '.koah-ad-container',
        '.koah-sponsored'
      ],

      // Monetzly-powered apps
      monetzly: [
        '[data-monetzly-ad]',
        '[data-ad-provider="monetzly"]',
        '.monetzly-ad',
        '.monetzly-sponsored'
      ],

      // Sponsored.so-powered apps
      sponsoredso: [
        '[data-sponsored-so]',
        '[data-ad-provider="sponsored.so"]',
        '.sponsored-so-ad'
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
      let selectors = [...this.platformSelectors.generic];

      if (hostname.includes('x.com') || hostname.includes('twitter.com')) {
        selectors = selectors.concat(this.platformSelectors.grok);
      } else if (hostname.includes('perplexity')) {
        selectors = selectors.concat(this.platformSelectors.perplexity);
      } else if (hostname.includes('chatgpt') || hostname.includes('openai')) {
        selectors = selectors.concat(this.platformSelectors.chatgpt);
      }

      // Always include SDK-specific selectors
      selectors = selectors.concat(this.platformSelectors.koah);
      selectors = selectors.concat(this.platformSelectors.monetzly);
      selectors = selectors.concat(this.platformSelectors.sponsoredso);

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
