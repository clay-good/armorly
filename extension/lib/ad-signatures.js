/**
 * Armorly - deterministic ad signatures.
 *
 * Pure, side-effect-free classifiers shared by:
 *   - content/payload-shield.js (MAIN world): strips ad objects out of
 *     JSON / SSE / NDJSON / WebSocket payloads before the page renders
 *     them, and blocks the client-side "proof of delivery" requests
 *     (impression pixels, beacons, win/billing notices).
 *   - content/ai-ad-blocker.js (ISOLATED world): finds ad cards in the
 *     rendered DOM by their mandatory disclosure label.
 *   - tests/signatures.test.js (Node): unit tests.
 *
 * Everything here is a fixed rule over structure: key names, OpenRTB
 * field shapes, URL parameters, and exact disclosure-label strings. No
 * scoring, no models, no remote code. The same input always produces the
 * same verdict.
 */

(function (root) {
  'use strict';

  // ---------------------------------------------------------------------------
  // Payload (JSON) signatures
  // ---------------------------------------------------------------------------

  // OpenRTB 2.x bid fields (seatbid[].bid[]). Two or more of these together,
  // with a creative or a notice URL, is a bid object.
  const RTB_BID_KEYS = ['adm', 'nurl', 'burl', 'lurl', 'crid', 'adomain', 'impid', 'adid', 'cid', 'dealid'];
  const RTB_CREATIVE_KEYS = ['adm', 'nurl', 'burl'];

  // OpenRTB Native / common ad-server tracker arrays. Their presence alone
  // marks the enclosing object as an ad.
  const TRACKER_ARRAY_KEYS = new Set([
    'imptrackers', 'clicktrackers', 'eventtrackers', 'jstracker',
    'impressiontrackers', 'impression_trackers', 'click_trackers',
    'viewability_trackers', 'viewabilitytrackers',
    'impressionurls', 'impression_urls', 'viewtrackers', 'view_trackers'
  ]);

  // Keys whose value is a tracking URL (impression, view, click, win, bill...).
  const TRACKING_URL_KEY = /^(imp|impression|view|viewable|viewability|click|tracking|track|beacon|pixel|win|bill|billing|notice)[_-]?(url|urls|uri|link|tracker|trackers|pixel|pixels|beacon|beacons|endpoint)$/i;
  // The subset that proves delivery/viewing (not just a click-through).
  const PROOF_URL_KEY = /^(imp|impression|view|viewable|viewability|beacon|pixel|win|bill|billing|notice)[_-]?(url|urls|uri|link|tracker|trackers|pixel|pixels|beacon|beacons|endpoint)$/i;

  // Identity of an ad, a bid, or a placement.
  const AD_ID_KEY = /^(ad|creative|campaign|bid|impression|imp|placement|line[_-]?item|advertiser|ad[_-]?unit|ad[_-]?group|sponsor|auction)[_-]?id$/i;

  // Boolean flags that declare "this is an ad". Value must be literally true.
  const AD_FLAG_KEY = /^(is[_-]?)?(sponsored|ad|advert|advertisement|promoted|paid[_-]?placement)$/i;

  // type/kind fields whose value declares an ad.
  const AD_TYPE_KEY = /^(type|kind|role|category|content[_-]?type|block[_-]?type|item[_-]?type|card[_-]?type|variant)$/i;
  const AD_TYPE_VALUE = /^(ad|ads|advert|advertisement|sponsored|sponsorship|promoted|native[_-]?ad|ad[_-]?(card|unit|block|slot|placement|message|result)|sponsored[_-]?(content|message|result|card|block|answer|link|links|listing|product|products|suggestion|suggestions|recommendation|placement)|promoted[_-]?(content|result|listing|link|product|suggestion))$/i;

  // A parent key that names its value as an ad container.
  const AD_CONTAINER_KEY = /^(ad|ads|advert|adverts|advertisement|advertisements|sponsored|sponsorship|sponsored[_-]?\w+|promoted[_-]?\w+|native[_-]?ads?|ad[_-]?(slot|slots|unit|units|block|blocks|card|cards|placement|placements|content|response|payload|creative|creatives))$/i;

  // Keys that carry the destination of a clickable item.
  const LINK_KEY = /^(url|link|href|uri|landing[_-]?(page|url)?|destination([_-]?url)?|cta[_-]?(url|link)|click[_-]?url|target[_-]?url)$/i;

  // Keys whose value is the ad identity we remember so that later requests
  // mentioning it (a client-side impression report) can be blocked. Only
  // ad-specific ids: a plain `id` may be a chat message id the app sends
  // back later, and placement/campaign ids are shared across many ads.
  const ID_KEYS_TO_LEARN = /^(crid|adid|bidid|bid[_-]?id|ad[_-]?id|creative[_-]?id|impression[_-]?id|auction[_-]?id)$/i;

  // Unsubstituted OpenRTB auction macros.
  const RTB_MACRO = /(\$\{|%24%7B)AUCTION_(PRICE|ID|BID_ID|IMP_ID|SEAT_ID|AD_ID|LOSS|CURRENCY|MBR|MIN_TO_WIN)(\}|%7D)/i;

  // Event names in analytics payloads / query strings.
  const EXPLICIT_AD_EVENT = /^(ad|ads|sponsored|promoted)[_\-. ]?(impression|imp|view|viewable|viewability|click|render|rendered|served|delivered|shown|display|displayed|visible|start|complete|engagement)$/i;
  const DELIVERY_EVENT = /^(impression|imp|view|viewable|viewability|render|rendered|served|delivered|shown|display|displayed|visible|click|win|billable)$/i;
  const EVENT_KEY = /^(event|ev|evt|e|type|event[_-]?type|event[_-]?name|action|name|kind)$/i;

  const MAX_DEPTH = 24;
  const MAX_NODES = 100000;

  function isPlainObject(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
  }

  function lowerKeys(obj) {
    const out = new Set();
    for (const k of Object.keys(obj)) out.add(k.toLowerCase());
    return out;
  }

  function isNonEmptyValue(v) {
    if (v == null) return false;
    if (typeof v === 'string') return v.length > 0;
    if (Array.isArray(v)) return v.length > 0;
    return true;
  }

  /**
   * True when `obj` is, by structure alone, an advertisement payload:
   * an OpenRTB bid response or bid, a native-ad object with tracker
   * arrays, or an object that declares itself an ad and carries ad
   * plumbing (trackers, ad ids, or a destination link).
   */
  function isAdObject(obj) {
    if (!isPlainObject(obj)) return false;
    const keys = Object.keys(obj);
    if (keys.length === 0) return false;
    const lk = lowerKeys(obj);

    // 1. OpenRTB bid response.
    if (Array.isArray(obj.seatbid)) return true;

    // 2. OpenRTB bid.
    let rtb = 0;
    for (const k of RTB_BID_KEYS) if (lk.has(k)) rtb++;
    const hasCreative = RTB_CREATIVE_KEYS.some(k => lk.has(k));
    if (rtb >= 2 && hasCreative) return true;

    // 3. Native / ad-server tracker arrays.
    for (const k of keys) {
      if (TRACKER_ARRAY_KEYS.has(k.toLowerCase()) && isNonEmptyValue(obj[k])) return true;
    }

    let flagged = false;
    let hasTracking = false;
    let hasProof = false;
    let hasAdId = false;
    let hasLink = false;
    for (const k of keys) {
      const v = obj[k];
      if (AD_FLAG_KEY.test(k) && v === true) flagged = true;
      if (AD_TYPE_KEY.test(k) && typeof v === 'string' && AD_TYPE_VALUE.test(v.trim())) flagged = true;
      if (TRACKING_URL_KEY.test(k) && isNonEmptyValue(v)) hasTracking = true;
      if (PROOF_URL_KEY.test(k) && isNonEmptyValue(v)) hasProof = true;
      if (AD_ID_KEY.test(k) && isNonEmptyValue(v)) hasAdId = true;
      if (LINK_KEY.test(k) && typeof v === 'string' && v.length > 0) hasLink = true;
    }

    // 4. Declares itself an ad AND has ad plumbing.
    if (flagged && (hasTracking || hasAdId || hasLink || rtb > 0)) return true;

    // 5. Proof-of-delivery URL plus an ad identity, even without a flag.
    if (hasProof && hasAdId) return true;

    return false;
  }

  /** True when `obj` sits under a key that names it an ad container. */
  function isAdContainerEntry(key, value) {
    if (typeof key !== 'string' || !AD_CONTAINER_KEY.test(key)) return false;
    if (isPlainObject(value)) return Object.keys(value).length > 0;
    if (Array.isArray(value)) return value.some(v => isPlainObject(v) && Object.keys(v).length > 0);
    return false;
  }

  function isUrlString(v) {
    return typeof v === 'string' && /^(https?:)?\/\//i.test(v.trim());
  }

  /**
   * Walk an ad object and remember its tracker URLs and identities.
   * Learned values let the shield block the client-side impression
   * report that a server-side ad still has to send.
   */
  function harvest(obj, collector, depth) {
    if (!collector || depth > MAX_DEPTH || obj == null) return;
    if (Array.isArray(obj)) {
      for (const v of obj) harvest(v, collector, depth + 1);
      return;
    }
    if (!isPlainObject(obj)) return;
    for (const [k, v] of Object.entries(obj)) {
      const lk = k.toLowerCase();
      const trackerKey =
        TRACKER_ARRAY_KEYS.has(lk) || TRACKING_URL_KEY.test(k) ||
        lk === 'nurl' || lk === 'burl' || lk === 'lurl' || lk === 'url' && collector._inTracker;
      if (trackerKey) {
        const urls = [];
        collectStrings(v, urls, depth + 1);
        for (const u of urls) if (isUrlString(u)) collector.urls.add(u.trim());
        // eventtrackers: [{event, method, url}] — descend with url-as-tracker.
        if (Array.isArray(v) || isPlainObject(v)) {
          const prev = collector._inTracker;
          collector._inTracker = true;
          harvest(v, collector, depth + 1);
          collector._inTracker = prev;
        }
        continue;
      }
      if (ID_KEYS_TO_LEARN.test(k) && (typeof v === 'string' || typeof v === 'number')) {
        const s = String(v);
        // Short ids collide with unrelated strings; only remember distinctive ones.
        if (s.length >= 8) collector.ids.add(s);
      }
      if (typeof v === 'object') harvest(v, collector, depth + 1);
    }
  }

  function collectStrings(v, out, depth) {
    if (depth > MAX_DEPTH || out.length > 500) return;
    if (typeof v === 'string') out.push(v);
    else if (Array.isArray(v)) for (const x of v) collectStrings(x, out, depth + 1);
    else if (isPlainObject(v)) for (const x of Object.values(v)) collectStrings(x, out, depth + 1);
  }

  function newCollector() {
    return { urls: new Set(), ids: new Set(), removed: 0 };
  }

  /**
   * Remove every ad object from a parsed JSON value.
   *
   * Mutates `value` in place (callers pass a freshly parsed copy) and
   * returns { value, changed, removedAll }. `removedAll` means the root
   * itself was an ad — the caller decides what to substitute.
   */
  function pruneAds(value, collector) {
    const c = collector || newCollector();
    const state = { nodes: 0, changed: false };

    if (isAdObject(value)) {
      harvest(value, c, 0);
      c.removed++;
      return { value: null, changed: true, removedAll: true, collector: c };
    }

    walk(value, 0);
    return { value, changed: state.changed, removedAll: false, collector: c };

    function walk(node, depth) {
      if (depth > MAX_DEPTH || ++state.nodes > MAX_NODES || node === null || typeof node !== 'object') return;
      if (Array.isArray(node)) {
        for (let i = node.length - 1; i >= 0; i--) {
          const v = node[i];
          if (isAdObject(v)) {
            harvest(v, c, 0);
            node.splice(i, 1);
            c.removed++;
            state.changed = true;
          } else {
            walk(v, depth + 1);
          }
        }
        return;
      }
      for (const k of Object.keys(node)) {
        const v = node[k];
        if (isAdObject(v) || isAdContainerEntry(k, v)) {
          harvest(v, c, 0);
          delete node[k];
          c.removed++;
          state.changed = true;
        } else {
          walk(v, depth + 1);
        }
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Outgoing-request signatures (client-side proof of delivery)
  // ---------------------------------------------------------------------------

  function hasRtbMacro(url) {
    return typeof url === 'string' && RTB_MACRO.test(url);
  }

  /** Query string reports an ad impression/click. */
  function isAdEventQuery(params) {
    if (!params || typeof params.forEach !== 'function') return false;
    let explicit = false;
    let delivery = false;
    let adId = false;
    params.forEach((value, key) => {
      if (EVENT_KEY.test(key)) {
        const v = String(value).trim();
        if (EXPLICIT_AD_EVENT.test(v)) explicit = true;
        else if (DELIVERY_EVENT.test(v)) delivery = true;
      }
      if (AD_ID_KEY.test(key) && value) adId = true;
    });
    return explicit || (delivery && adId);
  }

  /** JSON body reports an ad impression/click. */
  function isAdEventPayload(obj, depth) {
    depth = depth || 0;
    if (depth > 4 || obj == null || typeof obj !== 'object') return false;
    if (Array.isArray(obj)) return obj.some(v => isAdEventPayload(v, depth + 1));
    let explicit = false;
    let delivery = false;
    let adId = false;
    for (const [k, v] of Object.entries(obj)) {
      if (EVENT_KEY.test(k) && typeof v === 'string') {
        const s = v.trim();
        if (EXPLICIT_AD_EVENT.test(s)) explicit = true;
        else if (DELIVERY_EVENT.test(s)) delivery = true;
      }
      if (AD_ID_KEY.test(k) && isNonEmptyValue(v)) adId = true;
    }
    if (explicit || (delivery && adId)) return true;
    if (isAdObject(obj)) return true;
    // Batched analytics: { events: [...] } / { data: {...} }
    for (const v of Object.values(obj)) {
      if (v && typeof v === 'object' && isAdEventPayload(v, depth + 1)) return true;
    }
    return false;
  }

  // ---------------------------------------------------------------------------
  // Link signatures
  // ---------------------------------------------------------------------------

  // utm_medium values that mean "this click was bought".
  const PAID_MEDIUM = /^(cpc|ppc|cpm|cpa|cpv|paid|paid[_-]?(search|social|media|ads?)|paidsearch|paidsocial|display|sponsored|native|ad|ads|advert|advertising|banner|retargeting|programmatic)$/i;
  // Ad-click identifiers appended by ad platforms.
  const AD_CLICK_ID_PARAMS = ['gclid', 'gbraid', 'wbraid', 'dclid', 'gclsrc', 'msclkid', 'ttclid', 'twclid', 'li_fat_id', 'yclid', 'irclickid', 'epik', 'rdt_cid', 'scclid'];
  const REDIRECT_PATH = /\/(aclk|pagead\/aclk|click|clk|clicks|clickthrough|track|tracking|redirect|redir|r|out|go)\/?$/i;
  const REDIRECT_PARAM = ['adurl', 'dest', 'destination', 'redirect', 'redirect_url', 'redirect_uri', 'url', 'u', 'to', 'target', 'landing', 'landing_url', 'lp', 'dl'];

  /** The link was paid for (ad click), by its URL alone. */
  function isPaidClickUrl(url) {
    let u;
    try { u = new URL(url); } catch (_) { return false; }
    const medium = u.searchParams.get('utm_medium');
    if (medium && PAID_MEDIUM.test(medium.trim())) return true;
    return AD_CLICK_ID_PARAMS.some(p => u.searchParams.has(p));
  }

  /**
   * If `url` is an ad click-redirect (tracker host + destination param),
   * return the destination so the click goes straight there and no click
   * is recorded. Otherwise null.
   */
  function unwrapClickRedirect(url, isTrackerHost) {
    let u;
    try { u = new URL(url); } catch (_) { return null; }
    const trackerHost = typeof isTrackerHost === 'function' && isTrackerHost(u.hostname);
    if (!trackerHost && !REDIRECT_PATH.test(u.pathname)) return null;
    for (const p of REDIRECT_PARAM) {
      const dest = u.searchParams.get(p);
      if (!dest) continue;
      let d;
      try { d = new URL(dest); } catch (_) { continue; }
      if ((d.protocol === 'https:' || d.protocol === 'http:') && d.hostname !== u.hostname) return d.toString();
    }
    return null;
  }

  // ---------------------------------------------------------------------------
  // Disclosure labels (DOM)
  // ---------------------------------------------------------------------------

  // Characters used to dodge string matching: zero-width, soft hyphen, BOM.
  const INVISIBLE = /[­͏؜ᅟᅠ឴឵᠎​-‏‪-‮⁠-⁤⁪-⁯﻿]/g;
  // Lookalike characters (Cyrillic/Greek/fullwidth/digits) folded to ASCII.
  const CONFUSABLES = {
    'а': 'a', 'А': 'a', 'е': 'e', 'Е': 'e', 'о': 'o', 'О': 'o', 'р': 'p', 'Р': 'p',
    'с': 'c', 'С': 'c', 'ѕ': 's', 'Ѕ': 's', 'і': 'i', 'І': 'i', 'ԁ': 'd', 'ո': 'n',
    'ο': 'o', 'Ο': 'o', 'α': 'a', 'Α': 'a', 'ε': 'e', 'Ε': 'e', 'ρ': 'p', 'Ρ': 'p',
    'ν': 'v', 'τ': 't', 'Τ': 't', 'Μ': 'm', 'Ν': 'n', 'Ι': 'i', 'ι': 'i',
    '0': 'o', '1': 'l', '3': 'e', '5': 's', '$': 's', '@': 'a'
  };

  function normalizeText(text) {
    if (typeof text !== 'string') return '';
    const s = text.normalize('NFKC').replace(INVISIBLE, '');
    let out = '';
    for (const ch of s) out += Object.prototype.hasOwnProperty.call(CONFUSABLES, ch) ? CONFUSABLES[ch] : ch;
    return out.toLowerCase().replace(/\s+/g, ' ').trim();
  }

  function normalizeLabel(text) {
    return normalizeText(text)
      .replace(/^[\s:·•|\-–—()[\]]+|[\s:·•|\-–—()[\]]+$/g, '')
      .trim();
  }

  // A disclosure label is a SHORT element whose whole text is the label.
  // Prose that merely mentions sponsorship ("this study was sponsored by
  // NIH") never matches because the regex is anchored on both ends.
  // Bare "paid", "sponsor" and "advertising" are deliberately absent: they
  // are also invoice statuses, sponsor buttons and footer links.
  const DISCLOSURE = /^(sponsored|ad|ads|advert|advertisement|advertisements|promoted|paid (ad|partnership|promotion|placement|content|post|link|listing|recommendation)|partner content|sponsored (ad|result|results|content|listing|listings|link|links|product|products|answer|suggestion|suggestions|recommendation|recommendations|message|post|placement|offer|by .{1,40})|promoted (content|result|results|post|listing|link|links|product|products|suggestion|by .{1,40})|ad (by|from|·) .{1,40}|ads by .{1,40}|from (our|a) sponsors?|our sponsors?|brought to you by .{1,40})$/;

  // "Sponsored: Try Acme…", "[Ad] Acme…" — a label glued to the start of
  // a paragraph. The colon/bracket is required so "Ad hoc" or "Promoted to
  // manager" never match.
  const DISCLOSURE_PREFIX = /^(?:(sponsored|ad|advertisement|promoted|paid partnership|paid promotion|sponsored content|sponsored result|sponsored suggestion)\s*[:|·—–]\s*\S|[\[(](sponsored|ad|advertisement|promoted)[\])]\s*\S)/;

  function isDisclosurePrefix(text) {
    if (typeof text !== 'string') return false;
    return DISCLOSURE_PREFIX.test(normalizeText(text.slice(0, 120)));
  }

  function isDisclosureLabel(text) {
    if (typeof text !== 'string' || text.length > 80) return false;
    const n = normalizeLabel(text);
    return n.length > 0 && n.length <= 60 && DISCLOSURE.test(n);
  }

  const api = Object.freeze({
    isAdObject,
    isAdContainerEntry,
    pruneAds,
    newCollector,
    hasRtbMacro,
    isAdEventQuery,
    isAdEventPayload,
    isPaidClickUrl,
    unwrapClickRedirect,
    normalizeLabel,
    isDisclosureLabel,
    isDisclosurePrefix,
    AD_CLICK_ID_PARAMS: Object.freeze(AD_CLICK_ID_PARAMS.slice())
  });

  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.ArmorlyAdSignatures = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
