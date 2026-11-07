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

  // OpenRTB 2.x bid fields (seatbid[].bid[]) and OpenRTB 3.0 (`purl`).
  // Two or more of these together, with a creative or a notice URL, is a bid.
  const RTB_BID_KEYS = ['adm', 'nurl', 'burl', 'lurl', 'purl', 'crid', 'adomain', 'impid', 'adid', 'cid', 'dealid'];
  const RTB_CREATIVE_KEYS = ['adm', 'nurl', 'burl', 'purl'];

  // OpenRTB Native / common ad-server tracker arrays. Their presence alone
  // marks the enclosing object as an ad.
  const TRACKER_ARRAY_KEYS = new Set([
    'imptrackers', 'clicktrackers', 'eventtrackers', 'jstracker',
    'impressiontrackers', 'impression_trackers', 'click_trackers',
    'viewability_trackers', 'viewabilitytrackers',
    'impressionurls', 'impression_urls', 'viewtrackers', 'view_trackers',
    'trackingurls', 'tracking_urls', 'impressiontrackingurls', 'impression_tracking_urls'
  ]);
  // { trackers: { impression: [...], click: [...] } } style tracker maps.
  const TRACKER_MAP_KEY = /^(trackers|beacons|pixels|tracking|tracking[_-]?events)$/i;

  // Keys whose value is a tracking URL (impression, view, click, win, bill...).
  const TRACKING_URL_KEY = /^(imp|impression|view|viewable|viewability|click|tracking|tracker|track|beacon|pixel|win|bill|billing|notice)[_-]?(tracking[_-]?)?(url|urls|uri|link|tracker|trackers|pixel|pixels|beacon|beacons|endpoint)s?$/i;
  // The subset that proves delivery/viewing (not just a click-through).
  const PROOF_URL_KEY = /^(imp|impression|view|viewable|viewability|beacon|pixel|win|bill|billing|notice)[_-]?(tracking[_-]?)?(url|urls|uri|link|tracker|trackers|pixel|pixels|beacon|beacons|endpoint)s?$/i;

  // Identity of an ad. STRONG ids exist only for ads; WEAK ones (campaign,
  // placement, impression, bid...) also appear in email, recommender, CI and
  // auction telemetry, so they only count next to an explicit ad flag.
  const STRONG_AD_ID_KEY = /^(ad|creative|line[_-]?item|advertiser|ad[_-]?unit|ad[_-]?group|ads?[_-]?request)[_-]?id$/i;
  const AD_ID_KEY = /^(ad|creative|campaign|bid|impression|imp|placement|line[_-]?item|advertiser|ad[_-]?unit|ad[_-]?group|sponsor|auction|ads?[_-]?request|bid[_-]?request)[_-]?id$/i;

  // Boolean flags that declare "this is an ad".
  const AD_FLAG_KEY = /^(is[_-]?)?(sponsored|ad|advert|advertisement|promoted|paid[_-]?placement)$/i;

  // type/kind fields whose value declares an ad. (`variant` and `category`
  // are left out: UI libraries use variant:"ad" for styling.)
  const AD_TYPE_KEY = /^(type|kind|role|content[_-]?type|block[_-]?type|item[_-]?type|card[_-]?type)$/i;
  const AD_TYPE_VALUE = /^((?:[a-z0-9]+[_-])*ad[_-](?:unit|card|carousel)|ad|ads|advert|advertisement|sponsored|sponsorship|promoted|native[\s_-]?ad|ad[\s_-]?(card|unit|block|slot|placement|message|result)|sponsored[\s_-]?(content|message|result|card|block|answer|link|links|listing|product|products|suggestion|suggestions|recommendation|placement)|promoted[\s_-]?(content|result|listing|link|product|suggestion))$/i;
  // A key that itself names an ad format (adType, ad_format).
  const AD_FORMAT_KEY = /^ad[_-]?(type|format|kind)$/i;
  // Fields that hold a disclosure label ("Sponsored", "Ad").
  const LABEL_KEY = /^(label|badge|disclosure|tag|preamble)$/i;
  // Keys that only ad payloads carry (ChatGPT ad unit, Gravity).
  const AD_ONLY_KEYS = new Set(['ads_spam_integrity_payload', 'ad_data_token', 'advertiser_brand', 'adtext', 'ad_text']);

  // A parent key that names its value as an ad container. The value still
  // has to carry ad plumbing (see hasAdPlumbing): a key name alone is not
  // enough ({ads:[{name, status}]} is an ad manager's campaign list).
  const AD_CONTAINER_KEY = /^(ad|ads|advert|adverts|advertisement|advertisements|sponsored|sponsorship|sponsored[_-]?\w+|promoted[_-]?\w+|native[_-]?ads?|ad[_-]?(slot|slots|unit|units|block|blocks|card|cards|placement|placements|content|response|payload|creative|creatives)|(hyperlink|display|text|banner|video|native|inline|search|shopping)[_-]ads|vast|vast[_-]?xml|vast[_-]?tag([_-]?url)?|vmap|[a-z0-9.-]+\/(sponsored|ads?))$/i;
  // Envelope keys whose whole event is dropped when they carry an ad, so
  // SDKs never see a half-empty event ({type:'content_block_start'} with no
  // content_block crashes the Anthropic SDK).
  const ENVELOPE_KEYS = new Set(['content_block', 'item', 'part', 'message', 'delta', 'data', 'payload', 'annotation']);

  // Destination keys that only ads use (a call-to-action / click-through).
  const AD_LINK_KEY = /^(cta[_-]?(url|link)|click[_-]?(url|through|through[_-]?url)|landing[_-]?(page|url)|destination[_-]?url)$/i;
  // Keys that carry the destination of a clickable item.
  const LINK_KEY = /^(url|link|href|uri|landing[_-]?(page|url)?|destination([_-]?url)?|cta[_-]?(url|link)|click[_-]?url|target[_-]?url)$/i;

  // Keys whose value is the ad identity we remember so that later requests
  // mentioning it (a client-side impression report) can be blocked. Only
  // ad-specific ids: a plain `id` may be a chat message id the app sends
  // back later, and placement/campaign ids are shared across many ads.
  const ID_KEYS_TO_LEARN = /^(crid|adid|bidid|bid[_-]?id|ad[_-]?id|creative[_-]?id|impression[_-]?id|auction[_-]?id|ads?[_-]?request[_-]?id)$/i;
  // A learnable id looks like an id: 8-128 id characters, with a digit.
  const LEARNABLE_ID = /^(?=.*\d)[A-Za-z0-9._:-]{8,128}$/;

  // Unsubstituted OpenRTB auction macros.
  const RTB_MACRO = /(\$\{|%24%7B)AUCTION_(PRICE|ID|BID_ID|IMP_ID|SEAT_ID|AD_ID|LOSS|CURRENCY|MBR|MIN_TO_WIN)(\}|%7D)/i;
  // A VAST/VMAP video ad document.
  const VAST_DOC = /^\s*(<\?xml[^>]*>\s*)?<(VAST|vmap:VMAP)\b/;

  // Event names in analytics payloads / query strings.
  const EXPLICIT_AD_EVENT = /^(video[_\-. ]?)?(ad|ads|sponsored|promoted)[_\-. ]?(impression|imp|view|viewed|viewable|viewability|click|clicked|filled|render|rendered|served|delivered|shown|display|displayed|visible|start|started|complete|completed|loaded|engagement)$/i;
  const DELIVERY_EVENT = /^(impression|imp|view|viewed|viewable|viewability|render|rendered|served|delivered|shown|display|displayed|visible|click|clicked|win|billable)$/i;
  const EVENT_KEY = /^(event|ev|evt|e|type|event[_-]?type|event[_-]?name|kind)$/i;

  const MAX_DEPTH = 256;
  const MAX_NODES = 200000;
  const MAX_EMBEDDED_JSON = 256 * 1024;

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

  function isTrue(v) {
    return v === true || v === 1 || v === 'true';
  }

  function isTrackerMap(v) {
    if (!isPlainObject(v)) return false;
    return Object.keys(v).some(k => DELIVERY_EVENT.test(k) || /^(impression|view|click)s?$/i.test(k));
  }

  /**
   * True when `obj` is, by structure alone, an advertisement payload:
   * an OpenRTB bid response or bid, a native-ad object with tracker
   * arrays, a VAST document, a known ad-network shape, or an object that
   * declares itself an ad and carries ad plumbing (trackers, ad ids, or a
   * destination link).
   */
  function isAdObject(obj) {
    if (!isPlainObject(obj)) return false;
    const keys = Object.keys(obj);
    if (keys.length === 0) return false;
    const lk = lowerKeys(obj);

    // 1. OpenRTB bid response (2.x, and 3.0's openrtb.response.seatbid).
    if (Array.isArray(obj.seatbid)) return true;

    // 2. OpenRTB bid.
    let rtb = 0;
    for (const k of RTB_BID_KEYS) if (lk.has(k)) rtb++;
    const hasCreative = RTB_CREATIVE_KEYS.some(k => lk.has(k));
    if (rtb >= 2 && hasCreative) return true;

    // 3. Native / ad-server tracker arrays, tracker maps, ad-only keys, VAST.
    for (const k of keys) {
      const v = obj[k];
      const kl = k.toLowerCase();
      if (TRACKER_ARRAY_KEYS.has(kl) && isNonEmptyValue(v)) return true;
      if (TRACKER_MAP_KEY.test(k) && isTrackerMap(v)) return true;
      if (AD_ONLY_KEYS.has(kl) && isNonEmptyValue(v)) return true;
      if (typeof v === 'string' && v.length > 20 && VAST_DOC.test(v)) return true;
      // Vercel AI SDK v5 data parts: {type:'data-ad', data:{...}}.
      if (kl === 'type' && typeof v === 'string' && /^data-/.test(v) && AD_TYPE_VALUE.test(v.slice(5))) return true;
    }

    let flagged = false;
    let labelFlagged = false;
    let hasTracking = false;
    let hasProof = false;
    let hasAdId = false;
    let hasStrongAdId = false;
    let hasLink = false;
    for (const k of keys) {
      const v = obj[k];
      if (AD_FLAG_KEY.test(k) && isTrue(v)) flagged = true;
      if (AD_TYPE_KEY.test(k) && typeof v === 'string' && AD_TYPE_VALUE.test(v.trim())) flagged = true;
      if (AD_FORMAT_KEY.test(k) && typeof v === 'string' && v) flagged = true;
      if (LABEL_KEY.test(k) && typeof v === 'string' && isDisclosureLabel(v)) labelFlagged = true;
      if (TRACKING_URL_KEY.test(k) && isNonEmptyValue(v)) hasTracking = true;
      if (PROOF_URL_KEY.test(k) && isNonEmptyValue(v)) hasProof = true;
      if (AD_ID_KEY.test(k) && isNonEmptyValue(v)) hasAdId = true;
      if (STRONG_AD_ID_KEY.test(k) && isNonEmptyValue(v)) hasStrongAdId = true;
      if (LINK_KEY.test(k) && typeof v === 'string' && v.length > 0) hasLink = true;
    }

    // 4. Declares itself an ad AND has ad plumbing.
    if (flagged && (hasTracking || hasAdId || hasLink || rtb > 0)) return true;
    // A "Sponsored" label field needs real plumbing (a menu item
    // {label:'Sponsored', url} is not an ad).
    if (labelFlagged && (hasTracking || hasAdId || rtb > 0)) return true;

    // 5. Proof-of-delivery URL plus an ad identity, even without a flag.
    if (hasProof && hasStrongAdId) return true;

    // 6. Known ad-network shapes.
    // Creative markup plus a click/tracking URL (Thrad, generic SSPs).
    for (const k of ['creative', 'creatives']) {
      const c = obj[k];
      if (isPlainObject(c) && (typeof c.html === 'string' || typeof c.markup === 'string') &&
          Object.keys(c).some(ck => TRACKING_URL_KEY.test(ck) && isNonEmptyValue(c[ck]))) return true;
    }
    // Named advertiser plus a tracking URL (Imprezia append).
    if ((lk.has('advertiser') || lk.has('advertiser_name') || lk.has('advertisername')) && hasTracking) return true;
    // Auction bid: bid id plus revenue (Kontext preload bids[]). `price`
    // alone is left out: auction sites send {bid_id, price}.
    if (['bidid', 'bid_id'].some(x => lk.has(x)) && ['revenue', 'cpm', 'ecpm'].some(x => typeof obj[x] === 'number')) return true;
    // Billed affiliate offers (ChatAds envelope).
    if (Array.isArray(obj.offers) && typeof obj.billed === 'boolean') return true;

    return false;
  }

  /**
   * Ad plumbing anywhere in the first two levels of `v`: trackers, ad ids,
   * creatives, RTB fields, an ad-only click-through key. A bare `url` is
   * not enough ({ads:[{id, name, status, url}]} is a campaign list).
   */
  function hasAdPlumbing(v, depth) {
    depth = depth || 0;
    if (depth > 2 || v == null || typeof v !== 'object') return false;
    if (Array.isArray(v)) return v.some(x => hasAdPlumbing(x, depth + 1));
    if (isAdObject(v)) return true;
    for (const [k, x] of Object.entries(v)) {
      const kl = k.toLowerCase();
      if (AD_LINK_KEY.test(k) && typeof x === 'string' && x) return true;
      if (TRACKING_URL_KEY.test(k) && isNonEmptyValue(x)) return true;
      if (AD_ID_KEY.test(k) && isNonEmptyValue(x)) return true;
      if (RTB_BID_KEYS.includes(kl) || kl === 'creative' || kl === 'creatives' || kl === 'html' || kl === 'markup') return true;
      if (typeof x === 'string' && x.length > 20 && VAST_DOC.test(x)) return true;
      if (x && typeof x === 'object' && hasAdPlumbing(x, depth + 1)) return true;
    }
    return false;
  }

  /** True when `value` sits under a key that names it an ad container. */
  function isAdContainerEntry(key, value) {
    if (typeof key !== 'string' || !AD_CONTAINER_KEY.test(key)) return false;
    if (typeof value === 'string') return /^vast|vmap/i.test(key) && value.length > 0;
    if (isPlainObject(value)) return Object.keys(value).length > 0 && hasAdPlumbing(value);
    if (Array.isArray(value)) return value.some(v => isPlainObject(v) && Object.keys(v).length > 0) && hasAdPlumbing(value);
    return false;
  }

  function isUrlString(v) {
    return typeof v === 'string' && /^(https?:)?\/\//i.test(v.trim());
  }

  const VAST_URL = /<(Impression|Tracking|ClickTracking|Error|Viewable|ViewUndetermined|NotViewable)\b[^>]*>\s*(?:<!\[CDATA\[)?\s*([^<\]\s]+)/gi;

  /**
   * Walk an ad object and remember its tracker URLs and identities.
   * Learned values let the shield block the client-side impression
   * report that a server-side ad still has to send.
   */
  function harvest(obj, collector, depth) {
    if (!collector || depth > MAX_DEPTH || obj == null) return;
    if (typeof obj === 'string') {
      if (VAST_DOC.test(obj)) {
        let m;
        VAST_URL.lastIndex = 0;
        while ((m = VAST_URL.exec(obj))) if (isUrlString(m[2])) collector.urls.add(m[2].trim());
      }
      return;
    }
    if (Array.isArray(obj)) {
      for (const v of obj) harvest(v, collector, depth + 1);
      return;
    }
    if (!isPlainObject(obj)) return;
    for (const [k, v] of Object.entries(obj)) {
      const lk = k.toLowerCase();
      const trackerKey =
        TRACKER_ARRAY_KEYS.has(lk) || TRACKING_URL_KEY.test(k) || (TRACKER_MAP_KEY.test(k) && isTrackerMap(v)) ||
        lk === 'nurl' || lk === 'burl' || lk === 'lurl' || lk === 'purl' ||
        // OpenRTB 3.0 / AdCOM event trackers: event:[{type, method, url}].
        (lk === 'event' && Array.isArray(v)) ||
        (lk === 'url' && collector._inTracker);
      if (trackerKey) {
        const urls = [];
        collectStrings(v, urls, depth + 1);
        for (const u of urls) if (isUrlString(u)) collector.urls.add(u.trim());
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
        // Only distinctive, id-shaped values: anything else could collide
        // with ordinary request content.
        if (LEARNABLE_ID.test(s)) collector.ids.add(s);
      }
      if (typeof v === 'object' || typeof v === 'string') harvest(v, collector, depth + 1);
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

  /** React Server Components element tuple: ["$", type, key, props]. */
  function isRscElement(v) {
    return Array.isArray(v) && v.length >= 4 && v[0] === '$' && typeof v[1] === 'string';
  }

  function isAdValue(key, v) {
    if (isAdObject(v)) return true;
    if (key !== null && isAdContainerEntry(key, v)) return true;
    if (typeof v === 'string' && v.length > 20 && VAST_DOC.test(v)) return true;
    // A React element whose props are an ad.
    if (isRscElement(v) && isAdObject(v[3])) return true;
    return false;
  }

  /**
   * Remove every ad object from a parsed JSON value.
   *
   * Mutates `value` in place (callers pass a freshly parsed copy) and
   * returns { value, changed, removedAll }. `removedAll` means the root
   * itself was an ad, or an envelope around one — the caller drops the
   * whole message.
   */
  function pruneAds(value, collector, embedDepth) {
    const c = collector || newCollector();
    const state = { nodes: 0, changed: false };
    embedDepth = embedDepth || 0;

    if (isAdValue(null, value)) {
      harvest(value, c, 0);
      c.removed++;
      return { value: null, changed: true, removedAll: true, collector: c };
    }

    const dropRoot = walk(value, 0, false);
    if (dropRoot) return { value: null, changed: true, removedAll: true, collector: c };
    return { value, changed: state.changed, removedAll: false, collector: c };

    function remove(v) {
      harvest(v, c, 0);
      c.removed++;
      state.changed = true;
    }

    /** JSON encoded inside a string (MCP text content, tool arguments). */
    function prunedString(str) {
      if (embedDepth >= 2 || str.length > MAX_EMBEDDED_JSON) return null;
      const t = str.trim();
      if ((t[0] !== '{' || t[t.length - 1] !== '}') && (t[0] !== '[' || t[t.length - 1] !== ']')) return null;
      let parsed;
      try { parsed = JSON.parse(t); } catch (_) { return null; }
      const r = pruneAds(parsed, c, embedDepth + 1);
      if (!r.changed) return null;
      state.changed = true;
      return r.removedAll ? (t[0] === '[' ? '[]' : '{}') : JSON.stringify(r.value);
    }

    /**
     * Returns true when `node` itself must be dropped by its parent.
     * `inUser`: inside a message the user wrote. JSON a user pasted into
     * their own message (e.g. asking about an OpenRTB response) is theirs
     * and is never rewritten.
     */
    function walk(node, depth, inUser) {
      if (node === null || typeof node !== 'object') return false;
      if (depth > MAX_DEPTH || ++state.nodes > MAX_NODES) return false;
      if (!Array.isArray(node) && node.role === 'user') inUser = true;
      if (Array.isArray(node)) {
        for (let i = node.length - 1; i >= 0; i--) {
          const v = node[i];
          if (isAdValue(null, v)) { remove(v); node.splice(i, 1); continue; }
          if (typeof v === 'string') {
            const p = inUser ? null : prunedString(v);
            if (p !== null) node[i] = p;
          } else if (walk(v, depth + 1, inUser)) {
            node.splice(i, 1);
          }
        }
        return false;
      }
      for (const k of Object.keys(node)) {
        const v = node[k];
        if (isAdValue(k, v)) {
          remove(v);
          // An event envelope ({type, index, content_block:<ad>}) goes
          // with its ad; otherwise just the key goes.
          if (ENVELOPE_KEYS.has(k) && typeof node.type === 'string') return true;
          delete node[k];
          continue;
        }
        if (typeof v === 'string') {
          const p = inUser ? null : prunedString(v);
          if (p !== null) node[k] = p;
        } else if (walk(v, depth + 1, inUser)) {
          if (ENVELOPE_KEYS.has(k) && typeof node.type === 'string') return true;
          delete node[k];
        }
      }
      return false;
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
      if (STRONG_AD_ID_KEY.test(key) && value) adId = true;
    });
    return explicit || (delivery && adId);
  }

  /** One event object reports an ad impression/click. */
  function isAdEvent(obj) {
    if (!isPlainObject(obj)) return false;
    let explicit = false;
    let delivery = false;
    let adId = false;
    for (const [k, v] of Object.entries(obj)) {
      if (EVENT_KEY.test(k) && typeof v === 'string') {
        const s = v.trim();
        if (EXPLICIT_AD_EVENT.test(s)) explicit = true;
        else if (DELIVERY_EVENT.test(s)) delivery = true;
      }
      if (STRONG_AD_ID_KEY.test(k) && isNonEmptyValue(v)) adId = true;
    }
    if (explicit || (delivery && adId)) return true;
    // Viewability state on an impression event (Thrad).
    if (delivery && ('impressionState' in obj || 'impression_state' in obj)) return true;
    // Segment/RudderStack-style properties bag.
    if (delivery && isPlainObject(obj.properties) && Object.keys(obj.properties).some(k => STRONG_AD_ID_KEY.test(k))) return true;
    return false;
  }

  /**
   * JSON body reports an ad impression/click. Only event-shaped objects
   * are checked: the root, or the items of a batch (events/batch/data).
   * A request that merely CONTAINS an ad (a chat request carrying the
   * conversation history) is never blocked.
   */
  function isAdEventPayload(obj) {
    if (Array.isArray(obj)) return obj.some(isAdEvent);
    if (!isPlainObject(obj)) return false;
    if (isAdEvent(obj)) return true;
    for (const k of ['events', 'batch', 'data', 'items']) {
      const v = obj[k];
      if (Array.isArray(v) && v.some(isAdEvent)) return true;
      if (isPlainObject(v) && isAdEvent(v)) return true;
    }
    return false;
  }

  // ---------------------------------------------------------------------------
  // Link signatures
  // ---------------------------------------------------------------------------

  // utm_medium values that mean "this click was bought".
  const PAID_MEDIUM = /^(cpc|ppc|cpm|cpa|cpv|paid|paid[_-]?(search|social|media|ads?)|paidsearch|paidsocial|display|sponsored|native|ad|ads|advert|advertising|banner|retargeting|programmatic)$/i;
  // Ad-click identifiers appended by ad platforms.
  const AD_CLICK_ID_PARAMS = ['gclid', 'gbraid', 'wbraid', 'dclid', 'gclsrc', 'msclkid', 'ttclid', 'twclid', 'li_fat_id', 'yclid', 'irclickid', 'epik', 'rdt_cid', 'scclid', 'kad_cid', 'oppref', 'olref'];
  // Ad-server click paths. Generic ones (/redirect, /go, /out...) are also
  // used by logout and SSO flows, so they only count on a known ad host or
  // when the URL carries an ad click id.
  const AD_CLICK_PATH = /\/(aclk|pagead\/aclk)\/?$/i;
  const REDIRECT_PATH = /\/(click|clk|clicks|clickthrough|track|tracking|redirect|redir|r|out|go)\/?$/i;
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
    const adClick = AD_CLICK_PATH.test(u.pathname) ||
      (REDIRECT_PATH.test(u.pathname) && AD_CLICK_ID_PARAMS.some(p => u.searchParams.has(p)));
    if (!trackerHost && !adClick) return null;
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
  // Lookalike letters (Cyrillic/Greek/Armenian/Cherokee/small caps) folded
  // to ASCII so "Ѕроnѕоrеd" reads as "sponsored".
  const LETTER_CONFUSABLES = {
    'а': 'a', 'А': 'a', 'е': 'e', 'Е': 'e', 'о': 'o', 'О': 'o', 'р': 'p', 'Р': 'p',
    'с': 'c', 'С': 'c', 'ѕ': 's', 'Ѕ': 's', 'і': 'i', 'І': 'i', 'ԁ': 'd', 'ո': 'n',
    'ο': 'o', 'Ο': 'o', 'α': 'a', 'Α': 'a', 'ε': 'e', 'Ε': 'e', 'ρ': 'p', 'Ρ': 'p',
    'ν': 'v', 'τ': 't', 'Τ': 't', 'Μ': 'm', 'Ν': 'n', 'Ι': 'i', 'ι': 'i',
    'ꜱ': 's', 'ɑ': 'a', 'ʀ': 'r', 'ᴅ': 'd', 'ᴏ': 'o', 'ɴ': 'n', 'ᴀ': 'a', 'ᴇ': 'e', 'ᴘ': 'p',
    'օ': 'o', 'Տ': 's', 'ս': 'u', 'Ꭺ': 'a', 'Ꭰ': 'd', 'ı': 'i'
  };
  // Digit/symbol stand-ins ("Sp0ns0red"). Only applied to words of five or
  // more characters with at least three letters: folded into short words
  // they turn "Ad5" into "ads", and into "(1/3)" they break counters.
  const DIGIT_CONFUSABLES = { '0': 'o', '1': 'l', '3': 'e', '5': 's', '$': 's', '@': 'a' };

  function fold(s, map) {
    let out = '';
    for (const ch of s) out += Object.prototype.hasOwnProperty.call(map, ch) ? map[ch] : ch;
    return out;
  }

  function normalizeText(text) {
    if (typeof text !== 'string') return '';
    let s = fold(text.normalize('NFKC').replace(INVISIBLE, ''), LETTER_CONFUSABLES);
    s = s.replace(/\S{5,}/g, w => ((w.match(/[a-z]/gi) || []).length >= 3 ? fold(w, DIGIT_CONFUSABLES) : w));
    return s.toLowerCase().replace(/\s+/g, ' ').trim();
  }

  const EDGE_PUNCT = /^[\s:·•|\-–—()[\]【】「」〔〕［］]+|[\s:·•|\-–—()[\]【】「」〔〕［］]+$/g;

  function normalizeLabel(text) {
    return normalizeText(text).replace(EDGE_PUNCT, '').trim();
  }

  // Non-Latin labels must not go through the lookalike fold (it would turn
  // "Реклама" into mixed-script nonsense), so they get their own pass.
  function normalizeI18n(text, keepEdges) {
    if (typeof text !== 'string') return '';
    const s = text.normalize('NFKC').replace(INVISIBLE, '').toLocaleLowerCase().replace(/\s+/g, ' ').trim();
    return keepEdges ? s : s.replace(EDGE_PUNCT, '').trim();
  }

  // "Ad 1 of 3", "Sponsored · 2/3", "Ad (1/3)": carousel counters.
  const COUNTER = String.raw`(?:\s*[·•|]?\s*\(?\d+\s*(?:of|/)\s*\d+\)?)?`;

  // A disclosure label is a SHORT element whose whole text is the label.
  // Prose that merely mentions sponsorship ("this study was sponsored by
  // NIH") never matches because the regex is anchored on both ends.
  // Bare "paid", "sponsor" and "advertising" are deliberately absent: they
  // are also invoice statuses, sponsor buttons and footer links.
  const DISCLOSURE = new RegExp('^(sponsored|ad|ads|advert|advertisement|advertisements|promoted|paid (ad|partnership|promotion|placement|content|post|link|listing|recommendation)|partner content|sponsored (ad|result|results|content|listing|listings|link|links|product|products|answer|suggestion|suggestions|recommendation|recommendations|message|post|placement|offer|by .{1,40})|promoted (content|result|results|post|listing|link|links|product|products|suggestion|by .{1,40})|ad (by|from|·) .{1,40}|ads by .{1,40}|from (our|a) sponsors?|our sponsors?|brought to you by .{1,40})' + COUNTER + '$');

  // Disclosure labels in other languages (EU DSA, UK, JP, KR, CN, BR, ...).
  // These words mean only "sponsored"/"advertisement"/"paid partnership",
  // so they are safe as whole-element labels on any page.
  const I18N_STRONG = [
    'gesponsert', 'bezahlte partnerschaft', 'werbeanzeige',
    'sponsorisé', 'sponsorisée', 'publicité', 'contenu sponsorisé', 'partenariat rémunéré',
    'patrocinado', 'patrocinada', 'publicidad', 'colaboración pagada',
    'sponsorizzato', 'sponsorizzata', 'pubblicità', 'partnership retribuita',
    'publicidade', 'parceria paga',
    'gesponsord', 'advertentie', 'betaald partnerschap',
    'sponsorowane', 'płatna współpraca',
    'sponsrad', 'betalt partnerskap', 'sponsoreret', 'betalt partnerskab', 'sponset',
    'sponsoroitu', 'maksettu kumppanuus',
    'sponzorováno', 'placená spolupráce',
    'спонсировано', 'спонсорский контент', 'платное партнёрство', 'платное партнерство',
    'спонсоровано', 'платне партнерство',
    'sponsorlu', 'ücretli ortaklık',
    'ممول', 'مُموَّل', 'إعلان ممول', 'شراكة مدفوعة',
    'ממומן', 'שיתוף פעולה בתשלום',
    'प्रायोजित', 'सशुल्क साझेदारी',
    '広告', 'プロモーション', 'スポンサー広告',
    '광고', '협찬', '유료 광고 포함',
    '广告', '赞助', '赞助内容', '廣告', '贊助', '贊助內容',
    'bersponsor', 'kemitraan berbayar',
    'được tài trợ', 'hợp tác có trả phí',
    'ได้รับการสนับสนุน', 'โฆษณา',
    'χορηγούμενο', 'διαφήμιση', 'sponsorizat', 'publicitate', 'szponzorált', 'hirdetés'
  ];
  // Words that also mean something ordinary ("Anzeige" = display, "Annonce"
  // = announcement, "Reklama" in a menu). Accepted only when the page or
  // element language matches.
  const I18N_AMBIGUOUS = {
    de: ['anzeige', 'werbung'],
    fr: ['annonce', 'pub'],
    es: ['anuncio', 'promocionado'],
    it: ['annuncio', 'promosso'],
    pt: ['anúncio', 'promovido', 'publi'],
    nl: ['gepromoot'],
    pl: ['reklama', 'promowane'],
    sv: ['annons', 'marknadsförd'],
    da: ['annonce'],
    no: ['annonse', 'reklame'], nb: ['annonse', 'reklame'],
    fi: ['mainos'],
    cs: ['reklama', 'inzerce'],
    ru: ['реклама'], uk: ['реклама'],
    tr: ['reklam', 'tanıtılan'],
    ar: ['إعلان'],
    he: ['מודעה', 'פרסומת'],
    hi: ['विज्ञापन'],
    ja: ['スポンサー', 'タイアップ'],
    ko: ['스폰서'],
    zh: ['推广', '推廣'],
    id: ['iklan', 'dipromosikan'],
    vi: ['quảng cáo'],
    hu: ['reklám']
  };
  const I18N_STRONG_SET = new Set(I18N_STRONG);

  function stripCounter(n) {
    return n.replace(/\s*[·•|]?\s*\(?\d+\s*(?:of|\/)\s*\d+\)?$/, '').trim();
  }

  function isI18nLabel(text, lang) {
    const n = stripCounter(normalizeI18n(text));
    if (!n || n.length > 40) return false;
    if (I18N_STRONG_SET.has(n)) return true;
    const code = typeof lang === 'string' ? lang.toLowerCase().split('-')[0] : '';
    const words = code && I18N_AMBIGUOUS[code];
    return !!words && words.includes(n);
  }

  // "Sponsored: Try Acme…", "[Ad] Acme…", "【広告】…" — a label glued to the
  // start of a paragraph. The colon/bracket is required so "Ad hoc" or
  // "Promoted to manager" never match.
  const DISCLOSURE_PREFIX = /^(?:(sponsored|ad|advertisement|promoted|paid partnership|paid promotion|sponsored content|sponsored result|sponsored suggestion)\s*[:|·—–]\s*\S|[\[(](sponsored|ad|advertisement|promoted)[\])]\s*\S)/;
  const I18N_PREFIX = /^(?:[【［\[(（]\s*(広告|pr|광고|广告|廣告|anzeige|werbung|publicité|publicidad|pubblicità|reklama|реклама)\s*[】］\])）]|(gesponsert|sponsorisé|patrocinado|sponsorizzato|gesponsord|sponsorowane|спонсировано|sponsorlu|広告|광고|广告|廣告)\s*[:：|·—–])\s*\S/;

  function isDisclosurePrefix(text) {
    if (typeof text !== 'string') return false;
    // "— Sponsored: …" (a suffix set off by a dash) counts too.
    const head = text.slice(0, 120).replace(/^[\s—–\-•·|]+/, '');
    const raw = head.normalize('NFKC').replace(INVISIBLE, '').trim();
    // "AD: Alzheimer disease" / "PROMOTED: v2.1" are glossary entries and
    // release notes; real disclosures are written "Ad:" / "Promoted:".
    if (/^(AD|PROMOTED)\s*[:|·—–]/.test(raw)) return false;
    return DISCLOSURE_PREFIX.test(normalizeText(head)) || I18N_PREFIX.test(normalizeI18n(head, true));
  }

  function matchesLabel(text, lang) {
    const n = normalizeLabel(text);
    if (n.length > 0 && n.length <= 60 && DISCLOSURE.test(n)) {
      // All-caps "AD"/"ADS" is Active Directory, anno domini, a table column.
      const raw = text.normalize('NFKC').replace(INVISIBLE, '').replace(EDGE_PUNCT, '').trim();
      if (/^(AD|ADS)\b/.test(raw) && !/^ADS? (BY|FROM)\b/.test(raw)) return false;
      return true;
    }
    return isI18nLabel(text, lang);
  }

  function isDisclosureLabel(text, lang) {
    if (typeof text !== 'string' || text.length > 80) return false;
    if (matchesLabel(text, lang)) return true;
    // "S p o n s o r e d": letters spaced out one by one.
    const tokens = text.trim().split(/\s+/);
    if (tokens.length >= 4 && tokens.every(t => [...t].length === 1) && matchesLabel(tokens.join(''), lang)) return true;
    // Right-to-left override: "‮derosnops" renders as "sponsored".
    if (/[‭‮]/.test(text) && matchesLabel([...text].reverse().join(''), lang)) return true;
    return false;
  }

  // A lone all-caps "AD"/"ADS" badge. matchesLabel rejects it because the
  // same text is an abbreviation; the content script accepts it only as a
  // standalone badge at the top of a link card in a chat answer or frame.
  function isCapsAdBadge(text) {
    if (typeof text !== 'string' || text.length > 12) return false;
    return /^[\[(【]?\s*ADS?\s*[\])】]?$/.test(text.normalize('NFKC').replace(INVISIBLE, '').trim());
  }

  const api = Object.freeze({
    isAdObject,
    isAdContainerEntry,
    pruneAds,
    newCollector,
    hasRtbMacro,
    isAdEventQuery,
    isAdEventPayload,
    LEARNABLE_ID,
    isPaidClickUrl,
    unwrapClickRedirect,
    normalizeLabel,
    isDisclosureLabel,
    isDisclosurePrefix,
    isCapsAdBadge,
    AD_CLICK_ID_PARAMS: Object.freeze(AD_CLICK_ID_PARAMS.slice())
  });

  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.ArmorlyAdSignatures = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
