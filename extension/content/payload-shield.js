/**
 * Armorly - payload shield (MAIN world).
 *
 * Server-side / OpenRTB ads never load an ad SDK: the chatbot's own server
 * runs the auction and stitches the ad into its response. Network blocking
 * by domain can't see that. Two things still have to happen in the
 * browser, and this file intercepts both:
 *
 *   1. The ad has to reach the page as data. We filter JSON (including
 *      streamed top-level arrays and XSSI-prefixed JSON), Server-Sent
 *      Events, NDJSON, AI-SDK and React Server Component line streams,
 *      WebSocket (text, binary, Socket.IO, SignalR) and EventSource
 *      messages, and XHR responses, and drop every object that is an ad by
 *      structure (lib/ad-signatures.js) before the page's own code reads it.
 *   2. The advertiser has to get proof the ad was delivered. We block the
 *      impression pixels, beacons and win/billing notices: URLs learned
 *      from the ad objects we removed, requests that carry those ads' ids,
 *      ad-event analytics payloads, and known ad/verification hosts.
 *      Learned tracker URLs are also handed to the background worker as
 *      tab-scoped block rules, which catches pixels no JS hook can see
 *      (<img> parsed from innerHTML).
 *
 * Plus the browser's own ad APIs (Protected Audience, Topics, Attribution
 * Reporting) are stubbed out.
 *
 * Every rule is a fixed structural match; nothing here is probabilistic,
 * fetched remotely, or evaluated. Any error fails open (the original
 * response is returned untouched) so a bug here can't break a site.
 *
 * This file must not touch chrome.* (MAIN world has no extension APIs).
 */

(function () {
  'use strict';

  const S = window.ArmorlyAdSignatures;
  const P = window.ArmorlyAdPatterns;
  // Take the signature library out of the page's reach so page scripts
  // can't overwrite the classifiers we hold references to.
  try { delete window.ArmorlyAdSignatures; } catch (_) { /* noop */ }
  if (!S || !P) return;

  // SDK-blocker hands us its controls through a one-shot global that we
  // remove before any page script runs.
  const sdkControl = window.__armorlySdkControl || null;
  try { delete window.__armorlySdkControl; } catch (_) { /* noop */ }

  const pageHost = location.hostname.toLowerCase();
  if (typeof P.isSkippedHost === 'function' && P.isSkippedHost(pageHost)) return;

  let enabled = true;

  // Native references, taken before we patch anything.
  const nativeAddEventListener = EventTarget.prototype.addEventListener;
  const nativeRemoveEventListener = EventTarget.prototype.removeEventListener;
  const nativePostMessage = window.postMessage.bind(window);

  // ---------------------------------------------------------------------------
  // Control channel with the isolated-world script
  //
  // Both content scripts run at document_start, before any page script.
  // Whichever runs first writes three random keys to an attribute on
  // <html>; the other reads and removes it. One key per message type, so a
  // page that sees one message can't forge another:
  //   [0] pattern updates  (ISOLATED -> MAIN, sent on most pages)
  //   [1] disable-site     (ISOLATED -> MAIN, sent only where the user
  //                         switched Armorly off, so it never leaks
  //                         anywhere it would matter)
  //   [2] learned trackers (MAIN -> ISOLATED; a forged one can only block
  //                         requests in the forger's own tab)
  // ---------------------------------------------------------------------------

  const KEY_ATTR = 'data-armorly-bridge';
  let keys = null;
  try {
    const rootEl = document.documentElement;
    if (rootEl) {
      if (rootEl.hasAttribute(KEY_ATTR)) {
        keys = rootEl.getAttribute(KEY_ATTR).split('.');
        rootEl.removeAttribute(KEY_ATTR);
      } else {
        keys = [0, 1, 2].map(() => {
          const buf = new Uint32Array(4);
          crypto.getRandomValues(buf);
          return Array.from(buf, n => n.toString(36)).join('');
        });
        rootEl.setAttribute(KEY_ATTR, keys.join('.'));
      }
    }
  } catch (_) { /* noop */ }
  const hasKey = (i, k) => !!keys && typeof keys[i] === 'string' && keys[i].length > 8 && k === keys[i];

  nativeAddEventListener.call(window, 'message', function (event) {
    if (event.source !== window) return;
    const d = event.data;
    if (!d || d.source !== 'armorly') return;
    if (d.type === 'disable-site' && hasKey(1, d.key)) {
      enabled = false;
      if (sdkControl) sdkControl.disable();
    } else if (d.type === 'update-sdk-list' && hasKey(0, d.key)) {
      if (sdkControl && Array.isArray(d.functions)) sdkControl.install(d.functions);
      if (Array.isArray(d.domains)) for (const h of d.domains) if (typeof h === 'string') adHosts.add(h.toLowerCase());
    }
  });

  function report(kind) {
    try { nativePostMessage({ source: 'armorly', type: 'shield-blocked', kind }, '*'); } catch (_) { /* noop */ }
  }

  // ---------------------------------------------------------------------------
  // What to block
  // ---------------------------------------------------------------------------

  // Ad network + ad verification/measurement hosts. Verification vendors
  // are how a brand checks that a server-side ad was actually viewed.
  const adHosts = new Set(P.getAllSDKDomains().map(h => h.toLowerCase()));
  for (const h of (P.verificationDomains || [])) adHosts.add(h.toLowerCase());

  // Learned from ads we removed. A tracker on the page's own host is only
  // blocked for beacon-like loads (pixels, scripts, frames, sendBeacon): a
  // poisoned or careless ad naming the site's own API as its impression
  // URL must never take the chat down.
  const learnedExact = new Set();     // href without fragment
  const learnedThirdParty = new Set(); // third-party origin + pathname
  const learnedFirstParty = new Set(); // same-host origin + pathname (beacons only)
  const learnedIds = new Set();        // ids of ads we removed

  function hostMatches(h, d) {
    return h === d || h.endsWith('.' + d);
  }

  // Registrable domain (eTLD+1), close enough without the full public
  // suffix list: two labels, or three under common two-level suffixes.
  const TWO_LEVEL_SUFFIX = /\.(co|com|net|org|gov|edu|ac|ne|or|go)\.[a-z]{2}$/;
  function siteOf(host) {
    const parts = host.toLowerCase().split('.');
    if (/^\d+$/.test(parts[parts.length - 1])) return host.toLowerCase(); // IP address
    const n = TWO_LEVEL_SUFFIX.test(host.toLowerCase()) ? 3 : 2;
    return parts.slice(-n).join('.');
  }
  const pageSite = siteOf(pageHost);
  const isFirstParty = host => siteOf(host) === pageSite;

  // A vendor's own site (docs, dashboard) may load its own domains, the
  // same exemption rules/ad-sdks.json makes via excludedInitiatorDomains.
  const ownVendorHosts = new Set();
  for (const sdk of Object.values(P.adSDKs || {})) {
    const domains = (sdk && sdk.domainPatterns) || [];
    if (domains.some(d => hostMatches(pageHost, d.toLowerCase()))) {
      for (const d of domains) ownVendorHosts.add(d.toLowerCase());
    }
  }

  function isAdHost(hostname) {
    const h = hostname.toLowerCase();
    for (const d of ownVendorHosts) if (hostMatches(h, d)) return false;
    for (const d of adHosts) if (hostMatches(h, d)) return true;
    return false;
  }

  function toUrl(u) {
    try { return new URL(String(u), location.href); } catch (_) { return null; }
  }

  function learn(collector) {
    if (!collector) return;
    const fresh = [];
    for (const raw of collector.urls) {
      const u = toUrl(raw);
      if (!u || (u.protocol !== 'http:' && u.protocol !== 'https:')) continue;
      const href = u.href.split('#')[0];
      if (learnedExact.has(href)) continue;
      learnedExact.add(href);
      const firstParty = isFirstParty(u.hostname);
      (firstParty ? learnedFirstParty : learnedThirdParty).add(u.origin + u.pathname);
      fresh.push({ url: href, firstParty });
    }
    for (const id of collector.ids) if (S.LEARNABLE_ID.test(id)) learnedIds.add(id);
    if (fresh.length && keys) {
      try { nativePostMessage({ source: 'armorly', type: 'shield-learned', key: keys[2], urls: fresh.slice(0, 50) }, '*'); } catch (_) { /* noop */ }
    }
  }

  function decodeSafe(s) {
    try { return decodeURIComponent(s); } catch (_) { return s; }
  }

  /** An id we learned appears as an exact query value or path segment. */
  function urlCarriesLearnedId(u) {
    if (!learnedIds.size) return false;
    for (const seg of u.pathname.split('/')) if (seg && learnedIds.has(decodeSafe(seg))) return true;
    let hit = false;
    u.searchParams.forEach(v => { if (learnedIds.has(v)) hit = true; });
    return hit;
  }

  /** An id we learned appears as an exact string value in a JSON body. */
  function jsonCarriesLearnedId(v, depth, budget) {
    if (!learnedIds.size || budget.n-- <= 0 || depth > 8) return false;
    if (typeof v === 'string') return learnedIds.has(v);
    if (typeof v === 'number') return learnedIds.has(String(v));
    if (v && typeof v === 'object') {
      for (const x of Object.values(v)) if (jsonCarriesLearnedId(x, depth + 1, budget)) return true;
    }
    return false;
  }

  /**
   * kind: 'beacon' (img/script/frame src, sendBeacon, ping) | 'get'
   * (fetch/XHR without a body) | 'body' (fetch/XHR with a body).
   */
  function isBlockedUrl(raw, kind) {
    if (!enabled || raw == null) return false;
    const u = toUrl(raw);
    if (!u || (u.protocol !== 'http:' && u.protocol !== 'https:')) return false;
    const href = u.href.split('#')[0];
    const firstParty = isFirstParty(u.hostname);
    // First-party learned trackers: pixels/beacons/scripts/frames only. The
    // site's own fetch/XHR calls are never blocked by a learned URL.
    if (learnedExact.has(href) && (!firstParty || kind === 'beacon')) return true;
    const path = u.origin + u.pathname;
    if (learnedThirdParty.has(path)) return true;
    if (kind === 'beacon' && learnedFirstParty.has(path)) return true;
    if (isAdHost(u.hostname)) return true;
    if (S.hasRtbMacro(u.href)) return true;
    if (u.search && S.isAdEventQuery(u.searchParams)) return true;
    // Learned ids are often the chat's own message/query ids too: on the
    // site's own requests they only count for beacons.
    if ((kind === 'beacon' || !firstParty) && urlCarriesLearnedId(u)) return true;
    return false;
  }

  const textDecoder = new TextDecoder();

  /** Synchronous view of a request body as text, or null. */
  function bodyText(body) {
    if (body == null) return null;
    if (typeof body === 'string') return body;
    if (body instanceof URLSearchParams) return body.toString();
    if (typeof FormData !== 'undefined' && body instanceof FormData) {
      const parts = [];
      body.forEach((v, k) => { if (typeof v === 'string') parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(v)); });
      return parts.join('&');
    }
    try {
      if (body instanceof ArrayBuffer) return body.byteLength <= 65536 ? textDecoder.decode(body) : null;
      if (ArrayBuffer.isView(body)) return body.byteLength <= 65536 ? textDecoder.decode(body) : null;
    } catch (_) { return null; }
    return null; // Blob / stream: see asyncBodyText.
  }

  /** `ids`: also match learned ad ids (beacons and third-party requests only). */
  function isBlockedText(text, ids) {
    if (!enabled || !text || text.length > 65536) return false;
    const t = text.trim();
    if (t[0] === '{' || t[0] === '[') {
      let parsed;
      try { parsed = JSON.parse(t); } catch (_) { return false; }
      return S.isAdEventPayload(parsed) || (ids && jsonCarriesLearnedId(parsed, 0, { n: 5000 }));
    }
    if (t.includes('=')) {
      try {
        const params = new URLSearchParams(t);
        if (S.isAdEventQuery(params)) return true;
        if (!ids) return false;
        let hit = false;
        params.forEach(v => { if (learnedIds.has(v)) hit = true; });
        return hit;
      } catch (_) { return false; }
    }
    return false;
  }

  function idsApply(url, kind) {
    if (kind === 'beacon') return true;
    const u = toUrl(url);
    return !!u && !isFirstParty(u.hostname);
  }

  function isBlockedBody(body, url, kind) {
    return isBlockedText(bodyText(body), idsApply(url, kind));
  }

  /** Small text-like Blob bodies, read without consuming them. */
  function readableBlob(b) {
    return typeof Blob !== 'undefined' && b instanceof Blob && b.size > 0 && b.size <= 65536 &&
      (!b.type || /json|text|x-www-form-urlencoded/i.test(b.type));
  }

  // ---------------------------------------------------------------------------
  // Payload filtering
  // ---------------------------------------------------------------------------

  const MAX_JSON_CHARS = 8 * 1024 * 1024;
  // Root-level positional fields renumbered after an envelope is dropped
  // (Anthropic content blocks, OpenAI Responses output items).
  const INDEX_KEYS = ['index', 'output_index'];

  function newStreamState() {
    return { dropped: new Map() };
  }

  /**
   * Filter one JSON document. Returns null when unchanged, else
   * { text } or { drop: true }. `state` (per stream) carries dropped
   * envelope indexes so later events for that block go too, and later
   * indexes shift down to stay contiguous.
   */
  function filterJsonText(text, state) {
    if (!enabled || typeof text !== 'string' || text.length > MAX_JSON_CHARS) return null;
    const t = text.trim();
    if (t[0] !== '{' && t[0] !== '[') return null;
    let value;
    try { value = JSON.parse(t); } catch (_) { return null; }
    const isObj = value !== null && typeof value === 'object' && !Array.isArray(value);
    const r = S.pruneAds(value);
    let changed = r.changed;

    if (state && isObj) {
      if (r.removedAll) {
        for (const k of INDEX_KEYS) {
          if (typeof value[k] === 'number') {
            const list = state.dropped.get(k) || [];
            list.push(value[k]);
            state.dropped.set(k, list);
          }
        }
      } else {
        for (const k of INDEX_KEYS) {
          const list = state.dropped.get(k);
          if (!list || typeof value[k] !== 'number') continue;
          if (list.includes(value[k])) { report('payload'); return { drop: true }; }
          const shift = list.filter(n => n < value[k]).length;
          if (shift) { value[k] -= shift; changed = true; }
        }
      }
    }

    if (!changed) return null;
    if (r.changed) { learn(r.collector); report('payload'); }
    if (r.removedAll) return { drop: true };
    return { text: JSON.stringify(r.value) };
  }

  // Anti-JSON-hijacking prefixes some APIs put in front of JSON.
  const XSSI = /^(\)\]\}'[,\s]*|for\s*\(;;\);\s*|while\s*\(1\);\s*)/;
  // Socket.IO / Engine.IO packet: "42[...]" or "42/ns,17[...]".
  const SOCKET_IO = /^(\d+(?:\/[^,[]*,)?\d*)(\[[\s\S]*\])$/;

  /** Filter a message that may be framed (SignalR, Socket.IO, XSSI). */
  function filterFramed(text, state) {
    if (typeof text !== 'string') return null;
    if (text.indexOf('\x1e') !== -1) {
      let changed = false;
      const out = [];
      for (const part of text.split('\x1e')) {
        const r = part ? filterJsonText(part, state) : null;
        if (!r) { out.push(part); continue; }
        changed = true;
        if (!r.drop) out.push(r.text);
      }
      if (!changed) return null;
      if (!out.some(Boolean)) return { drop: true };
      return { text: out.join('\x1e') };
    }
    const io = SOCKET_IO.exec(text);
    if (io) {
      let arr;
      try { arr = JSON.parse(io[2]); } catch (_) { return null; }
      const before = arr.length;
      const r = S.pruneAds(arr);
      if (!r.changed) return null;
      learn(r.collector);
      report('payload');
      // An ad removed from the event's argument list would shift the
      // handler's arguments; drop the whole event instead.
      if (r.removedAll || r.value.length !== before) return { drop: true };
      return { text: io[1] + JSON.stringify(r.value) };
    }
    const x = XSSI.exec(text);
    if (x) {
      const r = filterJsonText(text.slice(x[0].length), state);
      if (!r) return null;
      return { text: x[0] + (r.drop ? '{}' : r.text) };
    }
    return filterJsonText(text, state);
  }

  const AD_EVENT_NAME = /^(ad|ads|advert|advertisement|sponsored|promoted|ad[_-][\w-]+|sponsored[_-][\w-]+|promoted[_-][\w-]+)$/i;

  /** Filter one SSE event block (text between blank lines). */
  function filterSseEvent(block, state) {
    const lines = block.split(/\r?\n/);
    const dataLines = [];
    const other = [];
    for (const line of lines) {
      if (/^event:/.test(line) && AD_EVENT_NAME.test(line.slice(6).trim())) {
        report('payload');
        return null; // named ad event: drop
      }
      if (/^data:/.test(line)) dataLines.push(line.slice(5).replace(/^ /, ''));
      else other.push(line);
    }
    if (!dataLines.length) return block;
    const r = filterJsonText(dataLines.join('\n'), state);
    if (!r) return block;
    // Dropped whole: an event with only id:/retry: left would reach
    // parsers as an empty data event, which many JSON.parse and crash on.
    if (r.drop) return null;
    return other.concat('data: ' + r.text).join('\n');
  }

  // NDJSON, AI-SDK data stream ("0:...", "8:[...]"), and React Server
  // Component rows ("1a:{...}"; "1a:T<len>," text rows are left alone).
  const LINE_PREFIX = /^([0-9a-f]{1,8}|[0-9a-z]{1,2}):(.*)$/;

  function filterLine(line, state) {
    if (!line.trim()) return line;
    const m = LINE_PREFIX.exec(line);
    if (m && /^T[0-9a-f]+,/.test(m[2])) return line;
    const payload = m ? m[2] : line;
    const r = filterJsonText(payload, state);
    if (!r) return line;
    if (r.drop) return null;
    return m ? m[1] + ':' + r.text : r.text;
  }

  /**
   * Split a text stream into units on `separator` (a global regex) and
   * filter each. Scanning resumes near where it stopped, so a huge single
   * line costs linear, not quadratic, time.
   */
  function makeStreamFilter(separator, filterUnit) {
    const decoder = new TextDecoder();
    const encoder = new TextEncoder();
    const state = newStreamState();
    let buffer = '';
    let scanFrom = 0;
    function emit(unit, controller, trailer) {
      if (!enabled) { controller.enqueue(encoder.encode(unit + trailer)); return; }
      let out;
      try { out = filterUnit(unit, state); } catch (_) { out = unit; }
      if (out !== null) controller.enqueue(encoder.encode(out + trailer));
    }
    return new TransformStream({
      transform(chunk, controller) {
        buffer += decoder.decode(chunk, { stream: true });
        for (;;) {
          separator.lastIndex = scanFrom;
          const m = separator.exec(buffer);
          if (!m) break;
          const unit = buffer.slice(0, m.index);
          buffer = buffer.slice(m.index + m[0].length);
          scanFrom = 0;
          emit(unit, controller, m[0]);
        }
        scanFrom = Math.max(0, buffer.length - 4);
      },
      flush(controller) {
        buffer += decoder.decode();
        if (buffer) emit(buffer, controller, '');
      }
    });
  }

  /**
   * JSON bodies. A top-level array is filtered element by element as it
   * arrives (chunked JSON-array streams keep streaming). An object is
   * buffered, up to a cap past which it passes through. Anything else
   * (length-prefixed frames, plain text mislabelled as JSON) passes through
   * at once. Unchanged and passed-through bodies keep their original bytes.
   */
  function makeJsonFilter() {
    const decoder = new TextDecoder();
    const encoder = new TextEncoder();
    const state = newStreamState();
    let buf = '';
    let raw = [];     // original chunks, kept while they may be forwarded as-is
    let rawLen = 0;
    let mode = null;  // null | 'array' | 'whole' | 'pass'
    // Array scanner state.
    let depth = 0, inStr = false, esc = false, elemStart = -1, pos = 0, wroteElem = false;

    const out = (controller, str) => { if (str) controller.enqueue(encoder.encode(str)); };
    const flushRaw = controller => { for (const c of raw) controller.enqueue(c); raw = []; rawLen = 0; };

    function decide(controller) {
      const x = XSSI.exec(buf);
      const rest = x ? buf.slice(x[0].length) : buf;
      const lead = /^\s*/.exec(rest)[0];
      if (lead.length === rest.length) return; // need more bytes
      const first = rest[lead.length];
      if (first === '[') {
        mode = 'array';
        raw = []; rawLen = 0;
        out(controller, (x ? x[0] : '') + lead);
        buf = rest.slice(lead.length);
      } else if (first === '{') {
        mode = 'whole';
      } else {
        mode = 'pass';
        flushRaw(controller);
        buf = '';
      }
    }

    function emitElement(controller, rawElem) {
      const trimmed = rawElem.trim();
      if (!trimmed) return;
      let text = trimmed;
      if (enabled) {
        let r = null;
        try { r = filterJsonText(trimmed, state); } catch (_) { r = null; }
        if (r && r.drop) return;
        if (r) text = r.text;
      }
      out(controller, (wroteElem ? ',' : '') + text);
      wroteElem = true;
    }

    function scanArray(controller) {
      for (; pos < buf.length; pos++) {
        const ch = buf[pos];
        if (inStr) {
          if (esc) esc = false;
          else if (ch === '\\') esc = true;
          else if (ch === '"') inStr = false;
          continue;
        }
        if (ch === '"') { inStr = true; continue; }
        if (ch === '[' || ch === '{') {
          depth++;
          if (depth === 1) { out(controller, '['); elemStart = pos + 1; }
          continue;
        }
        if (ch === ']' || ch === '}') {
          depth--;
          if (depth === 0) {
            emitElement(controller, buf.slice(elemStart, pos));
            out(controller, ']' + buf.slice(pos + 1));
            buf = '';
            pos = 0;
            mode = 'pass';
            return;
          }
          continue;
        }
        if (ch === ',' && depth === 1) {
          emitElement(controller, buf.slice(elemStart, pos));
          elemStart = pos + 1;
        }
      }
      // Keep only the unfinished element.
      if (elemStart > 0) {
        buf = buf.slice(elemStart);
        pos -= elemStart;
        elemStart = 0;
      }
      if (buf.length > MAX_JSON_CHARS) {
        // One element too big to judge: give up filtering, keep the text.
        out(controller, (wroteElem ? ',' : '') + buf);
        buf = '';
        pos = 0;
        mode = 'pass';
      }
    }

    return new TransformStream({
      transform(chunk, controller) {
        if (mode === 'pass') { controller.enqueue(chunk); return; }
        buf += decoder.decode(chunk, { stream: true });
        if (mode !== 'array') { raw.push(chunk); rawLen += chunk.byteLength; }
        if (mode === null) decide(controller);
        if (mode === 'array') scanArray(controller);
        else if (mode === 'whole' && rawLen > MAX_JSON_CHARS) { mode = 'pass'; flushRaw(controller); buf = ''; }
      },
      flush(controller) {
        buf += decoder.decode();
        if (mode === null) decide(controller);
        if (mode === 'array') {
          scanArray(controller);
          // Unterminated array: pass what's left through as-is.
          if (mode === 'array') out(controller, (wroteElem && buf.trim() ? ',' : '') + buf);
        } else if (mode === 'whole') {
          let r = null;
          try { r = filterFramed(buf, state); } catch (_) { r = null; }
          if (r) out(controller, r.drop ? '{}' : r.text);
          else flushRaw(controller);
        } else {
          flushRaw(controller);
        }
      }
    });
  }

  function streamKind(contentType, headers) {
    const ct = (contentType || '').toLowerCase();
    if (ct.includes('text/event-stream')) return 'sse';
    if (ct.includes('text/x-component')) return 'lines';
    if (ct.includes('ndjson') || ct.includes('jsonl') || ct.includes('json-seq') || ct.includes('stream+json') ||
        ct.includes('json-lines') || ct.includes('json-stream')) return 'lines';
    if (headers && headers.get && headers.get('x-vercel-ai-data-stream')) return 'lines';
    if (ct.includes('json')) return 'json';
    return null;
  }

  function makeFilter(kind) {
    if (kind === 'sse') return makeStreamFilter(/\r?\n\r?\n/g, filterSseEvent);
    if (kind === 'lines') return makeStreamFilter(/\r?\n/g, filterLine);
    return makeJsonFilter();
  }

  /** Copy url/redirected/type onto a rebuilt response, clones included. */
  function withMeta(from, to) {
    for (const prop of ['url', 'redirected', 'type']) {
      try { Object.defineProperty(to, prop, { value: from[prop] }); } catch (_) { /* noop */ }
    }
    const nativeClone = to.clone;
    try {
      Object.defineProperty(to, 'clone', { value: function clone() { return withMeta(from, nativeClone.call(to)); } });
    } catch (_) { /* noop */ }
    return to;
  }

  function filterResponse(res) {
    try {
      if (!enabled || !res || !res.body || res.type === 'opaque' || res.status === 204 || res.status === 304) return res;
      const ct = res.headers.get('content-type') || '';
      const kind = streamKind(ct, res.headers);
      if (!kind) return res;
      // We decode as UTF-8; anything else passes through untouched.
      const charset = /charset\s*=\s*"?([\w-]+)/i.exec(ct);
      if (charset && !/^utf-?8$/i.test(charset[1])) return res;
      // The body is decoded and re-encoded: its length and encoding change.
      const headers = new Headers(res.headers);
      headers.delete('content-length');
      headers.delete('content-encoding');
      const body = res.body.pipeThrough(makeFilter(kind));
      return withMeta(res, new Response(body, { status: res.status, statusText: res.statusText, headers }));
    } catch (_) {
      return res;
    }
  }

  // ---------------------------------------------------------------------------
  // fetch
  // ---------------------------------------------------------------------------

  const blockedResponse = () => Promise.resolve(new Response(null, { status: 204 }));

  const nativeFetch = window.fetch;
  if (typeof nativeFetch === 'function') {
    window.fetch = function fetch(input, init) {
      if (!enabled) return nativeFetch.apply(this, arguments);
      const self = this;
      const args = arguments;
      const isRequest = typeof Request !== 'undefined' && input instanceof Request;
      let url = null;
      try { url = isRequest ? input.url : String(input); } catch (_) { /* noop */ }
      const method = String((init && init.method) || (isRequest && input.method) || 'GET').toUpperCase();
      const body = init && init.body;
      const kind = body != null || (method !== 'GET' && method !== 'HEAD') ? 'body' : 'get';

      if (isBlockedUrl(url, kind) || isBlockedBody(body, url, kind)) {
        report('tracker');
        return blockedResponse();
      }

      // Ad-measurement request options (Attribution Reporting, Topics).
      let callArgs = args;
      if (init && typeof init === 'object' && ('attributionReporting' in init || 'browsingTopics' in init)) {
        const clean = Object.assign({}, init);
        delete clean.attributionReporting;
        delete clean.browsingTopics;
        callArgs = [input, clean];
      }
      const send = () => nativeFetch.apply(self, callArgs).then(filterResponse);

      // Bodies we can only read asynchronously: a Request's own body, or
      // a small text-like Blob.
      let pending = null;
      if (readableBlob(body)) pending = body.text();
      else if (isRequest && body == null && method !== 'GET' && method !== 'HEAD' &&
               /json|text|x-www-form-urlencoded/i.test(input.headers.get('content-type') || '')) {
        try { pending = input.clone().text(); } catch (_) { pending = null; }
      }
      if (!pending) return send();
      return pending.then(
        text => (isBlockedText(text, idsApply(url, kind)) ? (report('tracker'), blockedResponse()) : send()),
        () => send()
      );
    };
  }

  // ---------------------------------------------------------------------------
  // XMLHttpRequest
  // ---------------------------------------------------------------------------

  const XHR = window.XMLHttpRequest && window.XMLHttpRequest.prototype;
  if (XHR) {
    const xhrInfo = new WeakMap(); // xhr -> { url, method }
    const xhrCache = new WeakMap(); // xhr -> filtered views
    const nativeOpen = XHR.open;
    const nativeSend = XHR.send;

    XHR.open = function open(method, url) {
      xhrInfo.set(this, { url, method: String(method || 'GET').toUpperCase() });
      xhrCache.delete(this);
      return nativeOpen.apply(this, arguments);
    };

    XHR.send = function send(body) {
      const info = xhrInfo.get(this) || {};
      const kind = body != null || (info.method && info.method !== 'GET' && info.method !== 'HEAD') ? 'body' : 'get';
      if (enabled && (isBlockedUrl(info.url, kind) || isBlockedBody(body, info.url, kind))) {
        report('tracker');
        // Never leaves the browser; settle the request so callers waiting
        // on it don't hang.
        const xhr = this;
        setTimeout(() => {
          try {
            xhr.dispatchEvent(new ProgressEvent('error'));
            xhr.dispatchEvent(new ProgressEvent('loadend'));
          } catch (_) { /* noop */ }
        }, 0);
        return undefined;
      }
      return nativeSend.apply(this, arguments);
    };

    const SEP = { sse: /\r?\n\r?\n/g, lines: /\r?\n/g };

    /**
     * Filtered text. For streamed formats the output is append-only (built
     * from complete units), so polyfills that slice by a running offset
     * keep working while the response is still loading.
     */
    function filteredText(xhr, raw) {
      if (!enabled || typeof raw !== 'string') return raw;
      let c = xhrCache.get(xhr);
      if (!c) { c = { state: newStreamState() }; xhrCache.set(xhr, c); }
      const kind = streamKind(xhr.getResponseHeader('content-type'));
      if (kind === 'json') {
        if (xhr.readyState !== 4) return raw;
        if (c.raw === raw) return c.out;
        const r = filterFramed(raw, c.state);
        c.raw = raw;
        c.out = r ? (r.drop ? '{}' : r.text) : raw;
        return c.out;
      }
      if (kind === 'sse' || kind === 'lines') {
        if (c.consumed === undefined) { c.consumed = 0; c.out = ''; }
        const unit = kind === 'sse' ? filterSseEvent : filterLine;
        const sep = SEP[kind];
        let rest = raw.slice(c.consumed);
        for (;;) {
          sep.lastIndex = 0;
          const m = sep.exec(rest);
          if (!m) break;
          const piece = rest.slice(0, m.index);
          let o;
          try { o = unit(piece, c.state); } catch (_) { o = piece; }
          if (o !== null) c.out += o + m[0];
          c.consumed += m.index + m[0].length;
          rest = rest.slice(m.index + m[0].length);
        }
        if (xhr.readyState === 4 && rest) {
          let o;
          try { o = unit(rest, c.state); } catch (_) { o = rest; }
          if (o !== null) c.out += o;
          c.consumed += rest.length;
        }
        return c.out;
      }
      return raw;
    }

    const textDesc = Object.getOwnPropertyDescriptor(XHR, 'responseText');
    if (textDesc && textDesc.get) {
      Object.defineProperty(XHR, 'responseText', {
        configurable: true,
        enumerable: textDesc.enumerable,
        get: function () { return filteredText(this, textDesc.get.call(this)); }
      });
    }

    const respDesc = Object.getOwnPropertyDescriptor(XHR, 'response');
    if (respDesc && respDesc.get) {
      Object.defineProperty(XHR, 'response', {
        configurable: true,
        enumerable: respDesc.enumerable,
        get: function () {
          const v = respDesc.get.call(this);
          const rt = this.responseType;
          if (rt === '' || rt === 'text') return filteredText(this, v);
          if (!enabled || this.readyState !== 4 || v == null) return v;
          let c = xhrCache.get(this);
          if (!c) { c = { state: newStreamState() }; xhrCache.set(this, c); }
          if (c.resp && c.resp.src === v) return c.resp.out;
          let out = v;
          try {
            if (rt === 'json' && typeof v === 'object') {
              const r = S.pruneAds(v);
              if (r.changed) { learn(r.collector); report('payload'); }
              out = r.removedAll ? {} : v;
            } else if (rt === 'arraybuffer' && v instanceof ArrayBuffer &&
                       streamKind(this.getResponseHeader('content-type')) === 'json' && v.byteLength <= MAX_JSON_CHARS) {
              const r = filterFramed(new TextDecoder('utf-8', { fatal: true }).decode(v), c.state);
              if (r) out = new TextEncoder().encode(r.drop ? '{}' : r.text).buffer;
            }
          } catch (_) { out = v; }
          c.resp = { src: v, out };
          return out;
        }
      });
    }
  }

  // ---------------------------------------------------------------------------
  // WebSocket + EventSource messages
  // ---------------------------------------------------------------------------

  const eventVerdict = new WeakMap();
  const targetState = new WeakMap();

  function isMessageSource(t) {
    return (typeof WebSocket !== 'undefined' && t instanceof WebSocket) ||
      (typeof EventSource !== 'undefined' && t instanceof EventSource);
  }

  /** Returns the event to deliver, or null to drop it. */
  function filterMessageEvent(ev) {
    if (!enabled || !ev) return ev;
    if (eventVerdict.has(ev)) return eventVerdict.get(ev);
    let out = ev;
    try {
      const target = ev.currentTarget || ev.target;
      let state = target && targetState.get(target);
      if (target && !state) { state = newStreamState(); targetState.set(target, state); }
      if (ev.type !== 'message' && AD_EVENT_NAME.test(ev.type)) {
        report('payload');
        out = null;
      } else {
        let data = ev.data;
        let binary = false;
        if (data instanceof ArrayBuffer && data.byteLength <= MAX_JSON_CHARS) {
          try { data = new TextDecoder('utf-8', { fatal: true }).decode(data); binary = true; } catch (_) { data = null; }
        }
        const r = typeof data === 'string' ? filterFramed(data, state) : null;
        if (r && r.drop) out = null;
        else if (r) {
          out = new MessageEvent(ev.type, {
            data: binary ? new TextEncoder().encode(r.text).buffer : r.text,
            origin: ev.origin, lastEventId: ev.lastEventId, source: ev.source, ports: ev.ports ? Array.from(ev.ports) : []
          });
          for (const prop of ['target', 'currentTarget', 'srcElement']) {
            try { Object.defineProperty(out, prop, { value: ev[prop] }); } catch (_) { /* noop */ }
          }
        }
      }
    } catch (_) { out = ev; }
    eventVerdict.set(ev, out);
    return out;
  }

  function wrapListener(listener) {
    if (typeof listener === 'function') {
      return function (ev) {
        const out = filterMessageEvent(ev);
        if (out) return listener.call(this, out);
      };
    }
    if (listener && typeof listener.handleEvent === 'function') {
      return function (ev) {
        const out = filterMessageEvent(ev);
        if (out) return listener.handleEvent(out);
      };
    }
    return listener;
  }

  // Patched on EventTarget itself, so EventTarget.prototype.addEventListener
  // .call(ws, ...) can't sidestep it. Non-socket targets pass straight through.
  const wrappedListeners = new WeakMap(); // listener -> wrapper
  const PASS_TYPES = new Set(['open', 'close', 'error']);
  EventTarget.prototype.addEventListener = function addEventListener(type, listener, options) {
    if (listener && !PASS_TYPES.has(type) && isMessageSource(this)) {
      let w = wrappedListeners.get(listener);
      if (!w) { w = wrapListener(listener); wrappedListeners.set(listener, w); }
      return nativeAddEventListener.call(this, type, w, options);
    }
    return nativeAddEventListener.call(this, type, listener, options);
  };
  EventTarget.prototype.removeEventListener = function removeEventListener(type, listener, options) {
    const w = listener && !PASS_TYPES.has(type) && isMessageSource(this) ? wrappedListeners.get(listener) : null;
    return nativeRemoveEventListener.call(this, type, w || listener, options);
  };

  function patchOnMessage(Ctor) {
    if (typeof Ctor !== 'function' || !Ctor.prototype) return;
    const proto = Ctor.prototype;
    const desc = Object.getOwnPropertyDescriptor(proto, 'onmessage');
    if (!desc || !desc.set) return;
    const handlers = new WeakMap();
    Object.defineProperty(proto, 'onmessage', {
      configurable: true,
      enumerable: desc.enumerable,
      get: function () { return handlers.has(this) ? handlers.get(this) : desc.get.call(this); },
      set: function (fn) {
        handlers.set(this, fn);
        desc.set.call(this, typeof fn === 'function' ? wrapListener(fn) : fn);
      }
    });
  }
  patchOnMessage(window.WebSocket);
  patchOnMessage(window.EventSource);

  // ---------------------------------------------------------------------------
  // Beacons, pixels, scripts, frames
  // ---------------------------------------------------------------------------

  if (typeof Navigator !== 'undefined' && Navigator.prototype.sendBeacon) {
    const nativeBeacon = Navigator.prototype.sendBeacon;
    Navigator.prototype.sendBeacon = function sendBeacon(url, data) {
      if (!enabled) return nativeBeacon.apply(this, arguments);
      if (isBlockedUrl(url, 'beacon') || isBlockedBody(data, url, 'beacon')) {
        report('tracker');
        return true; // pretend it was queued
      }
      // A JSON Blob (the usual analytics beacon) can only be read
      // asynchronously. While the page is visible, read it first; on
      // pagehide there's no time, so it goes as-is.
      if (readableBlob(data) && document.visibilityState === 'visible') {
        const nav = this;
        data.text().then(
          text => { if (isBlockedText(text, true)) report('tracker'); else nativeBeacon.call(nav, url, data); },
          () => nativeBeacon.call(nav, url, data)
        );
        return true;
      }
      return nativeBeacon.apply(this, arguments);
    };
  }

  function srcsetBlocked(value) {
    return String(value || '').split(',').some(part => isBlockedUrl(part.trim().split(/\s+/)[0], 'beacon'));
  }

  function patchSetter(Ctor, prop, check) {
    if (typeof Ctor !== 'function') return;
    const desc = Object.getOwnPropertyDescriptor(Ctor.prototype, prop);
    if (!desc || !desc.set) return;
    Object.defineProperty(Ctor.prototype, prop, {
      configurable: true,
      enumerable: desc.enumerable,
      get: desc.get,
      set: function (v) {
        if (enabled && check(v)) { report('tracker'); return; }
        desc.set.call(this, v);
      }
    });
  }
  const beaconUrl = v => isBlockedUrl(v, 'beacon');
  patchSetter(window.HTMLImageElement, 'src', beaconUrl);
  patchSetter(window.HTMLImageElement, 'srcset', srcsetBlocked);
  patchSetter(window.HTMLSourceElement, 'srcset', srcsetBlocked);
  patchSetter(window.HTMLScriptElement, 'src', beaconUrl);
  patchSetter(window.HTMLIFrameElement, 'src', beaconUrl);
  // Hyperlink-auditing pings and Attribution Reporting exist only to report
  // ad clicks/views back to the advertiser.
  patchSetter(window.HTMLAnchorElement, 'ping', () => true);
  patchSetter(window.HTMLAnchorElement, 'attributionSrc', () => true);
  patchSetter(window.HTMLImageElement, 'attributionSrc', () => true);
  patchSetter(window.HTMLScriptElement, 'attributionSrc', () => true);

  const SRC_TAGS = new Set(['IMG', 'SCRIPT', 'IFRAME', 'SOURCE']);
  const nativeSetAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function setAttribute(name, value) {
    if (enabled && typeof name === 'string') {
      const n = name.toLowerCase();
      if (n === 'ping' || n === 'attributionsrc') { report('tracker'); return; }
      if (SRC_TAGS.has(this.tagName)) {
        if (n === 'src' && isBlockedUrl(value, 'beacon')) { report('tracker'); return; }
        if (n === 'srcset' && srcsetBlocked(value)) { report('tracker'); return; }
      }
    }
    return nativeSetAttribute.apply(this, arguments);
  };

  // Closed shadow roots are invisible to querySelectorAll. Flag their hosts
  // so the isolated-world DOM pass knows to open them via
  // chrome.dom.openOrClosedShadowRoot. The page's encapsulation is untouched.
  if (typeof Element.prototype.attachShadow === 'function') {
    const nativeAttachShadow = Element.prototype.attachShadow;
    Element.prototype.attachShadow = function attachShadow(init) {
      const root = nativeAttachShadow.apply(this, arguments);
      if (init && init.mode === 'closed') {
        try { nativeSetAttribute.call(this, 'data-armorly-shadow', ''); } catch (_) { /* noop */ }
      }
      return root;
    };
  }

  // ---------------------------------------------------------------------------
  // Browser ad APIs (Privacy Sandbox): on-device auctions, interest groups,
  // ad topics. Stubs resolve like "no ad available".
  // ---------------------------------------------------------------------------

  function stub(target, name, impl) {
    if (!target || typeof target[name] !== 'function') return;
    const nativeFn = target[name];
    try {
      Object.defineProperty(target, name, {
        configurable: true,
        writable: true,
        value: function () { return enabled ? impl() : nativeFn.apply(this, arguments); }
      });
    } catch (_) { /* noop */ }
  }
  const navProto = typeof Navigator !== 'undefined' ? Navigator.prototype : null;
  stub(navProto, 'runAdAuction', () => { report('adapi'); return Promise.resolve(null); });
  stub(navProto, 'joinAdInterestGroup', () => { report('adapi'); return Promise.resolve(); });
  stub(navProto, 'leaveAdInterestGroup', () => Promise.resolve());
  stub(navProto, 'updateAdInterestGroups', () => undefined);
  stub(typeof Document !== 'undefined' ? Document.prototype : null, 'browsingTopics', () => Promise.resolve([]));
})();
