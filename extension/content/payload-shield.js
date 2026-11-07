/**
 * Armorly - payload shield (MAIN world).
 *
 * Server-side / OpenRTB ads never load an ad SDK: the chatbot's own server
 * runs the auction and stitches the ad into its response. Network blocking
 * by domain can't see that. Two things still have to happen in the
 * browser, and this file intercepts both:
 *
 *   1. The ad has to reach the page as data. We filter JSON, Server-Sent
 *      Events, NDJSON, WebSocket and EventSource messages and drop every
 *      object that is an ad by structure (lib/ad-signatures.js), before
 *      the page's own code reads it.
 *   2. The advertiser has to get proof the ad was delivered. We block the
 *      impression pixels, beacons and win/billing notices: URLs learned
 *      from the ad objects we removed, requests that mention those ads'
 *      ids, ad-event analytics payloads, and known ad/verification hosts.
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

  // ---------------------------------------------------------------------------
  // Control channel with the isolated-world script
  //
  // Both content scripts run at document_start, before any page script.
  // Whichever runs first writes a random key to an attribute on <html>;
  // the other reads it and removes it. Page scripts never see the key, so
  // a page can't forge the "disable Armorly on this site" message.
  // ---------------------------------------------------------------------------

  const KEY_ATTR = 'data-armorly-bridge';
  let bridgeKey = null;
  try {
    const rootEl = document.documentElement;
    if (rootEl) {
      if (rootEl.hasAttribute(KEY_ATTR)) {
        bridgeKey = rootEl.getAttribute(KEY_ATTR);
        rootEl.removeAttribute(KEY_ATTR);
      } else {
        const buf = new Uint32Array(4);
        crypto.getRandomValues(buf);
        bridgeKey = Array.from(buf, n => n.toString(36)).join('');
        rootEl.setAttribute(KEY_ATTR, bridgeKey);
      }
    }
  } catch (_) { /* noop */ }

  window.addEventListener('message', function (event) {
    if (event.source !== window) return;
    const d = event.data;
    if (!d || d.source !== 'armorly' || !bridgeKey || d.key !== bridgeKey) return;
    if (d.type === 'disable-site') {
      enabled = false;
      if (sdkControl) sdkControl.disable();
    } else if (d.type === 'update-sdk-list') {
      if (sdkControl && Array.isArray(d.functions)) sdkControl.install(d.functions);
      if (Array.isArray(d.domains)) for (const h of d.domains) if (typeof h === 'string') adHosts.add(h.toLowerCase());
    }
  });

  function report(kind) {
    try { window.postMessage({ source: 'armorly', type: 'shield-blocked', kind }, '*'); } catch (_) { /* noop */ }
  }

  // ---------------------------------------------------------------------------
  // What to block
  // ---------------------------------------------------------------------------

  // Ad network + ad verification hosts. Verification vendors are how a
  // brand checks that a server-side ad was actually viewed.
  const adHosts = new Set(P.getAllSDKDomains().map(h => h.toLowerCase()));
  for (const h of (P.verificationDomains || [])) adHosts.add(h.toLowerCase());

  const learnedUrls = new Set(); // origin + pathname of tracker URLs
  const learnedIds = new Set();  // ids of ads we removed

  function isAdHost(hostname) {
    const h = hostname.toLowerCase();
    for (const d of adHosts) if (h === d || h.endsWith('.' + d)) return true;
    return false;
  }

  function toUrl(u) {
    try { return new URL(String(u), location.href); } catch (_) { return null; }
  }

  function learn(collector) {
    if (!collector) return;
    for (const raw of collector.urls) {
      const u = toUrl(raw);
      if (u && (u.protocol === 'http:' || u.protocol === 'https:')) learnedUrls.add(u.origin + u.pathname);
    }
    for (const id of collector.ids) learnedIds.add(id);
  }

  function mentionsLearnedId(text) {
    if (!learnedIds.size || typeof text !== 'string' || text.length > 65536) return false;
    for (const id of learnedIds) if (text.includes(id)) return true;
    return false;
  }

  function isBlockedUrl(raw) {
    if (!enabled || raw == null) return false;
    const u = toUrl(raw);
    if (!u || (u.protocol !== 'http:' && u.protocol !== 'https:')) return false;
    if (learnedUrls.has(u.origin + u.pathname)) return true;
    if (isAdHost(u.hostname)) return true;
    if (S.hasRtbMacro(u.href)) return true;
    if (u.search && S.isAdEventQuery(u.searchParams)) return true;
    if (u.search && mentionsLearnedId(decodeSafe(u.search))) return true;
    return false;
  }

  function decodeSafe(s) {
    try { return decodeURIComponent(s); } catch (_) { return s; }
  }

  function bodyText(body) {
    if (body == null) return null;
    if (typeof body === 'string') return body;
    if (body instanceof URLSearchParams) return body.toString();
    if (typeof FormData !== 'undefined' && body instanceof FormData) {
      const parts = [];
      body.forEach((v, k) => { if (typeof v === 'string') parts.push(k + '=' + v); });
      return parts.join('&');
    }
    return null; // Blob / ArrayBuffer / streams: not inspected.
  }

  function isBlockedBody(body) {
    if (!enabled) return false;
    const text = bodyText(body);
    if (!text || text.length > 65536) return false;
    if (mentionsLearnedId(text)) return true;
    const t = text.trim();
    if (t[0] === '{' || t[0] === '[') {
      try { return S.isAdEventPayload(JSON.parse(t)); } catch (_) { return false; }
    }
    if (t.includes('=')) {
      try { return S.isAdEventQuery(new URLSearchParams(t)); } catch (_) { return false; }
    }
    return false;
  }

  function shouldBlockRequest(url, body) {
    return isBlockedUrl(url) || isBlockedBody(body);
  }

  // ---------------------------------------------------------------------------
  // Payload filtering
  // ---------------------------------------------------------------------------

  const MAX_JSON_BYTES = 8 * 1024 * 1024;

  /** Returns null when unchanged, else { text } or { drop: true }. */
  function filterJsonText(text) {
    if (!enabled || typeof text !== 'string' || text.length > MAX_JSON_BYTES) return null;
    const t = text.trim();
    if (t[0] !== '{' && t[0] !== '[') return null;
    let value;
    try { value = JSON.parse(t); } catch (_) { return null; }
    const r = S.pruneAds(value);
    if (!r.changed) return null;
    learn(r.collector);
    report('payload');
    if (r.removedAll) return { drop: true };
    return { text: JSON.stringify(r.value) };
  }

  const AD_EVENT_NAME = /^(ad|ads|advert|advertisement|sponsored|promoted|ad[_-][\w-]+|sponsored[_-][\w-]+|promoted[_-][\w-]+)$/i;

  /** Filter one SSE event block (text between blank lines). */
  function filterSseEvent(block) {
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
    const r = filterJsonText(dataLines.join('\n'));
    if (!r) return block;
    if (r.drop) return null;
    return other.concat('data: ' + r.text).join('\n');
  }

  /** Filter one NDJSON / AI-SDK data-stream line ("0:..." / "8:[...]"). */
  function filterLine(line) {
    if (!line.trim()) return line;
    const m = /^([0-9a-z]{1,2}):(.*)$/.exec(line);
    const payload = m ? m[2] : line;
    const r = filterJsonText(payload);
    if (!r) return line;
    if (r.drop) return null;
    return m ? m[1] + ':' + r.text : r.text;
  }

  function makeStreamFilter(separator, filterUnit) {
    const decoder = new TextDecoder();
    const encoder = new TextEncoder();
    let buffer = '';
    function emit(unit, controller, trailer) {
      if (!enabled) { controller.enqueue(encoder.encode(unit + trailer)); return; }
      let out;
      try { out = filterUnit(unit); } catch (_) { out = unit; }
      if (out !== null) controller.enqueue(encoder.encode(out + trailer));
    }
    return new TransformStream({
      transform(chunk, controller) {
        buffer += decoder.decode(chunk, { stream: true });
        let m;
        while ((m = separator.exec(buffer))) {
          const unit = buffer.slice(0, m.index);
          const sep = m[0];
          buffer = buffer.slice(m.index + sep.length);
          separator.lastIndex = 0;
          emit(unit, controller, sep);
        }
      },
      flush(controller) {
        buffer += decoder.decode();
        if (buffer) emit(buffer, controller, '');
      }
    });
  }

  function streamKind(contentType, headers) {
    const ct = (contentType || '').toLowerCase();
    if (ct.includes('text/event-stream')) return 'sse';
    if (ct.includes('ndjson') || ct.includes('jsonl') || ct.includes('json-seq')) return 'lines';
    if (headers && headers.get('x-vercel-ai-data-stream')) return 'lines';
    if (ct.includes('json')) return 'json';
    return null;
  }

  function cloneResponseMeta(from, to) {
    for (const prop of ['url', 'redirected', 'type']) {
      try { Object.defineProperty(to, prop, { value: from[prop] }); } catch (_) { /* noop */ }
    }
    return to;
  }

  async function filterResponse(res) {
    try {
      if (!enabled || !res || !res.body || res.type === 'opaque' || res.status === 204) return res;
      const kind = streamKind(res.headers.get('content-type'), res.headers);
      if (!kind) return res;
      const init = { status: res.status, statusText: res.statusText, headers: res.headers };

      if (kind === 'json') {
        const len = Number(res.headers.get('content-length') || 0);
        if (len > MAX_JSON_BYTES) return res;
        const text = await res.clone().text();
        const r = filterJsonText(text);
        if (!r) return res;
        return cloneResponseMeta(res, new Response(r.drop ? '{}' : r.text, init));
      }

      const filter = kind === 'sse'
        ? makeStreamFilter(/\r?\n\r?\n/, filterSseEvent)
        : makeStreamFilter(/\r?\n/, filterLine);
      return cloneResponseMeta(res, new Response(res.body.pipeThrough(filter), init));
    } catch (_) {
      return res;
    }
  }

  // ---------------------------------------------------------------------------
  // fetch
  // ---------------------------------------------------------------------------

  const nativeFetch = window.fetch;
  if (typeof nativeFetch === 'function') {
    window.fetch = function fetch(input, init) {
      if (!enabled) return nativeFetch.apply(this, arguments);
      let url = null;
      try { url = (typeof Request !== 'undefined' && input instanceof Request) ? input.url : String(input); } catch (_) { /* noop */ }
      if (shouldBlockRequest(url, init && init.body)) {
        report('tracker');
        return Promise.resolve(new Response(null, { status: 204 }));
      }
      // Ad-measurement request options (Attribution Reporting, Topics).
      if (init && typeof init === 'object' && ('attributionReporting' in init || 'browsingTopics' in init)) {
        init = Object.assign({}, init);
        delete init.attributionReporting;
        delete init.browsingTopics;
        return nativeFetch.call(this, input, init).then(filterResponse);
      }
      return nativeFetch.apply(this, arguments).then(filterResponse);
    };
  }

  // ---------------------------------------------------------------------------
  // XMLHttpRequest
  // ---------------------------------------------------------------------------

  const XHR = window.XMLHttpRequest && window.XMLHttpRequest.prototype;
  if (XHR) {
    const xhrUrl = new WeakMap();
    const xhrBlocked = new WeakSet();
    const xhrFiltered = new WeakMap();
    const nativeOpen = XHR.open;
    const nativeSend = XHR.send;

    XHR.open = function open(method, url) {
      xhrUrl.set(this, url);
      return nativeOpen.apply(this, arguments);
    };

    XHR.send = function send(body) {
      if (enabled && shouldBlockRequest(xhrUrl.get(this), body)) {
        xhrBlocked.add(this);
        report('tracker');
        return undefined; // never leaves the browser
      }
      return nativeSend.apply(this, arguments);
    };

    function filteredText(xhr, raw) {
      if (!enabled || xhr.readyState !== 4 || typeof raw !== 'string') return raw;
      const cached = xhrFiltered.get(xhr);
      if (cached && cached.raw === raw) return cached.out;
      let out = raw;
      const kind = streamKind(xhr.getResponseHeader('content-type'));
      if (kind === 'json') {
        const r = filterJsonText(raw);
        if (r) out = r.drop ? '{}' : r.text;
      }
      xhrFiltered.set(xhr, { raw, out });
      return out;
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
      const prunedJson = new WeakSet();
      Object.defineProperty(XHR, 'response', {
        configurable: true,
        enumerable: respDesc.enumerable,
        get: function () {
          const v = respDesc.get.call(this);
          const rt = this.responseType;
          if (rt === '' || rt === 'text') return filteredText(this, v);
          if (rt === 'json' && enabled && v && typeof v === 'object' && !prunedJson.has(v)) {
            prunedJson.add(v);
            try {
              const r = S.pruneAds(v);
              if (r.changed) { learn(r.collector); report('payload'); }
              if (r.removedAll) return {};
            } catch (_) { /* noop */ }
          }
          return v;
        }
      });
    }
  }

  // ---------------------------------------------------------------------------
  // WebSocket + EventSource messages
  // ---------------------------------------------------------------------------

  const eventVerdict = new WeakMap();

  /** Returns the event to deliver, or null to drop it. */
  function filterMessageEvent(ev) {
    if (!enabled || !ev || typeof ev.data !== 'string') return ev;
    if (eventVerdict.has(ev)) return eventVerdict.get(ev);
    let out = ev;
    try {
      if (ev.type !== 'message' && AD_EVENT_NAME.test(ev.type)) {
        report('payload');
        out = null;
      } else {
        const r = filterJsonText(ev.data);
        if (r && r.drop) out = null;
        else if (r) {
          out = new MessageEvent(ev.type, {
            data: r.text, origin: ev.origin, lastEventId: ev.lastEventId, source: ev.source, ports: ev.ports ? Array.from(ev.ports) : []
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

  function patchMessageTarget(Ctor) {
    if (typeof Ctor !== 'function' || !Ctor.prototype) return;
    const proto = Ctor.prototype;
    const wrapped = new WeakMap(); // listener -> wrapper
    const nativeAdd = EventTarget.prototype.addEventListener;
    const nativeRemove = EventTarget.prototype.removeEventListener;

    proto.addEventListener = function addEventListener(type, listener, options) {
      if (listener && type !== 'open' && type !== 'close' && type !== 'error') {
        let w = wrapped.get(listener);
        if (!w) { w = wrapListener(listener); wrapped.set(listener, w); }
        return nativeAdd.call(this, type, w, options);
      }
      return nativeAdd.call(this, type, listener, options);
    };
    proto.removeEventListener = function removeEventListener(type, listener, options) {
      return nativeRemove.call(this, type, (listener && wrapped.get(listener)) || listener, options);
    };

    const desc = Object.getOwnPropertyDescriptor(proto, 'onmessage');
    if (desc && desc.set) {
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
  }

  patchMessageTarget(window.WebSocket);
  patchMessageTarget(window.EventSource);

  // ---------------------------------------------------------------------------
  // Beacons, pixels, scripts, frames
  // ---------------------------------------------------------------------------

  if (typeof Navigator !== 'undefined' && Navigator.prototype.sendBeacon) {
    const nativeBeacon = Navigator.prototype.sendBeacon;
    Navigator.prototype.sendBeacon = function sendBeacon(url, data) {
      if (enabled && shouldBlockRequest(url, data)) {
        report('tracker');
        return true; // pretend it was queued
      }
      return nativeBeacon.apply(this, arguments);
    };
  }

  function patchSrc(Ctor) {
    if (typeof Ctor !== 'function') return;
    const desc = Object.getOwnPropertyDescriptor(Ctor.prototype, 'src');
    if (!desc || !desc.set) return;
    Object.defineProperty(Ctor.prototype, 'src', {
      configurable: true,
      enumerable: desc.enumerable,
      get: desc.get,
      set: function (v) {
        if (enabled && isBlockedUrl(v)) { report('tracker'); return; }
        desc.set.call(this, v);
      }
    });
  }
  patchSrc(window.HTMLImageElement);
  patchSrc(window.HTMLScriptElement);
  patchSrc(window.HTMLIFrameElement);

  const SRC_TAGS = new Set(['IMG', 'SCRIPT', 'IFRAME']);
  const nativeSetAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function setAttribute(name, value) {
    if (enabled && typeof name === 'string') {
      const n = name.toLowerCase();
      // Hyperlink-auditing pings and Attribution Reporting exist only to
      // report ad clicks/views back to the advertiser.
      if (n === 'ping' || n === 'attributionsrc') { report('tracker'); return; }
      if (n === 'src' && SRC_TAGS.has(this.tagName) && isBlockedUrl(value)) { report('tracker'); return; }
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
