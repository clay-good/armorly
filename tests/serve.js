// Tiny static server for Playwright fixtures.
// Intentionally dependency-free so the test harness only needs Playwright.
//
// Besides static files it plays the part of a chatbot backend that runs
// its own ad auction and stitches the winning ad into its responses
// (the "server-side / OpenRTB" model). Every tracker URL it hands out
// points back here under /t/..., and /__hits reports how many times each
// was actually requested — the ground truth for "did the advertiser get
// proof of delivery?".

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = path.resolve(__dirname, 'fixtures');
const PORT = 8421;
const ORIGIN = `http://127.0.0.1:${PORT}`;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml'
};

// ---------------------------------------------------------------------------
// Hit counter
// ---------------------------------------------------------------------------

let hits = {};
function hit(key) { hits[key] = (hits[key] || 0) + 1; }

// ---------------------------------------------------------------------------
// Ad payloads, one shape per delivery channel. Each is recognised by a
// different structural rule in extension/lib/ad-signatures.js.
// ---------------------------------------------------------------------------

const t = (name, src) => `${ORIGIN}/t/${name}?src=${src}`;

const LEGIT_TEXT = 'The Logitech MX Master 3S is the best all-round wireless mouse for a Mac.';

// JSON: object that declares itself sponsored and carries a tracker.
const jsonChat = {
  id: 'msg_01',
  role: 'assistant',
  blocks: [
    { type: 'text', text: LEGIT_TEXT },
    {
      type: 'sponsored_product',
      title: 'AD:json PrecisionGlide Mouse',
      url: 'https://shop.example/precisionglide',
      impression_url: t('imp', 'json'),
      // Fired later as an <img> parsed from innerHTML: only the
      // background's tab-scoped rule can stop that one.
      view_url: t('view', 'html'),
      ad_id: 'ad-json-90817263'
    },
    {
      // Poisoned: names the site's own API as its tracker and a JSON
      // fragment as its id. Blocking either would break the chat.
      type: 'sponsored',
      title: 'AD:json-poison',
      url: 'https://evil.example',
      view_url: `${ORIGIN}/api/xhr.json`,
      crid: '"role":"user"'
    }
  ]
};

// SSE: OpenRTB Native ad (imptrackers/eventtrackers) mid-stream, plus a
// named `event: sponsored` frame.
const sseEvents = [
  { data: { type: 'text-delta', delta: 'The Logitech MX Master 3S ' } },
  {
    data: {
      type: 'message-annotation',
      native: {
        assets: [{ id: 1, title: { text: 'AD:sse TravelNest Tokyo' } }],
        link: { url: 'https://travelnest.example/tokyo', clicktrackers: [t('click', 'sse')] },
        imptrackers: [t('imp', 'sse')],
        eventtrackers: [{ event: 1, method: 1, url: t('view', 'sse') }]
      }
    }
  },
  { event: 'sponsored', data: { title: 'AD:sse-named QuickLoans', impression_url: t('imp', 'sse-named') } },
  { data: { type: 'text-delta', delta: 'is the best all-round wireless mouse for a Mac.' } },
  { data: '[DONE]', raw: true }
];

// NDJSON: an OpenRTB bid with nurl/burl (win + billing notices).
const ndjsonLines = [
  { type: 'text', text: LEGIT_TEXT },
  {
    id: 'bid-55e0a1b2c3',
    impid: 'imp-1',
    price: 2.15,
    crid: 'cr-7f3a9c21aa',
    adomain: ['acme.example'],
    adm: '<div>AD:ndjson Acme Shoes</div>',
    nurl: t('win', 'ndjson'),
    burl: t('bill', 'ndjson')
  }
];

// AI-SDK data stream: ad delivered as a message annotation under an "ad" key.
const aiSdkLines = [
  '0:' + JSON.stringify('The Logitech MX Master 3S '),
  '8:' + JSON.stringify([{ ad: { headline: 'AD:aisdk CloudVPN', cta_url: 'https://vpn.example', view_url: t('view', 'aisdk') } }]),
  '0:' + JSON.stringify('is the best all-round wireless mouse for a Mac.'),
  'd:' + JSON.stringify({ finishReason: 'stop' })
];

// WebSocket: a whole OpenRTB bid response.
const wsMessages = [
  { type: 'text', text: LEGIT_TEXT },
  {
    id: 'auction-1',
    seatbid: [{ bid: [{ id: 'bid-ws-77aa88bb', impid: '1', price: 1.2, adm: 'AD:ws BrightBank', nurl: t('win', 'ws') }] }]
  }
];

// XHR: a search-style list with one flagged result.
const xhrResults = {
  results: [
    { title: 'Logitech MX Master 3S review', url: 'https://reviews.example/mx3s' },
    {
      is_sponsored: true,
      title: 'AD:xhr MegaMouse',
      url: 'https://megamouse.example',
      click_tracker: t('click', 'xhr'),
      impression_url: t('imp', 'xhr'),
      creative_id: 'cr-xhr-11223344'
    }
  ]
};

// Socket.IO-framed messages (Engine.IO "42" event packets).
const ioMessages = [
  '0{"sid":"abc","upgrades":[],"pingInterval":25000,"pingTimeout":20000}',
  '40',
  '42' + JSON.stringify(['msg', { type: 'text', text: LEGIT_TEXT }]),
  '42' + JSON.stringify(['msg', { type: 'sponsored', title: 'AD:io QuickLoans', url: 'https://loans.example', impression_url: t('imp', 'io') }])
];

// Binary frames: JSON sent as bytes.
const binMessages = [
  { type: 'text', text: LEGIT_TEXT },
  { is_ad: true, title: 'AD:bin CloudCam', url: 'https://cam.example', impression_url: t('imp', 'bin') }
];

// React Server Components rows.
const rscRows = [
  '0:' + JSON.stringify(['$', 'p', null, { children: LEGIT_TEXT }]),
  '1:' + JSON.stringify({ type: 'sponsored', title: 'AD:rsc FlyNow', url: 'https://fly.example', impression_url: t('imp', 'rsc') }),
  '2:T1c,plain text row, untouched'
];

// A JSON array streamed element by element.
const jsonArrayParts = [
  '[' + JSON.stringify({ type: 'text', text: 'The Logitech MX Master 3S ' }),
  ',' + JSON.stringify({ type: 'sponsored', title: 'AD:jsonarr TentCo', url: 'https://tent.example', impression_url: t('imp', 'jsonarr') }),
  ',' + JSON.stringify({ type: 'text', text: 'is the best all-round wireless mouse for a Mac.' }) + ']'
];

// Anthropic-style message stream with a sponsored content block at index 1.
const anthropicEvents = [
  { event: 'message_start', data: { type: 'message_start', message: { id: 'msg_1', content: [] } } },
  { event: 'content_block_start', data: { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } } },
  { event: 'content_block_delta', data: { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'The Logitech MX Master 3S ' } } },
  { event: 'content_block_stop', data: { type: 'content_block_stop', index: 0 } },
  { event: 'content_block_start', data: { type: 'content_block_start', index: 1, content_block: { type: 'sponsored_message', text: 'AD:anth ', url: 'https://acme.example', ad_id: 'ad-anth-5544332211', impression_url: t('imp', 'anth') } } },
  { event: 'content_block_delta', data: { type: 'content_block_delta', index: 1, delta: { type: 'text_delta', text: 'AD:anth-delta Acme' } } },
  { event: 'content_block_stop', data: { type: 'content_block_stop', index: 1 } },
  { event: 'content_block_start', data: { type: 'content_block_start', index: 2, content_block: { type: 'text', text: '' } } },
  { event: 'content_block_delta', data: { type: 'content_block_delta', index: 2, delta: { type: 'text_delta', text: 'is the best all-round wireless mouse for a Mac.' } } },
  { event: 'content_block_stop', data: { type: 'content_block_stop', index: 2 } },
  { event: 'message_stop', data: { type: 'message_stop' } }
];

// ---------------------------------------------------------------------------
// Minimal WebSocket server (RFC 6455, unmasked text frames out, enough of
// the inbound side to ignore client frames). Keeps the harness dep-free.
// ---------------------------------------------------------------------------

function wsFrame(text, binary) {
  const payload = Buffer.from(text);
  const len = payload.length;
  const op = binary ? 0x82 : 0x81;
  let header;
  if (len < 126) header = Buffer.from([op, len]);
  else if (len < 65536) { header = Buffer.alloc(4); header[0] = op; header[1] = 126; header.writeUInt16BE(len, 2); }
  else { header = Buffer.alloc(10); header[0] = op; header[1] = 127; header.writeBigUInt64BE(BigInt(len), 2); }
  return Buffer.concat([header, payload]);
}

function handleUpgrade(req, socket) {
  if (!req.url.startsWith('/ws')) { socket.destroy(); return; }
  const accept = crypto
    .createHash('sha1')
    .update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
  );
  socket.on('error', () => {});
  socket.on('data', () => {}); // ignore client frames
  const path = req.url.split('?')[0];
  const frames = path === '/ws-io'
    ? ioMessages.map(m => wsFrame(m)).concat(wsFrame('42' + JSON.stringify(['done'])))
    : path === '/ws-bin'
      ? binMessages.map(m => wsFrame(JSON.stringify(m), true)).concat(wsFrame(JSON.stringify({ type: 'done' }), true))
      : wsMessages.map(m => wsFrame(JSON.stringify(m))).concat(wsFrame(JSON.stringify({ type: 'done' })));
  let i = 0;
  const timer = setInterval(() => {
    if (i < frames.length) socket.write(frames[i++]);
    else clearInterval(timer);
  }, 20);
  socket.on('close', () => clearInterval(timer));
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

function sendJson(res, obj, status = 200) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(obj));
}

function streamLines(res, lines, contentType, extraHeaders = {}) {
  res.statusCode = 200;
  res.setHeader('Content-Type', contentType);
  res.setHeader('Cache-Control', 'no-store');
  for (const [k, v] of Object.entries(extraHeaders)) res.setHeader(k, v);
  let i = 0;
  const tick = () => {
    if (i >= lines.length) { res.end(); return; }
    // Split each unit across two writes so the client sees chunk
    // boundaries in the middle of a frame.
    const s = lines[i++];
    const cut = Math.floor(s.length / 2);
    res.write(s.slice(0, cut));
    setTimeout(() => { res.write(s.slice(cut)); setTimeout(tick, 10); }, 5);
  };
  tick();
}

function readBody(req) {
  return new Promise(resolve => {
    let body = '';
    req.on('data', c => { body += c; if (body.length > 1e6) req.destroy(); });
    req.on('end', () => resolve(body));
  });
}

async function route(req, res) {
  const url = new URL(req.url, ORIGIN);
  const p = url.pathname;

  if (p === '/__hits') return sendJson(res, hits);
  if (p === '/__reset') { hits = {}; return sendJson(res, { ok: true }); }

  if (p.startsWith('/t/')) {
    // Tracker endpoint: /t/<kind>?src=<channel>
    hit(`${p.slice(3)}:${url.searchParams.get('src') || '-'}`);
    res.statusCode = 204;
    res.setHeader('Cache-Control', 'no-store');
    return res.end();
  }

  if (p === '/collect' || p === '/api/telemetry') {
    // First-party analytics endpoint. Bucket hits by the event name so
    // tests can tell ad events (should be blocked) from page views
    // (must still get through).
    const body = req.method === 'POST' ? await readBody(req) : '';
    let ev = url.searchParams.get('event') || '-';
    try { const j = JSON.parse(body); ev = j.event || j.kind || ev; } catch (_) { /* not JSON */ }
    hit(`${p.slice(1)}:${ev}`);
    res.statusCode = 204;
    return res.end();
  }

  if (p === '/api/chat.json') return sendJson(res, jsonChat);

  if (p === '/api/echo') {
    // Stands in for the chatbot's own "send message" endpoint.
    const body = await readBody(req);
    hit('api/echo');
    return sendJson(res, { ok: true, received: body.length });
  }

  if (p === '/api/xssi.json') {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    return res.end(")]}'\n" + JSON.stringify({ blocks: [{ type: 'text', text: LEGIT_TEXT }, { sponsored: true, title: 'AD:xssi SunTrips', url: 'https://sun.example', impression_url: t('imp', 'xssi') }] }));
  }

  if (p === '/api/stream.rsc') {
    return streamLines(res, rscRows.map(l => l + '\n'), 'text/x-component');
  }

  if (p === '/api/stream.jsonarray') {
    return streamLines(res, jsonArrayParts, 'application/json; charset=utf-8');
  }

  if (p === '/api/stream.anthropic') {
    const frames = anthropicEvents.map(e => `event: ${e.event}\ndata: ${JSON.stringify(e.data)}\n\n`);
    return streamLines(res, frames, 'text/event-stream; charset=utf-8');
  }
  if (p === '/api/xhr.json') return sendJson(res, xhrResults);

  if (p === '/api/stream.sse') {
    const frames = sseEvents.map(e => {
      const data = e.raw ? e.data : JSON.stringify(e.data);
      return (e.event ? `event: ${e.event}\n` : '') + `data: ${data}\n\n`;
    });
    return streamLines(res, frames, 'text/event-stream; charset=utf-8');
  }

  if (p === '/api/stream.ndjson') {
    return streamLines(res, ndjsonLines.map(l => JSON.stringify(l) + '\n'), 'application/x-ndjson');
  }

  if (p === '/api/stream.aisdk') {
    return streamLines(res, aiSdkLines.map(l => l + '\n'), 'text/plain; charset=utf-8', { 'x-vercel-ai-data-stream': 'v1' });
  }

  // Static files.
  const safePath = path.normalize(decodeURIComponent(p));
  const filePath = path.join(ROOT, safePath === '/' ? 'index.html' : safePath);
  if (!filePath.startsWith(ROOT)) {
    res.statusCode = 403;
    res.end('forbidden');
    return;
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.statusCode = 404;
      res.end('not found');
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    res.setHeader('Content-Type', MIME[ext] || 'application/octet-stream');
    res.end(data);
  });
}

const server = http.createServer((req, res) => {
  route(req, res).catch(() => { res.statusCode = 500; res.end(); });
});
server.on('upgrade', handleUpgrade);
server.listen(PORT, '127.0.0.1', () => {
  console.log(`[fixtures] ${ORIGIN}/`);
});
