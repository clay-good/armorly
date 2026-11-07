// Unit tests for extension/lib/ad-signatures.js (node:test, no deps).
// Run: npm run test:unit
//
// Two tables per classifier: shapes that MUST be caught (real ad formats)
// and shapes that must NOT be (the everyday JSON / text of chat apps and
// the wider web). The second table is what keeps the extension safe to
// run on every page.

const test = require('node:test');
const assert = require('node:assert/strict');
const S = require('../../extension/lib/ad-signatures.js');

// ---------------------------------------------------------------------------
// isAdObject
// ---------------------------------------------------------------------------

const AD_OBJECTS = {
  'OpenRTB bid response': { id: 'req-1', seatbid: [{ bid: [{ id: 'b1', impid: '1', price: 1.5, adm: '<div/>' }] }] },
  'OpenRTB bid': { id: 'b1', impid: '1', price: 2.1, crid: 'cr-1', adm: '<div>ad</div>' },
  'OpenRTB bid (notices only)': { impid: '1', nurl: 'https://x/win', burl: 'https://x/bill' },
  'OpenRTB Native response': { native: { assets: [], imptrackers: ['https://x/imp'] } }.native,
  'Native eventtrackers': { assets: [], eventtrackers: [{ event: 1, method: 1, url: 'https://x/v' }] },
  'flag + tracker': { sponsored: true, title: 'Acme', impression_url: 'https://x/i' },
  'is_ad + link': { is_ad: true, title: 'Acme', url: 'https://acme.example' },
  'isSponsored + creative id': { isSponsored: true, creativeId: 'c-1' },
  'type sponsored_product + link': { type: 'sponsored_product', title: 'Mouse', url: 'https://shop.example' },
  'type ad + click url': { type: 'ad', headline: 'Loans', click_url: 'https://x/c' },
  'kind promoted_result + ad id': { kind: 'promoted_result', ad_id: 'a-1' },
  'proof url + ad id (no flag)': { title: 'Acme', view_url: 'https://x/v', creative_id: 'cr-9' },
  'impression trackers array': { title: 'Acme', impressionTrackers: ['https://x/i'] }
};

const NOT_AD_OBJECTS = {
  'OpenAI chat chunk': { id: 'chatcmpl-1', object: 'chat.completion.chunk', choices: [{ index: 0, delta: { content: 'Hi' } }] },
  'Anthropic stream delta': { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'Hi' } },
  'AI SDK text delta': { type: 'text-delta', id: 't1', delta: 'Hello' },
  'AI SDK tool result': { type: 'tool-result', toolCallId: 'c1', result: { url: 'https://docs.example', title: 'Docs' } },
  'search result with link': { title: 'Logitech review', url: 'https://reviews.example', snippet: 'Great mouse' },
  'citation': { type: 'citation', url: 'https://en.wikipedia.org/wiki/Mouse', title: 'Mouse' },
  'sponsored: false': { sponsored: false, title: 'Acme', url: 'https://acme.example' },
  'type ad with nothing else': { type: 'ad' },
  'user record': { id: 42, login: 'octocat', type: 'User', url: 'https://api.example/users/42' },
  'admin flag': { admin: true, url: 'https://x' },
  'page view analytics': { event: 'page_view', path: '/' },
  'single rtb-ish key': { adm: 'x' },
  'tracking url without ad id': { title: 'Order', tracking_url: 'https://ups.example/track/1Z' },
  'empty object': {}
};

for (const [name, obj] of Object.entries(AD_OBJECTS)) {
  test(`isAdObject catches: ${name}`, () => assert.equal(S.isAdObject(obj), true));
}
for (const [name, obj] of Object.entries(NOT_AD_OBJECTS)) {
  test(`isAdObject ignores: ${name}`, () => assert.equal(S.isAdObject(obj), false));
}

// ---------------------------------------------------------------------------
// pruneAds
// ---------------------------------------------------------------------------

test('pruneAds removes ad array items and keeps the rest', () => {
  const v = { blocks: [{ type: 'text', text: 'real' }, { type: 'sponsored', title: 'Acme', url: 'https://a', ad_id: 'ad-12345678' }] };
  const r = S.pruneAds(v);
  assert.equal(r.changed, true);
  assert.deepEqual(r.value, { blocks: [{ type: 'text', text: 'real' }] });
  assert.ok(r.collector.ids.has('ad-12345678'));
});

test('pruneAds removes an ad-named container key', () => {
  const v = { answer: 'real', ad: { headline: 'Acme', cta_url: 'https://a' }, sources: [] };
  const r = S.pruneAds(v);
  assert.deepEqual(r.value, { answer: 'real', sources: [] });
});

test('pruneAds keeps empty/null ad containers (nothing to remove)', () => {
  const v = { answer: 'real', ads: [], ad: null };
  const r = S.pruneAds(v);
  assert.equal(r.changed, false);
});

test('pruneAds reports a root-level ad', () => {
  const r = S.pruneAds({ seatbid: [] });
  assert.equal(r.removedAll, true);
});

test('pruneAds learns tracker URLs, including nested eventtrackers', () => {
  const r = S.pruneAds([{ imptrackers: ['https://t.example/imp'], eventtrackers: [{ event: 1, url: 'https://t.example/view' }], nurl: 'https://t.example/win' }]);
  assert.ok(r.collector.urls.has('https://t.example/imp'));
  assert.ok(r.collector.urls.has('https://t.example/view'));
  assert.ok(r.collector.urls.has('https://t.example/win'));
});

test('pruneAds does not learn plain message ids or short ids', () => {
  const r = S.pruneAds([{ id: 'msg_0123456789', type: 'sponsored', url: 'https://a', crid: 'c1' }]);
  assert.equal(r.collector.ids.has('msg_0123456789'), false);
  assert.equal(r.collector.ids.has('c1'), false);
});

test('pruneAds leaves an ordinary chat payload untouched', () => {
  const v = { id: 'msg_1', role: 'assistant', content: [{ type: 'text', text: 'hi' }], citations: [{ url: 'https://x', title: 'X' }] };
  const before = JSON.stringify(v);
  const r = S.pruneAds(v);
  assert.equal(r.changed, false);
  assert.equal(JSON.stringify(r.value), before);
});

// ---------------------------------------------------------------------------
// Outgoing requests
// ---------------------------------------------------------------------------

test('isAdEventQuery: explicit ad event', () => assert.equal(S.isAdEventQuery(new URLSearchParams('event=ad_impression')), true));
test('isAdEventQuery: delivery event + ad id', () => assert.equal(S.isAdEventQuery(new URLSearchParams('e=impression&ad_id=1')), true));
test('isAdEventQuery: delivery event alone is not enough', () => assert.equal(S.isAdEventQuery(new URLSearchParams('event=click&page=2')), false));
test('isAdEventQuery: page view', () => assert.equal(S.isAdEventQuery(new URLSearchParams('event=page_view')), false));

test('isAdEventPayload: explicit ad event', () => assert.equal(S.isAdEventPayload({ event: 'ad_click' }), true));
test('isAdEventPayload: batched events', () => assert.equal(S.isAdEventPayload({ events: [{ type: 'impression', creative_id: 'c' }] }), true));
test('isAdEventPayload: page view', () => assert.equal(S.isAdEventPayload({ event: 'page_view', path: '/' }), false));
test('isAdEventPayload: generic click without ad id', () => assert.equal(S.isAdEventPayload({ event: 'click', target: 'send' }), false));

test('hasRtbMacro', () => {
  assert.equal(S.hasRtbMacro('https://x/win?p=${AUCTION_PRICE}'), true);
  assert.equal(S.hasRtbMacro('https://x/win?p=%24%7BAUCTION_PRICE%7D'), true);
  assert.equal(S.hasRtbMacro('https://x/?price=1.2'), false);
});

// ---------------------------------------------------------------------------
// Links
// ---------------------------------------------------------------------------

test('isPaidClickUrl', () => {
  assert.equal(S.isPaidClickUrl('https://a.example/?utm_medium=cpc'), true);
  assert.equal(S.isPaidClickUrl('https://a.example/?gclid=x'), true);
  assert.equal(S.isPaidClickUrl('https://a.example/?utm_medium=email'), false);
  assert.equal(S.isPaidClickUrl('https://a.example/?page=2'), false);
});

test('unwrapClickRedirect: ad click path with destination', () => {
  assert.equal(S.unwrapClickRedirect('https://ads.example/aclk?adurl=https%3A%2F%2Facme.example%2Fx'), 'https://acme.example/x');
});
test('unwrapClickRedirect: tracker host with destination', () => {
  const isTracker = h => h === 'trk.example';
  assert.equal(S.unwrapClickRedirect('https://trk.example/c/123?url=https://acme.example/', isTracker), 'https://acme.example/');
});
test('unwrapClickRedirect: ordinary redirect paths are left alone', () => {
  assert.equal(S.unwrapClickRedirect('https://www.google.com/url?q=https://example.org'), null);
  assert.equal(S.unwrapClickRedirect('https://example.org/login?redirect=https://example.org/home'), null);
});
test('unwrapClickRedirect: same-host destination is left alone', () => {
  assert.equal(S.unwrapClickRedirect('https://shop.example/click?url=https://shop.example/item'), null);
});

// ---------------------------------------------------------------------------
// Disclosure labels
// ---------------------------------------------------------------------------

const LABELS = ['Sponsored', 'SPONSORED', 'Ad', 'Ads', 'Advertisement', 'Promoted', 'Sponsored ·', '(Ad)',
  'Sponsored result', 'Sponsored by Acme', 'Ads by Acme', 'Paid partnership', 'Promoted content',
  'Spon​sored', 'Ѕроnѕоrеd', 'Sp0ns0red', 'S­ponsored', 'Ｓｐｏｎｓｏｒｅｄ'];
const NOT_LABELS = ['Paid', 'Sponsor', 'Advertising', 'Advertise with us', 'Adobe', 'Add', 'Admin',
  'This study was sponsored by NIH', 'Promoted to manager', 'Ad hoc', 'Sponsored by a very long name that goes on and on and on and on forever'];

for (const t of LABELS) test(`isDisclosureLabel catches: ${JSON.stringify(t)}`, () => assert.equal(S.isDisclosureLabel(t), true));
for (const t of NOT_LABELS) test(`isDisclosureLabel ignores: ${JSON.stringify(t)}`, () => assert.equal(S.isDisclosureLabel(t), false));

const PREFIXED = ['Sponsored: Try Acme', '[Ad] Acme shoes', '(Sponsored) Acme', 'Promoted — Acme', 'Ad | Acme'];
const NOT_PREFIXED = ['Ad hoc analysis', 'Sponsored content is labeled on this site', 'Promoted to manager', 'Advertisement history: a book'];

for (const t of PREFIXED) test(`isDisclosurePrefix catches: ${JSON.stringify(t)}`, () => assert.equal(S.isDisclosurePrefix(t), true));
for (const t of NOT_PREFIXED) test(`isDisclosurePrefix ignores: ${JSON.stringify(t)}`, () => assert.equal(S.isDisclosurePrefix(t), false));
