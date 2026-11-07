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

// ---------------------------------------------------------------------------
// Real AI-chat ad network payloads (shapes from each network's published
// SDK types / live SDK; see the PR for sources). Each must be pruned.
// ---------------------------------------------------------------------------

const NETWORK_PAYLOADS = {
  'Kontext preload': { sessionId: 's_9f1', bids: [{ bidId: 'b_7c2e4a91d0', code: 'inlineAd', revenue: 0.0042, impressionTrigger: 'immediate' }] },
  'Thrad response': { queryId: 'q_81f2', creative: { html: '<div>Acme</div>', css: '', clickUrl: 'https://ssp.thrads.ai/c/q_81f2' }, meta: { advertiser: 'Acme' } },
  'Gravity ad': [{ adText: 'Try Acme', brandName: 'Acme', url: 'https://acme.example', impUrl: 'https://api.trygravity.ai/i/1', clickUrl: 'https://api.trygravity.ai/c/1' }],
  'Imprezia append item': { ads: [{ trackingId: 'trk_123456789', advertiser: 'Trip.com', title: 'Tokyo hotels', url: 'https://go.imprezia.ai/go/x', trackerUrl: 'https://r.imprezia.net/t?id=trk_123456789' }] },
  'Lulu MCP result': { content: [{ type: 'text', text: '{"result":1}' }], structuredContent: { result: 1, sponsored: { label: 'Sponsored', text: 'Acme', url: 'https://ads.getlulu.dev/c/9f2a1c', impUrl: 'https://ads.getlulu.dev/i/9f2a1c' } }, _meta: { 'ads.getlulu.dev/sponsored': { label: 'Sponsored', text: 'Acme', url: 'https://ads.getlulu.dev/c/9f2a1c', impUrl: 'https://ads.getlulu.dev/i/9f2a1c' } } },
  'ChatAds envelope': { data: { status: 'filled', offers: [{ link_text: 'running shoes', url: 'https://www.amazon.com/dp/B0X?tag=chatads-20' }], requested: 1, returned: 1, billed: true }, meta: { request_id: 'req_1' } },
  'EarnLayer display ad': { id: 'ad1', impressionId: 'imp-123456789', title: 'Acme', url: 'https://acme.example', adType: 'banner' },
  'ChatGPT ad unit (stream)': { type: 'message', message: { type: 'single_advertiser_ad_unit', ads_request_id: 'adreq_1f2e', ads_spam_integrity_payload: 'gAAAA', advertiser_brand: { name: 'Grubhub' }, cards: [{ title: 'Order now', ad_data_token: 'eyJ' }] } },
  'OpenRTB 3.0 bid': { openrtb: { response: { seatbid: [{ bid: [{ id: 'b1', item: '1', price: 1.2, purl: 'https://x/win', media: { ad: { id: 'ad1' } } }] }] } } },
  'VAST in a field': { answer: 'hi', video: { vast: '<VAST version="4.0"><Ad><InLine><Impression><![CDATA[https://t.example/imp]]></Impression></InLine></Ad></VAST>' } },
  'AI SDK v5 data part': { parts: [{ type: 'text', text: 'hi' }, { type: 'data-ad', data: { title: 'Acme', url: 'https://a' } }] },
  'tracker map': { items: [{ title: 'Acme', url: 'https://a', trackers: { impression: ['https://t/i'], click: ['https://t/c'] } }] },
  'sponsored:"true"': { results: [{ sponsored: 'true', title: 'Acme', url: 'https://a' }] },
  'label + impression url': { cards: [{ label: 'Sponsored', title: 'Acme', impression_tracking_url: 'https://t/i' }] }
};
for (const [name, payload] of Object.entries(NETWORK_PAYLOADS)) {
  test(`pruneAds catches network payload: ${name}`, () => {
    const r = S.pruneAds(JSON.parse(JSON.stringify(payload)));
    assert.equal(r.changed, true);
  });
}

test('pruneAds strips an ad hidden in JSON-encoded string content (MCP text)', () => {
  const inner = JSON.stringify({ result: 'ok', sponsored: { label: 'Sponsored', url: 'https://a', impUrl: 'https://t/i' } });
  const v = { content: [{ type: 'text', text: inner }] };
  const r = S.pruneAds(v);
  assert.equal(r.changed, true);
  assert.deepEqual(JSON.parse(r.value.content[0].text), { result: 'ok' });
});

test('pruneAds drops a whole stream envelope instead of leaving a broken event', () => {
  const ev = { type: 'content_block_start', index: 1, content_block: { type: 'sponsored_message', url: 'https://a', ad_id: 'ad-123456789' } };
  assert.equal(S.pruneAds(ev).removedAll, true);
});

test('pruneAds survives deep nesting and huge primitive arrays', () => {
  let deep = { type: 'sponsored', url: 'https://a', ad_id: 'x' };
  for (let i = 0; i < 40; i++) deep = { child: deep };
  assert.equal(S.pruneAds(deep).changed, true);
  const big = { nums: new Array(150000).fill(1), ad: { type: 'sponsored', url: 'https://a', ad_id: 'x' } };
  assert.equal(S.pruneAds(big).changed, true);
});

test('pruneAds turns an ad React element (RSC row) into nothing', () => {
  const row = ['$', 'div', null, { children: [['$', 'p', null, { children: 'hi' }], ['$', 'AdCard', null, { type: 'sponsored', url: 'https://a', ad_id: 'ad-1' }]] }];
  const r = S.pruneAds(row);
  assert.equal(r.changed, true);
  assert.equal(r.value[3].children.length, 1);
});

// ---------------------------------------------------------------------------
// False positives the red-team found: must NOT be pruned or blocked.
// ---------------------------------------------------------------------------

const MUST_NOT_PRUNE = {
  'ad manager campaign list': { ads: [{ id: 1, name: 'My ad', status: 'ENABLED' }] },
  'CI promotion record': { promoted_build: { id: 7, sha: 'abc', env: 'prod' } },
  'UI variant ad': { variant: 'ad', label: 'Ad styles', url: '/design/ad' },
  'menu item labelled Sponsored': { label: 'Sponsored', url: '/settings/sponsored' },
  'auction site bid': { bid_id: 'b123', price: 12.5, url: 'https://auction.example/item/1' },
  'shipment tracking': { trackingId: '1Z999', trackingUrl: 'https://ups.example/track/1Z999' },
  'recommender impression id': { title: 'Movie', view_url: 'https://cdn/v', impression_id: 'imp-1' },
  'MCP outputTemplate meta': { _meta: { 'openai/outputTemplate': 'ui://widget/x.html' }, content: [] },
  'Anthropic text block start': { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } }
};
for (const [name, payload] of Object.entries(MUST_NOT_PRUNE)) {
  test(`pruneAds leaves alone: ${name}`, () => assert.equal(S.pruneAds(JSON.parse(JSON.stringify(payload))).changed, false));
}

const MUST_NOT_BLOCK_BODY = {
  'chat request carrying history with an ad': { messages: [{ role: 'assistant', content: [{ type: 'text', text: 'x' }, { type: 'sponsored', title: 'x', url: 'https://a' }] }, { role: 'user', content: 'next' }] },
  'auction click with bid id': { event: 'click', bid_id: 'b1' },
  'email shown with campaign id': { event: 'shown', campaign_id: 'c1' },
  'feed impression id': { type: 'impression', impression_id: 'i1' },
  'LangSmith run named click': { runs: [{ name: 'click', bid_id: 'b1' }] },
  'button action view': { action: 'view', item: 'settings' }
};
for (const [name, body] of Object.entries(MUST_NOT_BLOCK_BODY)) {
  test(`isAdEventPayload allows: ${name}`, () => assert.equal(S.isAdEventPayload(body), false));
}
test('isAdEventQuery allows ?action=view&placement_id=home', () => assert.equal(S.isAdEventQuery(new URLSearchParams('action=view&placement_id=home')), false));

const MUST_BLOCK_BODY = {
  'Segment "Ad Viewed"': { event: 'Ad Viewed', properties: { ad_id: 'a1' } },
  'Thrad impression': { type: 'impression', queryId: 'q1', impressionState: 'viewable' },
  'video ad started': { event: 'video_ad_started' },
  'batched impression with creative id': { batch: [{ type: 'impression', creative_id: 'c1' }] }
};
for (const [name, body] of Object.entries(MUST_BLOCK_BODY)) {
  test(`isAdEventPayload blocks: ${name}`, () => assert.equal(S.isAdEventPayload(body), true));
}

test('learned ids must look like ids (no poisoning with JSON fragments)', () => {
  const r = S.pruneAds([{ sponsored: true, url: 'https://a', crid: '"role":"user"', ad_id: 'ad-998877' }]);
  assert.equal(r.collector.ids.has('"role":"user"'), false);
  assert.equal(r.collector.ids.has('ad-998877'), true);
});

test('click ids from AI ad networks are paid-click markers', () => {
  assert.equal(S.isPaidClickUrl('https://shop.example/?kad_cid=123'), true);
  assert.equal(S.isPaidClickUrl('https://shop.example/?oppref=abc'), true);
});

// ---------------------------------------------------------------------------
// Labels: localized, evasions, and false positives
// ---------------------------------------------------------------------------

for (const t of ['Gesponsert', 'Sponsorisé', 'Patrocinado', 'Sponsorizzato', 'Gesponsord', 'Sponsorowane', 'Спонсировано', 'Sponsorlu', '広告', '광고', '广告', '贊助', 'ממומן', 'प्रायोजित', 'Được tài trợ']) {
  test(`isDisclosureLabel catches localized: ${t}`, () => assert.equal(S.isDisclosureLabel(t), true));
}
test('ambiguous localized labels need the page language', () => {
  assert.equal(S.isDisclosureLabel('Anzeige', 'de'), true);
  assert.equal(S.isDisclosureLabel('Anzeige', 'en'), false);
  assert.equal(S.isDisclosureLabel('Реклама', 'ru-RU'), true);
  assert.equal(S.isDisclosureLabel('Реклама'), false);
});
for (const t of ['Ad 1 of 3', 'Sponsored · 2/3', 'Ad (1/3)', 'S p o n s o r e d', '‮derosnops', 'ꜱponsored']) {
  test(`isDisclosureLabel catches evasion: ${JSON.stringify(t)}`, () => assert.equal(S.isDisclosureLabel(t), true));
}
for (const t of ['AD', 'Ad5', '@d', 'ADS', 'PR', '提供']) {
  test(`isDisclosureLabel ignores look-alike: ${JSON.stringify(t)}`, () => assert.equal(S.isDisclosureLabel(t), false));
}
for (const t of ['AD: Alzheimer disease, a progressive disorder', 'PROMOTED: v2.1 to stable', 'PR: fixes #12']) {
  test(`isDisclosurePrefix ignores: ${JSON.stringify(t)}`, () => assert.equal(S.isDisclosurePrefix(t), false));
}
for (const t of ['【広告】Acme hotels', '[PR] Acme', 'Gesponsert: Acme']) {
  test(`isDisclosurePrefix catches localized: ${JSON.stringify(t)}`, () => assert.equal(S.isDisclosurePrefix(t), true));
}

// ---------------------------------------------------------------------------
// Code-review regressions
// ---------------------------------------------------------------------------

test('pruneAds keeps an ad manager campaign list even with urls', () => {
  const v = { ads: [{ id: 1, name: 'Spring sale', status: 'ENABLED', url: 'https://shop.example/spring' }] };
  assert.equal(S.pruneAds(v).changed, false);
});
test('pruneAds keeps promoted_by / sponsored_by attribution', () => {
  assert.equal(S.pruneAds({ promoted_by: { id: 7, url: 'https://ci.example/u/7' } }).changed, false);
  assert.equal(S.pruneAds({ sponsored_by: { name: 'NIH', url: 'https://nih.gov' } }).changed, false);
});
test('pruneAds never rewrites JSON a user pasted into their own message', () => {
  const pasted = JSON.stringify({ seatbid: [{ bid: [{ impid: '1', adm: '<div/>', nurl: 'https://x' }] }] });
  const v = { messages: [{ role: 'user', content: pasted }] };
  const r = S.pruneAds(v);
  assert.equal(r.changed, false);
  assert.equal(v.messages[0].content, pasted);
});
test('unwrapClickRedirect leaves logout / SSO redirects alone', () => {
  assert.equal(S.unwrapClickRedirect('https://auth.example.com/logout/redirect?redirect_uri=https://app.example.com/'), null);
  assert.equal(S.unwrapClickRedirect('https://sso.example.com/go?to=https://app.example.com/'), null);
});
test('unwrapClickRedirect still unwraps a generic click path that carries an ad click id', () => {
  assert.equal(S.unwrapClickRedirect('https://trk.example/click?gclid=1&url=https://shop.example/'), 'https://shop.example/');
});
