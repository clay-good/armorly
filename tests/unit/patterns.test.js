'use strict';
// Domain matching in extension/lib/ad-patterns.js.
const test = require('node:test');
const assert = require('node:assert');

globalThis.window = globalThis.window || {};
require('../../extension/lib/ad-patterns.js');
const P = globalThis.window.ArmorlyAdPatterns;

for (const u of ['https://t.co/abc', 'https://www.t.co/abc', 'https://amzn.to/x']) {
  test(`isAffiliateDomain matches the host and its subdomains: ${u}`, () => assert.equal(P.isAffiliateDomain(u), true));
}
// "t.co" used to match any host containing it (smoke test on copilot.com).
for (const u of ['https://copilot.microsoft.com/', 'https://www.microsoft.com/', 'https://copilot.com/', 'https://nott.co.uk/']) {
  test(`isAffiliateDomain ignores hosts that only contain an affiliate domain: ${u}`, () => assert.equal(P.isAffiliateDomain(u), false));
}

test('isAdSDKDomain matches exact host and subdomains, not look-alikes', () => {
  const d = P.getAllSDKDomains()[0];
  assert.equal(P.isAdSDKDomain(`https://${d}/sdk.js`), true);
  assert.equal(P.isAdSDKDomain(`https://cdn.${d}/sdk.js`), true);
  assert.equal(P.isAdSDKDomain(`https://not${d}/sdk.js`), false);
});
