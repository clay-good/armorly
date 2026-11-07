/**
 * Armorly background service worker (v2.5.0).
 *
 * Phase 4.4: fetch the canonical ad-patterns.json from the main branch on
 * install and every 24h. Cached snapshots live in chrome.storage.local under
 * `cached_patterns`. Content scripts read this on startup and union it with
 * the bundled patterns (bundled is the floor).
 *
 * Important: this is DATA-only. We never eval, never inject, never load
 * remote code. Web Store policy forbids remote code; cached values are
 * flat strings consumed by querySelectorAll, URL parsing, and the SDK
 * function-name interceptor.
 */

const PATTERNS_URL =
  'https://raw.githubusercontent.com/clay-good/armorly/main/extension/lib/ad-patterns.json';
const ALARM_NAME = 'armorly-pattern-update';
const UPDATE_PERIOD_MIN = 60 * 24; // once a day

function isObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function isStringArray(v) {
  return Array.isArray(v) && v.every((x) => typeof x === 'string');
}

// Schema validation. Anything that fails this is dropped — bundled patterns
// keep working. Errors here are non-fatal.
function validatePatterns(data) {
  if (!isObject(data)) return false;
  if (typeof data.version !== 'string') return false;
  if (data.adSDKs !== undefined) {
    if (!isObject(data.adSDKs)) return false;
    for (const sdk of Object.values(data.adSDKs)) {
      if (!isObject(sdk)) return false;
      for (const key of ['functions', 'methods', 'domainPatterns']) {
        if (sdk[key] !== undefined && !isStringArray(sdk[key])) return false;
      }
    }
  }
  if (data.affiliateParams !== undefined && !isStringArray(data.affiliateParams)) return false;
  if (data.affiliateDomains !== undefined && !isStringArray(data.affiliateDomains)) return false;
  if (data.platformSelectors !== undefined) {
    if (!isObject(data.platformSelectors)) return false;
    for (const list of Object.values(data.platformSelectors)) {
      if (!isStringArray(list)) return false;
    }
  }
  return true;
}

async function fetchAndCachePatterns() {
  try {
    const res = await fetch(PATTERNS_URL, { cache: 'no-cache' });
    if (!res.ok) {
      console.warn('[Armorly] Pattern fetch failed:', res.status);
      return;
    }
    const data = await res.json();
    if (!validatePatterns(data)) {
      console.warn('[Armorly] Pattern fetch rejected by schema validation');
      return;
    }
    // Only replace cache if the version moved forward. We never roll back.
    const { cached_patterns: existing } = await chrome.storage.local.get({ cached_patterns: null });
    if (existing && typeof existing.version === 'string' && data.version <= existing.version) {
      return;
    }
    await chrome.storage.local.set({
      cached_patterns: data,
      cached_patterns_fetched_at: Date.now()
    });
    console.log('[Armorly] Cached patterns updated to version', data.version);
  } catch (err) {
    console.warn('[Armorly] Pattern fetch threw:', err && err.message);
  }
}

// Fire once on install/update, then hand the schedule to chrome.alarms so the
// SW doesn't have to stay alive between runs.
chrome.runtime.onInstalled.addListener(() => {
  fetchAndCachePatterns();
  chrome.alarms.create(ALARM_NAME, { periodInMinutes: UPDATE_PERIOD_MIN });
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === ALARM_NAME) fetchAndCachePatterns();
});

// In case the alarm got cleared (e.g. due to a browser restart edge case),
// re-register on startup. Cheap, idempotent.
chrome.runtime.onStartup.addListener(() => {
  chrome.alarms.create(ALARM_NAME, { periodInMinutes: UPDATE_PERIOD_MIN });
});

// ---------------------------------------------------------------------------
// Learned tracker URLs (server-side / OpenRTB ads).
//
// content/payload-shield.js strips ads out of a page's responses and learns
// the impression/win/billing URLs those ads carried. In-page hooks block
// most of the follow-up requests, but a pixel created by HTML parsing
// (innerHTML) loads without any JS hook running. These session rules close
// that gap: exact URLs, scoped to the one tab that saw the ad, cleared when
// the tab navigates or closes. A tracker on the page's own host is blocked
// only for pixel/beacon/script/frame loads, never for the site's own
// fetch/XHR calls.
// ---------------------------------------------------------------------------

const LEARNED_RULE_BASE = 900000;
const MAX_LEARNED_PER_TAB = 100;
const MAX_LEARNED_TOTAL = 500; // regex rules share a 1,000 budget
const learnedByTab = new Map(); // tabId -> [ruleId]
// Offset by time so ids from before a worker restart never collide.
let nextLearnedId = LEARNED_RULE_BASE + (Date.now() % 50000000);

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function removeLearnedRules(ids) {
  if (!ids || !ids.length) return;
  try { await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: ids }); } catch (_) { /* noop */ }
}

async function addLearnedTrackers(tabId, urls) {
  if (!chrome.declarativeNetRequest || !chrome.declarativeNetRequest.updateSessionRules) return;
  const list = learnedByTab.get(tabId) || [];
  const addRules = [];
  for (const { url, firstParty } of urls) {
    let u;
    try { u = new URL(url); } catch (_) { continue; }
    if (u.protocol !== 'https:' && u.protocol !== 'http:') continue;
    const href = u.href.split('#')[0];
    if (href.length > 1500) continue;
    const condition = { regexFilter: '^' + escapeRegex(href) + '$', tabIds: [tabId] };
    if (firstParty) condition.resourceTypes = ['image', 'ping', 'script', 'media', 'sub_frame', 'other'];
    addRules.push({ id: nextLearnedId++, priority: 2, action: { type: 'block' }, condition });
  }
  if (!addRules.length) return;
  const ids = list.concat(addRules.map(r => r.id));
  const overflow = ids.length > MAX_LEARNED_PER_TAB ? ids.splice(0, ids.length - MAX_LEARNED_PER_TAB) : [];
  let total = 0;
  for (const v of learnedByTab.values()) total += v.length;
  if (total + addRules.length > MAX_LEARNED_TOTAL) return;
  learnedByTab.set(tabId, ids);
  try {
    await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: overflow, addRules });
  } catch (err) {
    console.warn('[Armorly] Could not add learned tracker rules:', err && err.message);
  }
}

chrome.runtime.onMessage.addListener((message, sender) => {
  const tabId = sender && sender.tab && sender.tab.id;
  if (typeof tabId !== 'number' || tabId < 0 || !message) return;
  if (message.type === 'ARMORLY_LEARNED_TRACKERS' && Array.isArray(message.urls)) {
    addLearnedTrackers(tabId, message.urls.slice(0, 50));
  } else if (message.type === 'ARMORLY_PAGE_START' && sender.frameId === 0) {
    removeLearnedRules(learnedByTab.get(tabId));
    learnedByTab.delete(tabId);
  }
});

if (chrome.tabs && chrome.tabs.onRemoved) {
  chrome.tabs.onRemoved.addListener((tabId) => {
    removeLearnedRules(learnedByTab.get(tabId));
    learnedByTab.delete(tabId);
  });
}

// Session rules outlive a service-worker restart but our id map doesn't:
// start clean.
if (chrome.declarativeNetRequest && chrome.declarativeNetRequest.getSessionRules) {
  chrome.declarativeNetRequest.getSessionRules().then(rules => {
    const stale = rules.map(r => r.id).filter(id => id >= LEARNED_RULE_BASE);
    if (stale.length) removeLearnedRules(stale);
  }).catch(() => {});
}
