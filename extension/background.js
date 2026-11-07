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
const MAX_LEARNED_TOTAL = 2000; // session rules: 5,000 max per extension
const STATE_KEY = 'learned_tracker_rules'; // { [tabId]: [ruleId] }

// The worker sleeps after ~30s idle and restarts with empty memory, while
// session rules live on. Keep the tab -> rule map in storage.session so a
// restart neither forgets nor wipes live rules.
async function loadState() {
  try {
    const data = await chrome.storage.session.get({ [STATE_KEY]: {} });
    return data[STATE_KEY] || {};
  } catch (_) {
    return {};
  }
}

async function saveState(state) {
  try { await chrome.storage.session.set({ [STATE_KEY]: state }); } catch (_) { /* noop */ }
}

// Serialize updates: messages can arrive while a previous one is in flight.
let queue = Promise.resolve();
function serialized(fn) {
  queue = queue.then(fn, fn);
  return queue;
}

// Ads blocked inside a tab's frames: { [tabId]: { sdksBlocked, ... } }.
// The popup adds these to the top frame's own counts.
const FRAME_STATS_KEY = 'frame_stats';
const STAT_KEYS = ['sdksBlocked', 'linksCleaned', 'elementsRemoved'];

async function loadFrameStats() {
  try {
    const data = await chrome.storage.session.get({ [FRAME_STATS_KEY]: {} });
    return data[FRAME_STATS_KEY] || {};
  } catch (_) {
    return {};
  }
}

async function addFrameStats(tabId, delta) {
  const all = await loadFrameStats();
  const cur = all[tabId] || { sdksBlocked: 0, linksCleaned: 0, elementsRemoved: 0 };
  for (const k of STAT_KEYS) {
    const n = Number(delta[k]);
    if (Number.isFinite(n) && n > 0 && n < 10000) cur[k] += Math.floor(n);
  }
  all[tabId] = cur;
  try { await chrome.storage.session.set({ [FRAME_STATS_KEY]: all }); } catch (_) { /* noop */ }
}

async function clearFrameStats(tabId) {
  const all = await loadFrameStats();
  if (!(tabId in all)) return;
  delete all[tabId];
  try { await chrome.storage.session.set({ [FRAME_STATS_KEY]: all }); } catch (_) { /* noop */ }
}

async function removeTabRules(tabId) {
  await clearFrameStats(tabId);
  const state = await loadState();
  const ids = state[tabId];
  if (!ids || !ids.length) return;
  delete state[tabId];
  try { await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: ids }); } catch (_) { /* noop */ }
  await saveState(state);
}

// urlFilter wildcards/anchors; a URL containing them can't be matched exactly.
const URL_FILTER_SPECIAL = /[*^|]/;

async function addLearnedTrackers(tabId, urls) {
  if (!chrome.declarativeNetRequest || !chrome.declarativeNetRequest.updateSessionRules) return;
  const state = await loadState();
  const existing = await chrome.declarativeNetRequest.getSessionRules();
  const used = new Set(existing.map(r => r.id));
  const tabFilters = new Set(existing.filter(r => r.condition && (r.condition.tabIds || []).includes(tabId)).map(r => r.condition.urlFilter));
  const total = Object.values(state).reduce((n, ids) => n + ids.length, 0);

  const addRules = [];
  let nextId = LEARNED_RULE_BASE;
  for (const { url, firstParty } of urls) {
    let u;
    try { u = new URL(url); } catch (_) { continue; }
    if (u.protocol !== 'https:' && u.protocol !== 'http:') continue;
    const href = u.href.split('#')[0];
    if (href.length > 1500 || URL_FILTER_SPECIAL.test(href)) continue;
    const urlFilter = '|' + href + '|';
    if (tabFilters.has(urlFilter)) continue;
    tabFilters.add(urlFilter);
    while (used.has(nextId)) nextId++;
    used.add(nextId);
    const condition = { urlFilter, tabIds: [tabId], isUrlFilterCaseSensitive: true };
    // A tracker on the site's own domain: pixels/beacons/scripts/frames
    // only, never the site's own fetch/XHR.
    if (firstParty) condition.resourceTypes = ['image', 'ping', 'script', 'media', 'sub_frame', 'other'];
    addRules.push({ id: nextId, priority: 2, action: { type: 'block' }, condition });
  }
  if (!addRules.length || total + addRules.length > MAX_LEARNED_TOTAL) return;

  const ids = (state[tabId] || []).concat(addRules.map(r => r.id));
  const overflow = ids.length > MAX_LEARNED_PER_TAB ? ids.splice(0, ids.length - MAX_LEARNED_PER_TAB) : [];
  try {
    await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: overflow, addRules });
  } catch (err) {
    console.warn('[Armorly] Could not add learned tracker rules:', err && err.message);
    return; // nothing recorded: the budget isn't spent on rules that don't exist
  }
  state[tabId] = ids;
  await saveState(state);
}

chrome.runtime.onMessage.addListener((message, sender) => {
  const tabId = sender && sender.tab && sender.tab.id;
  if (typeof tabId !== 'number' || tabId < 0 || !message) return;
  if (message.type === 'ARMORLY_LEARNED_TRACKERS' && Array.isArray(message.urls)) {
    serialized(() => addLearnedTrackers(tabId, message.urls.slice(0, 50)));
  } else if (message.type === 'ARMORLY_FRAME_STATS' && sender.frameId !== 0 && message.delta && typeof message.delta === 'object') {
    serialized(() => addFrameStats(tabId, message.delta));
  } else if (message.type === 'ARMORLY_PAGE_START' && sender.frameId === 0) {
    serialized(() => removeTabRules(tabId));
  }
});

if (chrome.tabs && chrome.tabs.onRemoved) {
  chrome.tabs.onRemoved.addListener((tabId) => serialized(() => removeTabRules(tabId)));
}

// On worker start: drop learned rules whose tab is gone (closed while the
// worker slept). Rules for open tabs stay.
async function pruneClosedTabs() {
  if (!chrome.declarativeNetRequest || !chrome.declarativeNetRequest.getSessionRules || !chrome.tabs) return;
  try {
    const open = new Set((await chrome.tabs.query({})).map(t => t.id));
    const rules = await chrome.declarativeNetRequest.getSessionRules();
    const stale = rules
      .filter(r => r.id >= LEARNED_RULE_BASE && !((r.condition && r.condition.tabIds) || []).some(id => open.has(id)))
      .map(r => r.id);
    if (stale.length) await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: stale });
    const state = await loadState();
    for (const tabId of Object.keys(state)) if (!open.has(Number(tabId))) delete state[tabId];
    await saveState(state);
    for (const tabId of Object.keys(await loadFrameStats())) if (!open.has(Number(tabId))) await clearFrameStats(Number(tabId));
  } catch (_) { /* noop */ }
}
serialized(pruneClosedTabs);
