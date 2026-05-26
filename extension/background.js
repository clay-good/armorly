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
