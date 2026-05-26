/**
 * Armorly Popup Script
 * Displays current protection status and stats
 */

(function() {
  'use strict';

  // AI platform patterns for detection
  const AI_PLATFORMS = [
    { pattern: /chat\.openai\.com|chatgpt\.com/i, name: 'ChatGPT' },
    { pattern: /claude\.ai/i, name: 'Claude' },
    { pattern: /perplexity\.ai/i, name: 'Perplexity' },
    { pattern: /gemini\.google\.com|bard\.google\.com/i, name: 'Gemini' },
    { pattern: /x\.com\/i\/grok|grok\.x\.com/i, name: 'Grok' },
    { pattern: /copilot\.microsoft\.com/i, name: 'Copilot' },
    { pattern: /poe\.com/i, name: 'Poe' },
    { pattern: /you\.com/i, name: 'You.com' },
    { pattern: /phind\.com/i, name: 'Phind' },
    { pattern: /huggingface\.co\/chat/i, name: 'HuggingChat' }
  ];

  // Sites we skip (from content script)
  const SKIP_DOMAINS = [
    'mail.google.com', 'calendar.google.com', 'docs.google.com',
    'youtube.com', 'github.com', 'stackoverflow.com', 'reddit.com',
    'twitter.com', 'facebook.com', 'instagram.com', 'linkedin.com',
    'amazon.com', 'netflix.com', 'spotify.com'
  ];

  /**
   * Check if a hostname should be skipped
   */
  function isSkippedDomain(hostname) {
    return SKIP_DOMAINS.some(domain =>
      hostname === domain || hostname.endsWith('.' + domain)
    );
  }

  /**
   * Get friendly name for AI platform
   */
  function getAIPlatformName(url) {
    try {
      const hostname = new URL(url).hostname;
      for (const platform of AI_PLATFORMS) {
        if (platform.pattern.test(url)) {
          return platform.name;
        }
      }
      return hostname;
    } catch {
      return 'Unknown';
    }
  }

  /**
   * Update the popup UI with current tab info
   */
  async function updatePopup() {
    try {
      // Get current tab
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

      if (!tab || !tab.url) {
        setInactiveState('No tab detected');
        return;
      }

      const url = tab.url;
      const hostname = new URL(url).hostname;

      // Update current site display
      document.getElementById('current-site-url').textContent = hostname;

      // Check if this is a chrome:// or other restricted URL
      if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:')) {
        setInactiveState('Extension pages');
        document.getElementById('current-site-url').textContent = 'Browser page (not monitored)';
        return;
      }

      // Check if domain is skipped
      if (isSkippedDomain(hostname)) {
        setInactiveState('Skipped site');
        showNote('This site is on the allowlist (not an AI chatbot). Armorly is not active here.');
        return;
      }

      // Try to get stats from content script
      try {
        const response = await chrome.tabs.sendMessage(tab.id, { type: 'GET_STATS' });

        if (response && response.active) {
          setActiveState();
          document.getElementById('sdks-blocked').textContent = response.sdksBlocked || 0;
          document.getElementById('links-cleaned').textContent = response.linksCleaned || 0;

          // Show note if no ads detected
          if ((response.sdksBlocked || 0) === 0 && (response.linksCleaned || 0) === 0) {
            showNote('No ads detected on this page. This site may not currently serve AI ads.');
          }
        } else {
          setActiveState();
          showNote('Monitoring active. No AI ads detected on this page.');
        }
      } catch {
        // Content script not responding - might be a new tab or restricted page
        // But if it's an AI platform, show as monitoring
        const isAIPlatform = AI_PLATFORMS.some(p => p.pattern.test(url));

        if (isAIPlatform) {
          setActiveState();
          document.getElementById('current-site-url').textContent = getAIPlatformName(url);
          showNote('Monitoring active. No AI ads detected on this page.');
        } else {
          setActiveState();
          showNote('Monitoring for AI ad networks on this page.');
        }
      }

    } catch (error) {
      console.error('Popup error:', error);
      setInactiveState('Error');
    }
  }

  /**
   * Set UI to active monitoring state
   */
  function setActiveState() {
    const badge = document.getElementById('status-badge');
    const text = document.getElementById('status-text');

    badge.classList.remove('inactive');
    badge.classList.add('active');
    text.textContent = 'Monitoring';
  }

  /**
   * Set UI to inactive state
   */
  function setInactiveState(reason) {
    const badge = document.getElementById('status-badge');
    const text = document.getElementById('status-text');

    badge.classList.remove('active');
    badge.classList.add('inactive');
    text.textContent = reason || 'Inactive';

    // Zero out stats
    document.getElementById('sdks-blocked').textContent = '-';
    document.getElementById('links-cleaned').textContent = '-';
  }

  /**
   * Show info note
   */
  function showNote(message) {
    const note = document.getElementById('no-ads-note');
    note.textContent = message;
    note.style.display = 'block';
  }

  /**
   * Populate the version string from the manifest so it never drifts.
   */
  function setVersion() {
    const el = document.getElementById('version');
    if (el) el.textContent = chrome.runtime.getManifest().version;
  }

  // ---------------------------------------------------------------------------
  // Per-site whitelist (v2.2.0)
  // ---------------------------------------------------------------------------

  // chrome:// and similar restricted URLs can't be toggled — keep the row hidden.
  function isToggleableUrl(url) {
    return !!url && !url.startsWith('chrome://') &&
      !url.startsWith('chrome-extension://') && !url.startsWith('about:');
  }

  function getDisabledDomains() {
    return new Promise((resolve) => {
      chrome.storage.local.get({ disabled_domains: [] }, (data) => {
        resolve(Array.isArray(data.disabled_domains) ? data.disabled_domains : []);
      });
    });
  }

  function setDisabledDomains(list) {
    return new Promise((resolve) => {
      chrome.storage.local.set({ disabled_domains: list }, resolve);
    });
  }

  async function setupSiteToggle(hostname, url) {
    const row = document.getElementById('site-toggle');
    const input = document.getElementById('site-toggle-input');
    const sub = document.getElementById('site-toggle-sub');

    if (!hostname || !isToggleableUrl(url)) return;

    const disabled = await getDisabledDomains();
    const isOff = disabled.includes(hostname);

    row.style.display = 'flex';
    input.checked = !isOff;
    sub.textContent = isOff ? 'Off — reload to apply' : 'On';
    if (isOff) {
      // Override whatever the content-script ping decided — the toggle is the
      // source of truth for whether Armorly is doing anything on this site.
      setInactiveState('Disabled here');
    }

    input.addEventListener('change', async () => {
      const current = await getDisabledDomains();
      let next;
      if (input.checked) {
        next = current.filter(d => d !== hostname);
        sub.textContent = 'On — reload to apply';
      } else {
        next = current.includes(hostname) ? current : [...current, hostname];
        sub.textContent = 'Off — reload to apply';
      }
      await setDisabledDomains(next);
    });
  }

  // ---------------------------------------------------------------------------
  // Lifetime stats (v2.2.0)
  // ---------------------------------------------------------------------------

  function renderLifetime(lifetime) {
    const l = lifetime || { sdksBlocked: 0, linksCleaned: 0, elementsRemoved: 0 };
    document.getElementById('lifetime-sdks').textContent = (l.sdksBlocked || 0).toLocaleString();
    document.getElementById('lifetime-links').textContent = (l.linksCleaned || 0).toLocaleString();
    document.getElementById('lifetime-elements').textContent = (l.elementsRemoved || 0).toLocaleString();
  }

  function loadLifetime() {
    chrome.storage.local.get({ lifetime: { sdksBlocked: 0, linksCleaned: 0, elementsRemoved: 0 } }, (data) => {
      renderLifetime(data.lifetime);
    });
  }

  function setupResetButton() {
    const btn = document.getElementById('reset-stats');
    btn.addEventListener('click', () => {
      const empty = { sdksBlocked: 0, linksCleaned: 0, elementsRemoved: 0 };
      chrome.storage.local.set({ lifetime: empty }, () => renderLifetime(empty));
    });
  }

  // ---------------------------------------------------------------------------
  // Report-a-missed-ad link (v2.4.0)
  // ---------------------------------------------------------------------------

  function setupReportLink(tabUrl) {
    const a = document.getElementById('report-link');
    if (!a) return;
    const version = chrome.runtime.getManifest().version;
    const body = [
      '<!-- The page URL and browser are pre-filled below.',
      'Please attach a screenshot and paste any `[Armorly]` console output. -->',
      '',
      '**URL where you saw the ad**',
      isToggleableUrl(tabUrl) ? tabUrl : '(unknown — please paste it here)',
      '',
      '**Screenshot**',
      '',
      '**Console output**',
      '',
      '```',
      '(paste here)',
      '```',
      '',
      '**Ad network guess (optional)**',
      '',
      `**Armorly version**`,
      version,
      '',
      '**Browser & OS**',
      navigator.userAgent
    ].join('\n');
    const params = new URLSearchParams({
      template: 'missed-ad.md',
      title: '[missed ad] ',
      body
    });
    a.href = `https://github.com/clay-good/armorly/issues/new?${params.toString()}`;
  }

  // Initialize popup
  document.addEventListener('DOMContentLoaded', async () => {
    setVersion();
    setupResetButton();
    loadLifetime();
    await updatePopup();

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const url = tab && tab.url ? tab.url : '';
      setupReportLink(url);
      if (url) {
        const hostname = new URL(url).hostname;
        await setupSiteToggle(hostname, url);
      }
    } catch {
      setupReportLink('');
    }
  });

})();
