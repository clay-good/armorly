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

  // Initialize popup
  document.addEventListener('DOMContentLoaded', updatePopup);

})();
