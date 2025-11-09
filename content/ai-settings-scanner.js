/**
 * AI Settings Scanner for Armorly
 *
 * Injects into AI platform settings pages to scan memories and chat history
 * for malicious content. Works around CORS restrictions by reading DOM directly.
 *
 * Supported platforms:
 * - ChatGPT (chatgpt.com/settings/data-controls)
 * - Perplexity (perplexity.ai/settings)
 * - Claude (claude.ai/settings)
 *
 * @module ai-settings-scanner
 * @author Armorly Security Team
 * @license MIT
 */

(function() {
  'use strict';

  // Prevent multiple injections
  if (window.__armorlySettingsScannerInjected) {
    return;
  }
  window.__armorlySettingsScannerInjected = true;

  console.log('[Armorly Settings Scanner] Initializing on:', window.location.hostname);

  /**
   * Detect which AI platform we're on
   */
  function detectPlatform() {
    const hostname = window.location.hostname;

    if (hostname.includes('chatgpt.com') || hostname.includes('chat.openai.com')) {
      return 'chatgpt';
    } else if (hostname.includes('perplexity.ai')) {
      return 'perplexity';
    } else if (hostname.includes('claude.ai') || hostname.includes('anthropic.com')) {
      return 'claude';
    }

    return 'unknown';
  }

  /**
   * Scan ChatGPT memories from DOM
   */
  async function scanChatGPTMemories() {
    console.log('[Armorly Settings Scanner] Scanning ChatGPT memories...');

    const memories = [];

    // Wait for DOM to load
    await waitForElement('[data-testid="memory-item"], .memory-item, [class*="memory"]', 5000);

    // Try multiple selectors (ChatGPT UI changes frequently)
    const selectors = [
      '[data-testid="memory-item"]',
      '.memory-item',
      '[class*="Memory"]',
      '[aria-label*="memory"]',
      'div[class*="flex"][class*="gap"]', // Fallback: look for memory-like structures
    ];

    for (const selector of selectors) {
      const elements = document.querySelectorAll(selector);

      for (const element of elements) {
        const text = element.textContent || element.innerText;

        if (text && text.length > 10) { // Ignore empty or very short elements
          memories.push({
            text: text.trim(),
            html: element.outerHTML.substring(0, 500), // First 500 chars for context
            element: element,
          });
        }
      }

      if (memories.length > 0) {
        console.log(`[Armorly Settings Scanner] Found ${memories.length} memories using selector: ${selector}`);
        break; // Found memories, no need to try other selectors
      }
    }

    return memories;
  }

  /**
   * Scan Perplexity settings from DOM
   */
  async function scanPerplexitySettings() {
    console.log('[Armorly Settings Scanner] Scanning Perplexity settings...');

    const data = [];

    // Wait for settings to load
    await waitForElement('[class*="setting"], [class*="preference"]', 5000);

    // Scan for stored data/preferences
    const elements = document.querySelectorAll('[class*="setting"], input, textarea');

    for (const element of elements) {
      const text = element.value || element.textContent || element.innerText;

      if (text && text.length > 10) {
        data.push({
          text: text.trim(),
          type: element.tagName.toLowerCase(),
        });
      }
    }

    return data;
  }

  /**
   * Scan Claude settings from DOM
   */
  async function scanClaudeSettings() {
    console.log('[Armorly Settings Scanner] Scanning Claude settings...');

    const data = [];

    // Wait for settings to load
    await waitForElement('[class*="conversation"], [class*="history"]', 5000);

    // Scan conversation history and settings
    const elements = document.querySelectorAll('[class*="conversation"], [class*="message"], textarea, input');

    for (const element of elements) {
      const text = element.value || element.textContent || element.innerText;

      if (text && text.length > 10) {
        data.push({
          text: text.trim(),
          type: element.tagName.toLowerCase(),
        });
      }
    }

    return data;
  }

  /**
   * Wait for element to appear in DOM
   */
  function waitForElement(selector, timeout = 5000) {
    return new Promise((resolve) => {
      const element = document.querySelector(selector);

      if (element) {
        resolve(element);
        return;
      }

      const observer = new MutationObserver((mutations, obs) => {
        const element = document.querySelector(selector);
        if (element) {
          obs.disconnect();
          resolve(element);
        }
      });

      observer.observe(document.documentElement, {
        childList: true,
        subtree: true,
      });

      // Timeout fallback
      setTimeout(() => {
        observer.disconnect();
        resolve(null);
      }, timeout);
    });
  }

  /**
   * Analyze text for threats
   */
  function analyzeForThreats(items) {
    const threats = [];

    // Injection patterns to detect
    const patterns = [
      { pattern: /ignore\s+(?:all\s+)?previous\s+instructions/i, type: 'INSTRUCTION_OVERRIDE', severity: 'CRITICAL' },
      { pattern: /system\s*:\s*you\s+are/i, type: 'SYSTEM_ROLE_MANIPULATION', severity: 'CRITICAL' },
      { pattern: /disregard\s+(?:all\s+)?(?:prior|previous)/i, type: 'INSTRUCTION_OVERRIDE', severity: 'HIGH' },
      { pattern: /<script[^>]*>/i, type: 'XSS_INJECTION', severity: 'CRITICAL' },
      { pattern: /eval\s*\(/i, type: 'CODE_INJECTION', severity: 'HIGH' },
      { pattern: /fetch\s*\(['"](https?:\/\/[^'"]+)/i, type: 'DATA_EXFILTRATION', severity: 'HIGH' },
      { pattern: /\.then\s*\(\s*\(?\s*(?:response|res|r)\s*\)?\s*=>/i, type: 'ASYNC_EXFILTRATION', severity: 'MEDIUM' },
      { pattern: /localStorage\.setItem/i, type: 'STORAGE_MANIPULATION', severity: 'MEDIUM' },
      { pattern: /document\.cookie/i, type: 'COOKIE_THEFT', severity: 'HIGH' },
      { pattern: /<\|im_start\|>|<\|im_end\|>|\[INST\]|\[\/INST\]/i, type: 'SPECIAL_TOKENS', severity: 'HIGH' },
    ];

    for (const item of items) {
      const text = item.text;

      for (const { pattern, type, severity } of patterns) {
        const match = text.match(pattern);

        if (match) {
          threats.push({
            type,
            severity,
            text: text.substring(0, 200), // First 200 chars
            match: match[0],
            item,
          });
        }
      }
    }

    return threats;
  }

  /**
   * Remove malicious memories from DOM
   */
  function removeThreats(threats) {
    let removed = 0;

    for (const threat of threats) {
      if (threat.item.element) {
        try {
          // Replace with warning message (using safe DOM methods)
          const warning = document.createElement('div');
          warning.style.cssText = `
            background: #fee;
            border: 2px solid #c00;
            border-radius: 8px;
            padding: 12px;
            margin: 8px 0;
            font-family: system-ui, -apple-system, sans-serif;
          `;

          // Create header
          const strong = document.createElement('strong');
          strong.textContent = '🛡️ Armorly: Malicious Memory Blocked';
          warning.appendChild(strong);

          warning.appendChild(document.createElement('br'));

          // Create details span
          const details = document.createElement('span');
          details.style.cssText = 'font-size: 13px; color: #666;';

          // Add threat type
          const typeText = document.createTextNode('Type: ');
          details.appendChild(typeText);
          details.appendChild(document.createTextNode(threat.type));
          details.appendChild(document.createElement('br'));

          // Add severity
          details.appendChild(document.createTextNode('Severity: '));
          details.appendChild(document.createTextNode(threat.severity));
          details.appendChild(document.createElement('br'));

          // Add description
          details.appendChild(document.createTextNode('This memory contained a '));
          details.appendChild(document.createTextNode(threat.severity.toLowerCase()));
          details.appendChild(document.createTextNode(' threat and has been removed.'));

          warning.appendChild(details);

          threat.item.element.replaceWith(warning);
          removed++;
        } catch (error) {
          console.error('[Armorly Settings Scanner] Error removing threat:', error);
        }
      }
    }

    return removed;
  }

  /**
   * Main scanning function
   */
  async function scanAndClean() {
    const platform = detectPlatform();

    if (platform === 'unknown') {
      console.log('[Armorly Settings Scanner] Unknown platform, skipping scan');
      return;
    }

    console.log(`[Armorly Settings Scanner] Detected platform: ${platform}`);

    let items = [];

    try {
      // Scan based on platform
      switch (platform) {
        case 'chatgpt':
          items = await scanChatGPTMemories();
          break;
        case 'perplexity':
          items = await scanPerplexitySettings();
          break;
        case 'claude':
          items = await scanClaudeSettings();
          break;
      }

      if (items.length === 0) {
        console.log('[Armorly Settings Scanner] No items found to scan');
        return;
      }

      console.log(`[Armorly Settings Scanner] Scanning ${items.length} items...`);

      // Analyze for threats
      const threats = analyzeForThreats(items);

      if (threats.length > 0) {
        console.warn(`[Armorly Settings Scanner] Found ${threats.length} threats!`, threats);

        // Remove threats from DOM
        const removed = removeThreats(threats);

        // Report to background worker
        chrome.runtime.sendMessage({
          type: 'MEMORY_THREATS_DETECTED',
          platform,
          threats: threats.map(t => ({
            type: t.type,
            severity: t.severity,
            text: t.text,
            match: t.match,
          })),
          removed,
        });

        // Show user notification
        showNotification(`Blocked ${removed} malicious ${removed === 1 ? 'memory' : 'memories'} on ${platform}`);
      } else {
        console.log('[Armorly Settings Scanner] No threats detected');
      }
    } catch (error) {
      console.error('[Armorly Settings Scanner] Error during scan:', error);
    }
  }

  /**
   * Show notification to user
   * SILENT MODE: Disabled for background operation
   */
  function showNotification(message) {
    // Silent mode - log only, no visible notifications
    console.warn('[Armorly Settings Scanner]', message);
    return;

    // Notifications disabled for silent background operation
    /* const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: #10b981;
      color: white;
      padding: 16px 24px;
      border-radius: 8px;
      font-family: system-ui, -apple-system, sans-serif;
      font-size: 14px;
      z-index: 999999;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      max-width: 300px;
    `;
    notification.textContent = `🛡️ ${message}`;

    document.body.appendChild(notification);

    setTimeout(() => {
      notification.style.transition = 'opacity 0.3s';
      notification.style.opacity = '0';
      setTimeout(() => notification.remove(), 300);
    }, 5000); */
  }

  // Run scan when page loads
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(scanAndClean, 2000); // Wait 2s for page to fully load
    });
  } else {
    setTimeout(scanAndClean, 2000);
  }

  // Also run when user navigates within SPA
  let lastUrl = window.location.href;
  new MutationObserver(() => {
    if (window.location.href !== lastUrl) {
      lastUrl = window.location.href;
      setTimeout(scanAndClean, 2000);
    }
  }).observe(document.documentElement, { subtree: true, childList: true });

  console.log('[Armorly Settings Scanner] Initialized successfully');
})();
