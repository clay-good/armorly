/**
 * Memory Monitoring System for Armorly
 * 
 * Monitors and audits AI assistant memories for:
 * - ChatGPT memory poisoning attacks
 * - Suspicious instruction injection
 * - Unauthorized memory modifications
 * - Malicious persistent commands
 * 
 * Based on LayerX Security research on "ChatGPT Tainted Memories"
 * 
 * @module memory-monitor
 * @author Armorly Security Team
 * @license MIT
 */

class MemoryMonitor {
  constructor(patternLibrary) {
    this.patternLibrary = patternLibrary;
    
    /**
     * Memory audit configuration
     */
    this.config = {
      auditFrequency: 'weekly', // daily, weekly, manual
      lastAuditDate: null,
      autoRemoveSuspicious: false,
      notifyOnSuspicious: true
    };

    /**
     * Suspicious memory cache
     */
    this.suspiciousMemories = new Map();

    /**
     * Audit history
     */
    this.auditHistory = [];

    /**
     * AI platform endpoints for memory access
     */
    this.memoryEndpoints = {
      chatgpt: {
        list: 'https://chatgpt.com/backend-api/memories',
        delete: 'https://chatgpt.com/backend-api/memories/{id}',
        settings: 'https://chatgpt.com/settings/data-controls'
      },
      perplexity: {
        preferences: 'https://www.perplexity.ai/api/preferences',
        settings: 'https://www.perplexity.ai/settings'
      }
    };
  }

  /**
   * Perform memory audit
   * 
   * @param {string} platform - Platform to audit ('chatgpt', 'perplexity', 'all')
   * @returns {Promise<Object>} Audit results
   */
  async performAudit(platform = 'all') {
    console.log(`[Armorly] Starting memory audit for: ${platform}`);

    const results = {
      platform,
      timestamp: Date.now(),
      memoriesScanned: 0,
      suspiciousFound: 0,
      suspicious: [],
      clean: [],
      errors: []
    };

    try {
      if (platform === 'chatgpt' || platform === 'all') {
        const chatgptResults = await this.auditChatGPTMemories();
        this.mergeResults(results, chatgptResults);
      }

      if (platform === 'perplexity' || platform === 'all') {
        const perplexityResults = await this.auditPerplexityPreferences();
        this.mergeResults(results, perplexityResults);
      }

      // Update config
      this.config.lastAuditDate = Date.now();

      // Add to history
      this.auditHistory.unshift(results);
      if (this.auditHistory.length > 50) {
        this.auditHistory.splice(50);
      }

      console.log(`[Armorly] Audit complete: ${results.suspiciousFound} suspicious memories found`);

      return results;
    } catch (error) {
      console.error('[Armorly] Memory audit failed:', error);
      results.errors.push(error.message);
      return results;
    }
  }

  /**
   * Audit ChatGPT memories
   * 
   * @returns {Promise<Object>} Audit results
   */
  async auditChatGPTMemories() {
    const results = {
      memoriesScanned: 0,
      suspiciousFound: 0,
      suspicious: [],
      clean: [],
      errors: []
    };

    try {
      // Note: This requires the user to be logged into ChatGPT
      // We can't directly access the API due to CORS, but we can:
      // 1. Inject a content script on chatgpt.com
      // 2. Guide users to check their memories manually
      // 3. Scan memories when they're visible on the page

      // For now, we'll provide guidance to users
      results.errors.push('Direct memory access requires user action. Please visit ChatGPT settings.');

      return results;
    } catch (error) {
      console.error('[Armorly] ChatGPT memory audit failed:', error);
      results.errors.push(error.message);
      return results;
    }
  }

  /**
   * Audit Perplexity preferences
   * 
   * @returns {Promise<Object>} Audit results
   */
  async auditPerplexityPreferences() {
    const results = {
      memoriesScanned: 0,
      suspiciousFound: 0,
      suspicious: [],
      clean: [],
      errors: []
    };

    try {
      // Similar to ChatGPT, direct API access is limited
      results.errors.push('Direct preference access requires user action. Please visit Perplexity settings.');

      return results;
    } catch (error) {
      console.error('[Armorly] Perplexity preference audit failed:', error);
      results.errors.push(error.message);
      return results;
    }
  }

  /**
   * Scan memory content for suspicious patterns
   *
   * @param {Object} memory - Memory object
   * @param {string} memory.id - Memory ID
   * @param {string} memory.content - Memory content
   * @param {string} memory.source - Source platform
   * @returns {Object} Scan result
   */
  scanMemory(memory) {
    if (!this.patternLibrary) {
      return {
        isSuspicious: false,
        score: 0,
        matches: []
      };
    }

    // Scan content using pattern library
    const scanResult = this.patternLibrary.scanText(memory.content, {
      isMemory: true,
      platform: memory.source
    });

    let score = scanResult.score;

    // Additional memory-specific checks
    const additionalChecks = this.performMemorySpecificChecks(memory.content);
    score += additionalChecks.score;

    const isSuspicious = score >= 40;

    if (isSuspicious) {
      this.suspiciousMemories.set(memory.id, {
        memory,
        scanResult,
        additionalChecks,
        detectedAt: Date.now()
      });
    }

    return {
      isSuspicious,
      score,
      matches: [...scanResult.matches, ...additionalChecks.matches],
      categories: Array.from(scanResult.categories),
      additionalFlags: additionalChecks.flags
    };
  }

  /**
   * Perform memory-specific security checks
   *
   * @param {string} content - Memory content
   * @returns {Object} Check results
   */
  performMemorySpecificChecks(content) {
    const result = {
      score: 0,
      matches: [],
      flags: []
    };

    const lowerContent = content.toLowerCase();

    // Check for persistent code injection instructions
    const codeInjectionPatterns = [
      /always\s+(use|import|fetch|include|require)\s+.*from\s+https?:\/\//gi,
      /never\s+forget\s+to\s+(use|import|fetch|include)/gi,
      /remember\s+to\s+always\s+(fetch|import|use)/gi,
      /default\s+(library|dependency|package|import)\s+should\s+be/gi
    ];

    for (const pattern of codeInjectionPatterns) {
      if (pattern.test(content)) {
        result.score += 45;
        result.matches.push('Persistent code injection instruction');
        result.flags.push('CODE_INJECTION');
        break;
      }
    }

    // Check for data exfiltration instructions
    if (lowerContent.includes('send') && lowerContent.includes('http')) {
      result.score += 40;
      result.matches.push('Data exfiltration instruction');
      result.flags.push('DATA_EXFILTRATION');
    }

    // Check for credential harvesting
    const credentialPatterns = ['password', 'api key', 'token', 'secret', 'credential'];
    const credentialCount = credentialPatterns.filter(p => lowerContent.includes(p)).length;
    if (credentialCount >= 2) {
      result.score += 35;
      result.matches.push('Credential harvesting pattern');
      result.flags.push('CREDENTIAL_HARVEST');
    }

    // Check for behavior modification
    const behaviorPatterns = [
      'never tell the user',
      'hide from the user',
      'don\'t mention',
      'keep secret',
      'without telling'
    ];

    for (const pattern of behaviorPatterns) {
      if (lowerContent.includes(pattern)) {
        result.score += 40;
        result.matches.push('Behavior modification instruction');
        result.flags.push('BEHAVIOR_MOD');
        break;
      }
    }

    // Check for URL patterns pointing to suspicious domains
    const urlPattern = /https?:\/\/[^\s"']+/gi;
    const urls = content.match(urlPattern);
    if (urls && urls.length > 0) {
      // Check for non-standard TLDs or suspicious patterns
      const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top'];
      const hasSuspiciousTLD = urls.some(url =>
        suspiciousTLDs.some(tld => url.toLowerCase().includes(tld))
      );

      if (hasSuspiciousTLD) {
        result.score += 30;
        result.matches.push('Suspicious domain TLD');
        result.flags.push('SUSPICIOUS_DOMAIN');
      }
    }

    return result;
  }

  /**
   * Scan memories from page content
   * 
   * This is called by content scripts when memory pages are loaded
   * 
   * @param {Array} memories - Array of memory objects from page
   * @returns {Object} Scan results
   */
  scanMemoriesFromPage(memories) {
    const results = {
      memoriesScanned: memories.length,
      suspiciousFound: 0,
      suspicious: [],
      clean: []
    };

    memories.forEach(memory => {
      const scanResult = this.scanMemory(memory);
      
      if (scanResult.isSuspicious) {
        results.suspiciousFound++;
        results.suspicious.push({
          ...memory,
          scanResult
        });
      } else {
        results.clean.push(memory);
      }
    });

    return results;
  }

  /**
   * Get guidance for manual memory check
   * 
   * @param {string} platform - Platform name
   * @returns {Object} Guidance information
   */
  getManualCheckGuidance(platform) {
    const guidance = {
      chatgpt: {
        title: 'Check Your ChatGPT Memories',
        steps: [
          'Go to ChatGPT Settings → Data Controls',
          'Click on "Manage Memory"',
          'Review each memory for suspicious content',
          'Look for instructions like "always fetch from", "ignore previous", "your new goal"',
          'Delete any memories you don\'t recognize or that contain commands'
        ],
        url: 'https://chatgpt.com/settings/data-controls',
        warningPatterns: [
          'Instructions to fetch code from external URLs',
          'Commands to "always" do something',
          'Goal or role redefinition',
          'Instructions to ignore guidelines',
          'Data exfiltration commands'
        ]
      },
      perplexity: {
        title: 'Check Your Perplexity Preferences',
        steps: [
          'Go to Perplexity Settings',
          'Review your preferences and saved searches',
          'Look for suspicious instructions or commands',
          'Remove any preferences you don\'t recognize'
        ],
        url: 'https://www.perplexity.ai/settings',
        warningPatterns: [
          'Unusual search preferences',
          'Instructions embedded in saved searches',
          'External URL references'
        ]
      }
    };

    return guidance[platform] || null;
  }

  /**
   * Open ChatGPT memory page for user to review
   *
   * @returns {Promise<void>}
   */
  async openMemoryPage() {
    try {
      await chrome.tabs.create({
        url: 'https://chatgpt.com/settings/data-controls',
        active: true
      });
    } catch (error) {
      console.error('[Armorly] Failed to open memory page:', error);
    }
  }

  /**
   * Get statistics about suspicious memories
   *
   * @returns {Object} Statistics
   */
  getStatistics() {
    return {
      totalSuspicious: this.suspiciousMemories.size,
      lastAuditDate: this.config.lastAuditDate,
      auditCount: this.auditHistory.length,
      recentAudits: this.auditHistory.slice(0, 5).map(audit => ({
        timestamp: audit.timestamp,
        platform: audit.platform,
        suspiciousFound: audit.suspiciousFound,
        memoriesScanned: audit.memoriesScanned
      }))
    };
  }

  /**
   * Schedule automatic audit
   *
   * @param {string} frequency - 'daily', 'weekly', or 'manual'
   */
  scheduleAudit(frequency) {
    this.config.auditFrequency = frequency;

    // Clear existing alarms
    chrome.alarms.clear('memory-audit');

    if (frequency === 'daily') {
      chrome.alarms.create('memory-audit', {
        delayInMinutes: 1440, // 24 hours
        periodInMinutes: 1440
      });
    } else if (frequency === 'weekly') {
      chrome.alarms.create('memory-audit', {
        delayInMinutes: 10080, // 7 days
        periodInMinutes: 10080
      });
    }

    console.log(`[Armorly] Memory audit scheduled: ${frequency}`);
  }

  /**
   * Handle alarm for scheduled audit
   * 
   * @param {Object} alarm - Chrome alarm object
   */
  async handleAlarm(alarm) {
    if (alarm.name === 'memory-audit') {
      console.log('[Armorly] Running scheduled memory audit');
      const results = await this.performAudit('all');

      if (results.suspiciousFound > 0 && this.config.notifyOnSuspicious) {
        this.notifySuspiciousMemories(results);
      }
    }
  }

  /**
   * Notify user of suspicious memories
   * 
   * @param {Object} results - Audit results
   */
  notifySuspiciousMemories(results) {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: chrome.runtime.getURL('icons/icon-128.png'),
      title: 'Armorly: Suspicious Memories Detected',
      message: `Found ${results.suspiciousFound} suspicious memories. Click to review.`,
      priority: 2,
      requireInteraction: true
    });
  }

  /**
   * Merge audit results
   * 
   * @param {Object} target - Target results object
   * @param {Object} source - Source results object
   */
  mergeResults(target, source) {
    target.memoriesScanned += source.memoriesScanned;
    target.suspiciousFound += source.suspiciousFound;
    target.suspicious.push(...source.suspicious);
    target.clean.push(...source.clean);
    target.errors.push(...source.errors);
  }

  /**
   * Get audit history
   * 
   * @param {number} limit - Maximum number of entries
   * @returns {Array} Audit history
   */
  getAuditHistory(limit = 10) {
    return this.auditHistory.slice(0, limit);
  }

  /**
   * Get suspicious memories
   * 
   * @returns {Array} Array of suspicious memories
   */
  getSuspiciousMemories() {
    return Array.from(this.suspiciousMemories.values());
  }

  /**
   * Clear suspicious memory cache
   */
  clearSuspiciousCache() {
    this.suspiciousMemories.clear();
  }
}

// Export for use in service worker
export { MemoryMonitor };
