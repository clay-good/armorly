/**
 * Browser Detector
 * 
 * Detects which agentic browser Armorly is running in and provides
 * browser-specific capabilities and feature flags.
 * 
 * Supports:
 * - BrowserOS (Chromium fork with browserOS API)
 * - ChatGPT Atlas (OpenAI's OWL architecture)
 * - Perplexity Comet (Agentic browsing)
 * - Brave Browser (with Leo AI)
 * - Standard Chrome (baseline)
 */

export class BrowserDetector {
  constructor() {
    this.browserType = null;
    this.browserVersion = null;
    this.capabilities = {
      hasBrowserOSAPI: false,
      hasAtlasAPI: false,
      hasCometAPI: false,
      hasBraveLeoAPI: false,
      hasAccessibilityTree: false,
      hasAgenticMode: false,
      hasEphemeralContext: false,
      hasScreenshotAPI: false,
      hasJSExecutionAPI: false,
    };
    this.detectionComplete = false;
  }

  /**
   * Detect browser type and capabilities
   * @param {string} userAgent - Optional user agent string (uses navigator.userAgent if not provided)
   * @returns {Promise<Object>} Detection results
   *
   * NOTE: In service worker context, navigator.userAgent IS available in Chrome,
   * but other navigator properties may not be. Pass userAgent explicitly when possible.
   */
  async detect(userAgent = null) {
    console.log('[Armorly Browser Detector] Starting detection...');

    // Detect browser type
    await this.detectBrowserType(userAgent);

    // Detect capabilities
    await this.detectCapabilities();

    this.detectionComplete = true;

    const result = {
      browserType: this.browserType,
      browserVersion: this.browserVersion,
      capabilities: this.capabilities,
    };

    console.log('[Armorly Browser Detector] Detection complete:', result);
    return result;
  }

  /**
   * Detect browser type
   * @param {string} userAgent - Optional user agent string
   *
   * SECURITY: Safe for service worker context. Uses navigator.userAgent as fallback
   * which IS available in Chrome service workers, but with defensive error handling.
   */
  async detectBrowserType(userAgent = null) {
    // Check for BrowserOS
    if (typeof chrome !== 'undefined' && chrome.browserOS) {
      this.browserType = 'browseros';
      this.browserVersion = await this.getBrowserOSVersion();
      console.log('[Armorly Browser Detector] Detected: BrowserOS');
      return;
    }

    // Get user agent safely (service worker compatible)
    let ua = userAgent;
    if (!ua) {
      try {
        // navigator.userAgent IS available in Chrome service workers
        ua = (typeof navigator !== 'undefined' && navigator.userAgent)
          ? navigator.userAgent
          : 'Chrome'; // Fallback
      } catch (e) {
        console.warn('[Armorly Browser Detector] Could not access navigator.userAgent:', e);
        ua = 'Chrome'; // Safe fallback
      }
    }

    // Check for ChatGPT Atlas
    // Atlas uses OWL architecture with specific user agent patterns
    if (ua.includes('Atlas') || ua.includes('OWL')) {
      this.browserType = 'atlas';
      this.browserVersion = this.extractVersionFromUA(ua, 'Atlas');
      console.log('[Armorly Browser Detector] Detected: ChatGPT Atlas');
      return;
    }

    // Check for Perplexity Comet
    // Comet may have specific APIs or user agent patterns
    if (ua.includes('Comet') || ua.includes('Perplexity')) {
      this.browserType = 'comet';
      this.browserVersion = this.extractVersionFromUA(ua, 'Comet');
      console.log('[Armorly Browser Detector] Detected: Perplexity Comet');
      return;
    }

    // Check for Brave Browser
    // NOTE: navigator.brave is NOT available in service workers
    // Check for Brave-specific extension APIs instead
    try {
      if (typeof navigator !== 'undefined' &&
          navigator.brave &&
          typeof navigator.brave.isBrave === 'function' &&
          await navigator.brave.isBrave()) {
        this.browserType = 'brave';
        this.browserVersion = this.extractVersionFromUA(ua, 'Chrome');
        console.log('[Armorly Browser Detector] Detected: Brave Browser');
        return;
      }
    } catch (e) {
      // navigator.brave not available (service worker context) - that's OK
      // Brave detection will fall through to Chrome
    }

    // Check for Arc Browser (The Browser Company)
    if (ua.includes('Arc')) {
      this.browserType = 'arc';
      this.browserVersion = this.extractVersionFromUA(ua, 'Arc');
      console.log('[Armorly Browser Detector] Detected: Arc Browser');
      return;
    }

    // Default to standard Chrome
    this.browserType = 'chrome';
    this.browserVersion = this.extractVersionFromUA(ua, 'Chrome');
    console.log('[Armorly Browser Detector] Detected: Standard Chrome');
  }

  /**
   * Detect browser capabilities
   */
  async detectCapabilities() {
    // BrowserOS API
    if (typeof chrome !== 'undefined' && chrome.browserOS) {
      this.capabilities.hasBrowserOSAPI = true;
      this.capabilities.hasAccessibilityTree = typeof chrome.browserOS.getAccessibilityTree === 'function';
      this.capabilities.hasJSExecutionAPI = typeof chrome.browserOS.executeJavaScript === 'function';
      this.capabilities.hasScreenshotAPI = typeof chrome.browserOS.captureScreenshot === 'function';
      this.capabilities.hasAgenticMode = true;
    }

    // Atlas-specific capabilities
    if (this.browserType === 'atlas') {
      // Atlas uses standard Chrome APIs but with OWL architecture
      // Check for ephemeral context support
      this.capabilities.hasEphemeralContext = true;
      this.capabilities.hasAgenticMode = true;
    }

    // Comet-specific capabilities
    if (this.browserType === 'comet') {
      // Comet has agentic browsing features
      this.capabilities.hasAgenticMode = true;
    }

    // Brave Leo capabilities
    if (this.browserType === 'brave') {
      // Check for Leo API (may not be exposed to extensions yet)
      this.capabilities.hasBraveLeoAPI = typeof chrome.braveAI !== 'undefined';
      this.capabilities.hasAgenticMode = this.capabilities.hasBraveLeoAPI;
    }

    // Standard Chrome capabilities (baseline)
    this.capabilities.hasScreenshotAPI = typeof chrome.tabs !== 'undefined' && 
                                         typeof chrome.tabs.captureVisibleTab === 'function';

    console.log('[Armorly Browser Detector] Capabilities:', this.capabilities);
  }

  /**
   * Get BrowserOS version
   * @returns {Promise<string>} Version string
   */
  async getBrowserOSVersion() {
    try {
      if (chrome.browserOS && chrome.browserOS.getVersion) {
        return await chrome.browserOS.getVersion();
      }
    } catch (error) {
      console.warn('[Armorly Browser Detector] Could not get BrowserOS version:', error);
    }
    return 'unknown';
  }

  /**
   * Extract version from user agent
   * @param {string} userAgent - User agent string
   * @param {string} browserName - Browser name to extract version for
   * @returns {string} Version string
   */
  extractVersionFromUA(userAgent, browserName) {
    const regex = new RegExp(`${browserName}\\/(\\d+\\.\\d+\\.\\d+\\.\\d+)`);
    const match = userAgent.match(regex);
    return match ? match[1] : 'unknown';
  }

  /**
   * Check if browser is agentic
   * @returns {boolean} True if browser has agentic capabilities
   */
  isAgenticBrowser() {
    return this.capabilities.hasAgenticMode;
  }

  /**
   * Check if browser has specific capability
   * @param {string} capability - Capability name
   * @returns {boolean} True if capability exists
   */
  hasCapability(capability) {
    return this.capabilities[capability] === true;
  }

  /**
   * Get browser type
   * @returns {string} Browser type
   */
  getBrowserType() {
    return this.browserType;
  }

  /**
   * Get browser version
   * @returns {string} Browser version
   */
  getBrowserVersion() {
    return this.browserVersion;
  }

  /**
   * Get all capabilities
   * @returns {Object} Capabilities object
   */
  getCapabilities() {
    return { ...this.capabilities };
  }

  /**
   * Get detection status
   * @returns {boolean} True if detection complete
   */
  isDetectionComplete() {
    return this.detectionComplete;
  }

  /**
   * Get browser display name
   * @returns {string} Human-readable browser name
   */
  getBrowserDisplayName() {
    const names = {
      browseros: 'BrowserOS',
      atlas: 'ChatGPT Atlas',
      comet: 'Perplexity Comet',
      brave: 'Brave Browser',
      arc: 'Arc Browser',
      chrome: 'Google Chrome',
    };
    return names[this.browserType] || 'Unknown Browser';
  }

  /**
   * Get protection level based on browser
   * @returns {string} Protection level: 'maximum', 'enhanced', 'standard'
   */
  getProtectionLevel() {
    if (this.capabilities.hasBrowserOSAPI) {
      return 'maximum'; // Full API interception available
    }
    if (this.capabilities.hasAgenticMode) {
      return 'enhanced'; // Agentic features detected
    }
    return 'standard'; // Standard Chrome protection
  }

  /**
   * Get recommended security settings
   * @returns {Object} Recommended settings
   */
  getRecommendedSettings() {
    const settings = {
      enableDOMScanning: true,
      enableStorageMonitoring: true,
      enableNetworkMonitoring: true,
      enableCrossTabDetection: true,
      enablePromptInjectionDetection: true,
      enableFormValidation: true,
      enableBehavioralAnalysis: false,
      enableAPIInterception: false,
      enableAccessibilityTreeSanitization: false,
      threatSensitivity: 'medium', // low, medium, high
    };

    // Adjust based on browser type
    if (this.browserType === 'browseros') {
      settings.enableAPIInterception = true;
      settings.enableAccessibilityTreeSanitization = true;
      settings.threatSensitivity = 'high';
    }

    if (this.isAgenticBrowser()) {
      settings.enableBehavioralAnalysis = true;
      settings.threatSensitivity = 'high';
    }

    return settings;
  }

  /**
   * Get browser-specific threat patterns
   * @returns {Array<string>} Threat pattern categories
   */
  getBrowserSpecificThreats() {
    const threats = ['prompt_injection', 'memory_poisoning', 'csrf', 'xss'];

    if (this.capabilities.hasBrowserOSAPI) {
      threats.push('browseros_api_abuse', 'accessibility_tree_injection');
    }

    if (this.capabilities.hasAgenticMode) {
      threats.push('agent_hijacking', 'cross_domain_escalation', 'form_manipulation');
    }

    if (this.capabilities.hasScreenshotAPI) {
      threats.push('screenshot_exfiltration');
    }

    if (this.capabilities.hasJSExecutionAPI) {
      threats.push('js_execution_abuse');
    }

    return threats;
  }
}

