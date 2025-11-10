/**
 * Content Script for Armorly
 *
 * Main orchestrator that runs on every webpage. Coordinates:
 * - DOM scanning for prompt injection attacks
 * - Communication with background service worker
 * - Silent threat blocking
 * - AI agent activity detection
 *
 * @module content-script
 * @author Armorly Security Team
 * @license MIT
 */

(function() {
  'use strict';

  // Prevent multiple injections
  if (window.__armorlyInjected) {
    return;
  }
  window.__armorlyInjected = true;

  /**
   * Check if protection components are available
   * On non-AI platforms, only console-wrapper and content-script are loaded
   * On AI platforms, all 14 protection components are loaded
   */
  const hasProtectionComponents = typeof ContentSanitizer !== 'undefined';

  if (!hasProtectionComponents) {
    // Not an AI platform - only console wrapper was loaded
    console.log('[Armorly] Not an AI platform - protection disabled');
    return; // Exit early
  }

  console.log('[Armorly] AI platform detected - initializing protection');

  /**
   * Initialize Content Sanitizer (BLOCKING ENGINE)
   */
  let sanitizer = null;

  try {
    // eslint-disable-next-line no-undef
    if (typeof ContentSanitizer !== 'undefined') {
      // eslint-disable-next-line no-undef
      sanitizer = new ContentSanitizer();
      window.armorlySanitizer = sanitizer; // Make available globally
      console.log('[Armorly] Content Sanitizer initialized - BLOCKING MODE ACTIVE');
    }
  } catch (error) {
    console.error('[Armorly] Failed to initialize Content Sanitizer:', error);
  }

  /**
   * Initialize Mutation Blocker (REAL-TIME PROTECTION)
   */
  let mutationBlocker = null;

  try {
    // eslint-disable-next-line no-undef
    if (typeof MutationBlocker !== 'undefined') {
      // eslint-disable-next-line no-undef
      mutationBlocker = new MutationBlocker();
      mutationBlocker.start();
      console.log('[Armorly] Mutation Blocker started - REAL-TIME PROTECTION ACTIVE');
    }
  } catch (error) {
    console.error('[Armorly] Failed to initialize Mutation Blocker:', error);
  }

  /**
   * Initialize Clipboard Protector (CLIPBOARD SECURITY)
   */
  let clipboardProtector = null;

  try {
    // eslint-disable-next-line no-undef
    if (typeof ClipboardProtector !== 'undefined') {
      // eslint-disable-next-line no-undef
      clipboardProtector = new ClipboardProtector();
      clipboardProtector.start();
      console.log('[Armorly] Clipboard Protector started - CLIPBOARD PROTECTION ACTIVE');
    }
  } catch (error) {
    console.error('[Armorly] Failed to initialize Clipboard Protector:', error);
  }

  /**
   * Initialize Privacy Shield (ANTI-FINGERPRINTING)
   */
  let privacyShield = null;

  try {
    // eslint-disable-next-line no-undef
    if (typeof PrivacyShield !== 'undefined') {
      // eslint-disable-next-line no-undef
      privacyShield = new PrivacyShield();
      privacyShield.start();
      console.log('[Armorly] Privacy Shield started - ANTI-FINGERPRINTING ACTIVE');
    }
  } catch (error) {
    console.error('[Armorly] Failed to initialize Privacy Shield:', error);
  }

  /**
   * Initialize Memory Protector (MEMORY POISONING PREVENTION)
   */
  let memoryProtector = null;

  try {
    // eslint-disable-next-line no-undef
    if (typeof MemoryProtector !== 'undefined') {
      // eslint-disable-next-line no-undef
      memoryProtector = new MemoryProtector();
      memoryProtector.start();
      console.log('[Armorly] Memory Protector started - MEMORY PROTECTION ACTIVE');
    }
  } catch (error) {
    console.error('[Armorly] Failed to initialize Memory Protector:', error);
  }

  /**
   * Initialize Form Interceptor (INPUT PROTECTION - CRITICAL FOR GANDALF)
   */
  let formInterceptor = null;

  try {
    // eslint-disable-next-line no-undef
    if (typeof FormInterceptor !== 'undefined') {
      // eslint-disable-next-line no-undef
      formInterceptor = new FormInterceptor();
      formInterceptor.start();
      console.log('[Armorly] Form Interceptor started - INPUT PROTECTION ACTIVE');
    }
  } catch (error) {
    console.error('[Armorly] Failed to initialize Form Interceptor:', error);
  }

  /**
   * Initialize Output Validator (OUTPUT VALIDATION)
   */
  let outputValidator = null;

  try {
    // eslint-disable-next-line no-undef
    if (typeof OutputValidator !== 'undefined') {
      // eslint-disable-next-line no-undef
      outputValidator = new OutputValidator();
      outputValidator.start();
      console.log('[Armorly] Output Validator started - OUTPUT VALIDATION ACTIVE');
    }
  } catch (error) {
    console.error('[Armorly] Failed to initialize Output Validator:', error);
  }

  /**
   * Initialize Action Authorizer (EXCESSIVE AGENCY PROTECTION)
   */
  let actionAuthorizer = null;

  try {
    // eslint-disable-next-line no-undef
    if (typeof ActionAuthorizer !== 'undefined') {
      // eslint-disable-next-line no-undef
      actionAuthorizer = new ActionAuthorizer();
      actionAuthorizer.start();
      console.log('[Armorly] Action Authorizer started - ACTION AUTHORIZATION ACTIVE');
    }
  } catch (error) {
    console.error('[Armorly] Failed to initialize Action Authorizer:', error);
  }

  /**
   * Initialize Context Analyzer (CONTEXT-AWARE DETECTION)
   */
  let contextAnalyzer = null;

  try {
    // eslint-disable-next-line no-undef
    if (typeof ContextAnalyzer !== 'undefined') {
      // eslint-disable-next-line no-undef
      contextAnalyzer = new ContextAnalyzer();
      contextAnalyzer.start();
      console.log('[Armorly] Context Analyzer started - CONTEXT-AWARE DETECTION ACTIVE');
    }
  } catch (error) {
    console.error('[Armorly] Failed to initialize Context Analyzer:', error);
  }

  /**
   * Initialize Confidence Scorer (OVERRELIANCE PROTECTION)
   */
  let confidenceScorer = null;

  try {
    // eslint-disable-next-line no-undef
    if (typeof ConfidenceScorer !== 'undefined') {
      // eslint-disable-next-line no-undef
      confidenceScorer = new ConfidenceScorer();
      confidenceScorer.start();
      console.log('[Armorly] Confidence Scorer started - CONFIDENCE SCORING ACTIVE');
    }
  } catch (error) {
    console.error('[Armorly] Failed to initialize Confidence Scorer:', error);
  }

  /**
   * Initialize DOM scanner (DETECTION)
   */
  let scanner = null;

  try {
    // eslint-disable-next-line no-undef
    scanner = new DOMScanner();
  } catch (error) {
    // Silent failure - don't log to avoid noise
  }

  /**
   * Initialize AI Response Scanner (CRITICAL: RESPONSE MONITORING)
   */
  let responseScanner = null;

  try {
    // eslint-disable-next-line no-undef
    if (typeof AIResponseScanner !== 'undefined') {
      // eslint-disable-next-line no-undef
      responseScanner = new AIResponseScanner();
      responseScanner.start();
      console.log('[Armorly] AI Response Scanner started - MONITORING AI RESPONSES FOR THREATS');
    }
  } catch (error) {
    console.error('[Armorly] Failed to initialize AI Response Scanner:', error);
  }

  /**
   * Initialize Conversation Integrity Monitor (CRITICAL: TAMPERING DETECTION)
   */
  let conversationIntegrity = null;

  try {
    // eslint-disable-next-line no-undef
    if (typeof ConversationIntegrityMonitor !== 'undefined') {
      // eslint-disable-next-line no-undef
      conversationIntegrity = new ConversationIntegrityMonitor();
      conversationIntegrity.start();
      console.log('[Armorly] Conversation Integrity Monitor started - DETECTING CONVERSATION TAMPERING');
    }
  } catch (error) {
    console.error('[Armorly] Failed to initialize Conversation Integrity Monitor:', error);
  }

  /**
   * Initialize Multi-turn Attack Detector (CRITICAL: ATTACK CHAIN DETECTION)
   */
  let multiTurnDetector = null;

  try {
    // eslint-disable-next-line no-undef
    if (typeof MultiTurnAttackDetector !== 'undefined') {
      // eslint-disable-next-line no-undef
      multiTurnDetector = new MultiTurnAttackDetector();
      multiTurnDetector.start();

      // Make available globally for AI Response Scanner integration
      window.armorlyMultiTurnDetector = multiTurnDetector;

      console.log('[Armorly] Multi-turn Attack Detector started - DETECTING ATTACK CHAINS');
    }
  } catch (error) {
    console.error('[Armorly] Failed to initialize Multi-turn Attack Detector:', error);
  }

  /**
   * Initialize API Response Validator (CRITICAL: MITM DETECTION)
   */
  let apiValidator = null;

  try {
    // eslint-disable-next-line no-undef
    if (typeof APIResponseValidator !== 'undefined') {
      // eslint-disable-next-line no-undef
      apiValidator = new APIResponseValidator();
      apiValidator.start();
      console.log('[Armorly] API Response Validator started - VALIDATING API RESPONSES');
    }
  } catch (error) {
    console.error('[Armorly] Failed to initialize API Response Validator:', error);
  }

  /**
   * Initialize Browser API Monitor
   */
  let apiMonitor = null;

  try {
    // eslint-disable-next-line no-undef
    if (typeof BrowserAPIMonitor !== 'undefined') {
      // eslint-disable-next-line no-undef
      apiMonitor = new BrowserAPIMonitor();
      apiMonitor.startMonitoring();
    }
  } catch (error) {
    // Silent failure
  }

  /**
   * Initialize Network Monitor
   */
  let networkMonitor = null;

  try {
    // eslint-disable-next-line no-undef
    if (typeof NetworkMonitor !== 'undefined') {
      // eslint-disable-next-line no-undef
      networkMonitor = new NetworkMonitor();
      networkMonitor.startMonitoring();
    }
  } catch (error) {
    // Silent failure
  }

  /**
   * Protection state
   */
  let protectionEnabled = true;
  let aiAgentDetected = false;

  /**
   * Detect if an AI agent is active on this page
   * Looks for indicators of ChatGPT Atlas, Perplexity Comet, BrowserOS, etc.
   */
  function detectAIAgent() {
    // Check for ChatGPT Atlas indicators
    const isChatGPT = window.location.hostname.includes('chatgpt.com') ||
                      window.location.hostname.includes('openai.com');

    // Check for Perplexity Comet indicators
    const isPerplexity = window.location.hostname.includes('perplexity.ai');

    // Check for BrowserOS indicators
    const isBrowserOS = window.location.hostname.includes('browseros.com');

    // Check for AI agent activity in the page
    const hasAIIndicators = document.querySelector('[data-ai-agent]') !== null ||
                           document.querySelector('[class*="ai-"]') !== null ||
                           document.querySelector('[id*="chatgpt"]') !== null;

    aiAgentDetected = isChatGPT || isPerplexity || isBrowserOS || hasAIIndicators;

    if (aiAgentDetected) {
      notifyBackgroundOfAIAgent();
    }

    return aiAgentDetected;
  }

  /**
   * Notify background worker that an AI agent is active
   */
  function notifyBackgroundOfAIAgent() {
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({
        type: 'AI_AGENT_DETECTED',
        url: window.location.href,
        timestamp: Date.now()
      }).catch(error => {
        console.error('[Armorly] Error notifying background:', error);
      });
    }
  }

  /**
   * Start protection
   */
  function startProtection() {
    if (!protectionEnabled) {
      return;
    }

    // Detect AI agents
    detectAIAgent();

    // PHASE 1: SANITIZE PAGE (BLOCKING)
    if (sanitizer) {
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
          sanitizer.sanitizePage();
        });
      } else {
        sanitizer.sanitizePage();
      }
    }

    // PHASE 2: START REAL-TIME MONITORING (BLOCKING)
    if (mutationBlocker) {
      mutationBlocker.start();
    }

    // PHASE 3: START DOM SCANNING (DETECTION)
    if (scanner) {
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
          scanner.startScanning();
        });
      } else {
        scanner.startScanning();
      }
    }
  }

  /**
   * Stop protection
   */
  function stopProtection() {
    if (scanner) {
      scanner.stopScanning();
    }
    if (mutationBlocker) {
      mutationBlocker.stop();
    }
    if (sanitizer) {
      sanitizer.setEnabled(false);
    }
    if (clipboardProtector) {
      clipboardProtector.stop();
    }
    if (privacyShield) {
      privacyShield.setEnabled(false);
    }
    if (memoryProtector) {
      memoryProtector.setEnabled(false);
    }
    if (formInterceptor) {
      formInterceptor.stop();
    }
    if (outputValidator) {
      outputValidator.setEnabled(false);
    }
    if (actionAuthorizer) {
      actionAuthorizer.setEnabled(false);
    }
    if (contextAnalyzer) {
      contextAnalyzer.setEnabled(false);
    }
    if (confidenceScorer) {
      confidenceScorer.setEnabled(false);
    }
    if (responseScanner) {
      responseScanner.stop();
    }
    if (conversationIntegrity) {
      conversationIntegrity.stop();
    }
    if (multiTurnDetector) {
      multiTurnDetector.stop();
    }
    if (apiValidator) {
      apiValidator.stop();
    }
  }

  /**
   * Handle messages from background service worker and popup
   */
  if (typeof chrome !== 'undefined' && chrome.runtime) {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      switch (message.type) {
        case 'SCAN_PAGE':
          // Manual scan requested
          if (scanner) {
            scanner.clearThreats();
            scanner.scanInitialDOM();
            const summary = scanner.getThreatSummary();
            sendResponse({ success: true, summary });
          } else {
            sendResponse({ success: false, error: 'Scanner not initialized' });
          }
          break;

        case 'FORCE_SCAN':
          // Force a new scan (from popup)
          if (scanner) {
            scanner.clearThreats();
            const threats = scanner.scanInitialDOM();
            sendResponse({ success: true, threats: scanner.threats.length });
          } else {
            sendResponse({ success: false, error: 'Scanner not initialized' });
          }
          break;

        case 'GET_THREATS':
          // Return current threats
          if (scanner) {
            const summary = scanner.getThreatSummary();
            sendResponse({ success: true, summary, threats: scanner.threats });
          } else {
            sendResponse({ success: false, error: 'Scanner not initialized' });
          }
          break;

        case 'ENABLE_PROTECTION':
          protectionEnabled = true;
          startProtection();
          sendResponse({ success: true });
          break;

        case 'DISABLE_PROTECTION':
          protectionEnabled = false;
          stopProtection();
          sendResponse({ success: true });
          break;

        case 'GET_AI_INDICATORS': {
          // Return DOM indicators for AI agent detection
          const indicators = detectAIIndicators();
          sendResponse({ success: true, indicators });
          break;
        }

        case 'GET_USER_AGENT':
          // Return user agent string
          sendResponse({ success: true, userAgent: navigator.userAgent });
          break;

        case 'SHOW_WARNING':
          // Silent operation - warnings are handled by background service worker
          // No user-facing overlays or popups
          sendResponse({ success: true, silentMode: true });
          break;

        default:
          sendResponse({ success: false, error: 'Unknown message type' });
      }

      return true; // Keep message channel open for async response
    });
  }

  /**
   * Detect AI agent indicators in the DOM
   * Returns array of indicator strings found on the page
   */
  function detectAIIndicators() {
    const indicators = [];

    // ChatGPT Atlas indicators
    if (document.querySelector('[id*="chatgpt"]') ||
        document.querySelector('[class*="chatgpt"]')) {
      indicators.push('chatgpt-prompt-textarea');
    }
    if (document.querySelector('[class*="composer"]')) {
      indicators.push('composer-background');
    }

    // Perplexity Comet indicators
    if (document.querySelector('[class*="perplexity"]') ||
        document.querySelector('[data-testid*="search"]')) {
      indicators.push('perplexity-search');
    }
    if (document.querySelector('[class*="copilot"]')) {
      indicators.push('copilot-mode');
    }

    // BrowserOS indicators
    if (document.querySelector('[class*="browser-os"]') ||
        document.querySelector('[data-agent="true"]')) {
      indicators.push('browser-os-agent');
    }

    // Generic AI assistant indicators
    if (document.querySelector('[role="textbox"][placeholder*="Ask"]') ||
        document.querySelector('[placeholder*="chat"]') ||
        document.querySelector('[placeholder*="assistant"]')) {
      indicators.push('ai-assistant');
    }

    // Check for active input focus (user is interacting with AI)
    const activeElement = document.activeElement;
    if (activeElement &&
        (activeElement.tagName === 'TEXTAREA' ||
         activeElement.contentEditable === 'true')) {
      indicators.push('active-input');
    }

    return indicators;
  }

  /**
   * Initialize protection on page load
   */
  function initialize() {
    // Load settings from storage
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.get(['protectionEnabled'], (result) => {
        protectionEnabled = result.protectionEnabled !== false; // Default to true

        if (protectionEnabled) {
          startProtection();
        }
      });
    } else {
      // Fallback if chrome.storage not available
      startProtection();
    }
  }

  // Start initialization
  initialize();

})();

