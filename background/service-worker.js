/**
 * Background Service Worker for Armorly
 * 
 * Main coordinator for all protection components:
 * - Manages extension lifecycle
 * - Coordinates CSRF detection and DOM scanning
 * - Handles message passing between components
 * - Manages threat logs and statistics
 * - Controls badge and notifications
 * 
 * @module service-worker
 * @author Armorly Security Team
 * @license MIT
 */

import { CSRFDetector } from '../lib/csrf-detector.js';
import { PatternLibrary } from '../lib/pattern-library.js';
import { StorageManager } from '../lib/storage-manager.js';
import { DomainManager } from '../lib/domain-manager.js';
import { PerformanceMonitor } from '../lib/performance-monitor.js';
import { ThreatDetector } from './threat-detector.js';
import { MemoryMonitor } from './memory-monitor.js';
import { AIAgentDetector } from './ai-agent-detector.js';
import { ThreatIntelligence } from './threat-intelligence.js';
import { RequestBlocker } from './request-blocker.js';
import { TokenConsumptionMonitor } from './token-consumption-monitor.js';
import { NetworkInterceptor } from './network-interceptor.js';

console.log('[Armorly] Service worker starting...');

/**
 * Initialize core components
 */
const csrfDetector = new CSRFDetector();
const patternLibrary = new PatternLibrary();
const storageManager = new StorageManager();
const domainManager = new DomainManager();
const performanceMonitor = new PerformanceMonitor();
const threatDetector = new ThreatDetector();
const memoryMonitor = new MemoryMonitor(patternLibrary);
const aiAgentDetector = new AIAgentDetector();
const threatIntelligence = new ThreatIntelligence(patternLibrary);

/**
 * Initialize Request Blocker (Network-Level Protection)
 */
const requestBlocker = new RequestBlocker();
requestBlocker.initialize().then(() => {
  console.log('[Armorly] Request Blocker initialized - NETWORK PROTECTION ACTIVE');
}).catch(error => {
  console.error('[Armorly] Request Blocker initialization failed:', error);
});

/**
 * Initialize Network Interceptor (Advanced Network Protection)
 */
const networkInterceptor = new NetworkInterceptor();
networkInterceptor.setThreatCallback((threat) => {
  console.log('[Armorly] Network threat detected:', threat);
  // Log threat to storage
  logThreat({
    type: 'network',
    severity: threat.severity || 'high',
    description: threat.description,
    url: threat.url,
    timestamp: Date.now(),
    details: threat
  });
});
console.log('[Armorly] Network Interceptor initialized - ADVANCED NETWORK PROTECTION ACTIVE');

/**
 * Initialize Token Consumption Monitor (DoS Protection)
 */
const tokenMonitor = new TokenConsumptionMonitor();
tokenMonitor.initialize().then(() => {
  console.log('[Armorly] Token Monitor initialized - DoS PROTECTION ACTIVE');
}).catch(error => {
  console.error('[Armorly] Token Monitor initialization failed:', error);
});

// Initialize storage
storageManager.initialize().catch(error => {
  console.error('[Armorly] Storage initialization failed:', error);
});

// Check for threat intelligence updates on startup
setTimeout(async () => {
  const updateResult = await threatIntelligence.autoUpdateCheck();
  if (updateResult) {
    console.log('[Armorly] Startup update check:', updateResult);
  }
}, 5000); // Wait 5 seconds after startup

/**
 * Extension state
 */
let protectionEnabled = true;
let threatLog = [];
let statistics = {
  totalThreatsBlocked: 0,
  threatsByType: {},
  lastThreatDetected: null,
  protectionStartDate: Date.now()
};

/**
 * Track which tabs have already been warned about threats
 * Key: tabId, Value: { url, timestamp, score }
 * This prevents showing the same warning repeatedly
 */
const warnedTabs = new Map();

/**
 * Active tabs with AI agents
 */
const aiAgentTabs = new Set();

/**
 * Installation and update handler
 */
chrome.runtime.onInstalled.addListener(async (details) => {
  console.log('[Armorly] Extension installed/updated:', details.reason);

  if (details.reason === 'install') {
    // First installation
    await initializeSettings();
    
    // Show welcome page
    chrome.tabs.create({
      url: chrome.runtime.getURL('welcome.html')
    });
  } else if (details.reason === 'update') {
    // Extension updated
    console.log('[Armorly] Updated to version:', chrome.runtime.getManifest().version);
  }

  // Set default badge
  updateBadge(null, 'safe');
});

/**
 * Initialize default settings
 */
async function initializeSettings() {
  const defaultSettings = {
    protectionEnabled: true,
    autoBlock: true,
    showNotifications: true,
    sensitivityLevel: 'balanced',
    whitelistedDomains: [],
    blacklistedDomains: [],
    memoryAuditFrequency: 'weekly'
  };

  await chrome.storage.local.set({
    settings: defaultSettings,
    threatLog: [],
    statistics: statistics
  });

  console.log('[Armorly] Default settings initialized');
}

/**
 * Load settings from storage
 */
async function loadSettings() {
  const result = await chrome.storage.local.get(['settings', 'threatLog', 'statistics']);
  
  if (result.settings) {
    protectionEnabled = result.settings.protectionEnabled !== false;
  }
  
  if (result.threatLog) {
    threatLog = result.threatLog;
  }
  
  if (result.statistics) {
    statistics = result.statistics;
  }

  console.log('[Armorly] Settings loaded, protection:', protectionEnabled);
}

// Load settings on startup
loadSettings();

/**
 * Message handler from content scripts and popup
 */
chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
  console.log('[Armorly] Received message:', message.type, 'from:', sender.tab?.id || 'popup');

  switch (message.type) {
    case 'PING':
      // Health check for integration tests
      sendResponse({ success: true, status: 'alive', version: '1.0.0' });
      break;

    case 'THREATS_DETECTED':
      handleThreatsDetected(message, sender.tab);
      sendResponse({ success: true });
      break;

    case 'AI_AGENT_DETECTED':
      handleAIAgentDetected(sender.tab);
      sendResponse({ success: true });
      break;

    case 'GET_THREAT_LOG':
      sendResponse({ success: true, threatLog, statistics });
      break;

    case 'GET_PROTECTION_STATUS':
      sendResponse({
        success: true,
        enabled: protectionEnabled,
        statistics
      });
      break;

    case 'GET_AI_AGENT_STATUS': {
      const agent = aiAgentDetector.getActiveAgent(message.tabId);
      sendResponse({
        success: true,
        agent: agent
      });
      break;
    }

    case 'SCAN_MEMORIES':
      // Scan memories from page content
      if (message.memories && Array.isArray(message.memories)) {
        const scanResults = memoryMonitor.scanMemoriesFromPage(message.memories);
        sendResponse({ success: true, results: scanResults });
      } else {
        sendResponse({ success: false, error: 'Invalid memories data' });
      }
      break;

    case 'GET_MEMORY_STATS': {
      const memoryStats = memoryMonitor.getStatistics();
      sendResponse({ success: true, stats: memoryStats });
      break;
    }

    case 'ENABLE_PROTECTION':
      protectionEnabled = true;
      saveSettings();
      sendResponse({ success: true });
      break;

    case 'DISABLE_PROTECTION':
      protectionEnabled = false;
      saveSettings();
      sendResponse({ success: true });
      break;

    case 'SCAN_PAGE':
      scanPage(sender.tab.id).then(result => {
        sendResponse(result);
      });
      return true; // Async response

    case 'CLEAR_THREAT_LOG':
      threatLog = [];
      statistics = {
        totalThreatsBlocked: 0,
        totalPagesScanned: 0,
        lastThreatDetected: null,
        threatsByType: {}
      };
      await saveThreatLog();
      await saveStatistics();
      sendResponse({ success: true });
      break;

    case 'WARNING_DISMISSED':
      logUserAction(message.url, 'dismissed_warning', message.threat);
      sendResponse({ success: true });
      break;

    case 'ADD_TO_WHITELIST':
      domainManager.addToWhitelist(message.domain).then(success => {
        sendResponse({ success });
      });
      return true; // Async response

    case 'ADD_TO_BLACKLIST':
      domainManager.addToBlacklist(message.domain).then(success => {
        sendResponse({ success });
      });
      return true; // Async response

    case 'REMOVE_FROM_WHITELIST':
      domainManager.removeFromWhitelist(message.domain).then(success => {
        sendResponse({ success });
      });
      return true; // Async response

    case 'REMOVE_FROM_BLACKLIST':
      domainManager.removeFromBlacklist(message.domain).then(success => {
        sendResponse({ success });
      });
      return true; // Async response

    case 'GET_DOMAIN_LISTS': {
      const lists = domainManager.getAllLists();
      sendResponse({ success: true, lists });
      break;
    }

    case 'GET_PROTECTION_LEVEL': {
      const level = domainManager.getProtectionLevel(message.url);
      sendResponse({ success: true, level });
      break;
    }

    case 'EXPORT_DOMAIN_LISTS': {
      const exported = domainManager.exportLists();
      sendResponse({ success: true, data: exported });
      break;
    }

    case 'IMPORT_DOMAIN_LISTS':
      domainManager.importLists(message.data).then(result => {
        sendResponse(result);
      });
      return true; // Async response

    case 'CHECK_THREAT_INTEL_UPDATES':
      threatIntelligence.checkForUpdates().then(result => {
        sendResponse(result);
      });
      return true; // Async response

    case 'GET_THREAT_INTEL_STATS': {
      const intelStats = threatIntelligence.getStatistics();
      sendResponse({ success: true, stats: intelStats });
      break;
    }

    case 'GET_PERFORMANCE_STATS': {
      const perfStats = performanceMonitor.getStats();
      sendResponse({ success: true, stats: perfStats });
      break;
    }

    case 'GET_PERFORMANCE_REPORT': {
      const perfReport = performanceMonitor.getReport();
      sendResponse({ success: true, report: perfReport });
      break;
    }

    case 'RESET_PERFORMANCE_STATS':
      performanceMonitor.reset();
      sendResponse({ success: true });
      break;

    case 'SET_AUTO_UPDATE':
      threatIntelligence.setAutoUpdate(message.enabled).then(() => {
        sendResponse({ success: true });
      });
      return true; // Async response

    case 'SET_UPDATE_FREQUENCY':
      threatIntelligence.setUpdateFrequency(message.frequency).then(() => {
        sendResponse({ success: true });
      }).catch(error => {
        sendResponse({ success: false, error: error.message });
      });
      return true; // Async response

    default:
      sendResponse({ success: false, error: 'Unknown message type' });
  }

  return true; // Keep message channel open
});

/**
 * Handle threats detected by content script
 * 
 * @param {Object} message - Message with threat details
 * @param {Object} tab - Tab where threats were detected
 */
async function handleThreatsDetected(message, tab) {
  if (!protectionEnabled) return;

  const { threats, url, timestamp } = message;

  console.log(`[Armorly] ${threats.length} threats detected on ${url}`);

  // Check domain protection level
  const protectionLevel = domainManager.getProtectionLevel(url);

  if (protectionLevel === 'trusted') {
    console.log(`[Armorly] Domain is whitelisted, skipping threat detection: ${url}`);
    return;
  }

  if (protectionLevel === 'blocked') {
    console.log(`[Armorly] Domain is blacklisted, blocking immediately: ${url}`);
    // Show warning overlay immediately
    chrome.tabs.sendMessage(tab.id, {
      type: 'SHOW_WARNING',
      threat: {
        severity: 'CRITICAL',
        score: 100,
        threats: [{ type: 'BLACKLISTED_DOMAIN', reason: 'Domain is on your blacklist' }],
        url
      }
    }).catch(err => console.error('[Armorly] Error showing warning:', err));
    return;
  }

  // Check for AI agent activity and apply threat multiplier
  const agentMultiplier = aiAgentDetector.getThreatMultiplier(tab.id);
  const isOnChatGPT = aiAgentDetector.isOnChatGPT(url);
  const aiPlatform = aiAgentDetector.checkAIBrowserPlatform(url);

  // Calculate base threat score
  let baseScore = 0;
  threats.forEach(threat => {
    baseScore += threat.score || 0;
  });

  // Apply AI agent context multiplier for heightened protection
  let totalScore = baseScore * agentMultiplier;

  // Extra multiplier if user is on ChatGPT (memory poisoning risk)
  if (isOnChatGPT) {
    totalScore *= 1.5;
    console.log(`[Armorly] User on ChatGPT - applying 1.5x multiplier`);
  }

  // Log AI agent context
  if (agentMultiplier > 1.0) {
    console.log(`[Armorly] AI agent active - threat score: ${baseScore} → ${totalScore} (${agentMultiplier}x multiplier)`);
  }

  // Determine severity based on adjusted score
  let severity = 'LOW';
  if (totalScore >= 90) severity = 'CRITICAL';
  else if (totalScore >= 70) severity = 'HIGH';
  else if (totalScore >= 40) severity = 'MEDIUM';

  // Log threat with AI agent context
  const activeAgent = aiAgentDetector.getActiveAgent(tab.id);
  const threatEntry = {
    id: generateId(),
    timestamp,
    url,
    threats,
    baseScore,
    totalScore,
    severity,
    blocked: severity === 'CRITICAL',
    tabId: tab.id,
    aiAgentActive: activeAgent !== null,
    aiAgentType: activeAgent?.type || null,
    threatMultiplier: agentMultiplier,
    onChatGPT: isOnChatGPT,
    aiPlatform: aiPlatform.platform
  };

  threatLog.unshift(threatEntry);
  
  // Keep only last 1000 threats
  if (threatLog.length > 1000) {
    threatLog = threatLog.slice(0, 1000);
  }

  await saveThreatLog();

  // Update statistics
  statistics.totalThreatsBlocked++;
  statistics.lastThreatDetected = timestamp;
  threats.forEach(threat => {
    statistics.threatsByType[threat.type] = (statistics.threatsByType[threat.type] || 0) + 1;
  });
  await saveStatistics();

  // Update badge
  updateBadge(tab.id, severity.toLowerCase());

  // Show notification for high severity
  if (severity === 'CRITICAL' || severity === 'HIGH') {
    showNotification(threatEntry);
  }

  // Check if we already warned this tab about threats
  const existingWarning = warnedTabs.get(tab.id);
  if (existingWarning && existingWarning.url === url) {
    console.log('[Armorly] Already warned this tab, not showing overlay again');
    return;
  }

  // Block if critical (check sensitivity settings)
  const shouldShowWarning = await shouldBlockThreat(severity, totalScore);
  if (shouldShowWarning) {
    // Mark this tab as warned
    warnedTabs.set(tab.id, {
      url: url,
      timestamp: Date.now(),
      score: totalScore
    });

    chrome.tabs.sendMessage(tab.id, {
      type: 'SHOW_WARNING',
      threat: {
        type: 'MULTIPLE_THREATS',
        severity: severity,
        description: `${threats.length} critical threats detected on this page`,
        score: totalScore,
        indicators: threats.map(t => t.description || t.type).slice(0, 5)
      }
    });
  }
}

/**
 * Determine if a threat should trigger a warning based on sensitivity settings
 *
 * @param {string} severity - Threat severity
 * @param {number} score - Threat score
 * @returns {Promise<boolean>} Whether to show warning
 */
async function shouldBlockThreat(severity, score) {
  const result = await chrome.storage.local.get(['settings']);
  const sensitivityLevel = result.settings?.sensitivityLevel || 'balanced';
  const showNotifications = result.settings?.showNotifications !== false; // Default to true

  // If notifications are disabled, don't show overlay warnings
  if (!showNotifications) {
    console.log('[Armorly] Notifications disabled, not showing overlay');
    return false;
  }

  switch (sensitivityLevel) {
    case 'strict':
      // Show warnings for MEDIUM and above (score >= 40)
      return score >= 40;

    case 'balanced':
      // Show warnings for HIGH and above (score >= 70)
      return score >= 70;

    case 'permissive':
      // Only show warnings for CRITICAL (score > 90, not including 90)
      return score > 90;

    default:
      return score >= 70; // Default to balanced
  }
}

/**
 * Handle AI agent detection
 *
 * @param {Object} tab - Tab where AI agent was detected
 */
async function handleAIAgentDetected(tab) {
  aiAgentTabs.add(tab.id);

  // Run full AI agent detection with context
  // FIXED: Properly handle fallback for service worker context
  // navigator.userAgent IS available in Chrome service workers
  const userAgent = await chrome.tabs.sendMessage(tab.id, {
    type: 'GET_USER_AGENT'
  }).catch(() => {
    // Fallback to service worker's navigator.userAgent (available in Chrome MV3)
    try {
      return { userAgent: navigator.userAgent };
    } catch (e) {
      return { userAgent: 'Chrome' }; // Safe fallback
    }
  });

  const domIndicators = await aiAgentDetector.requestDOMIndicators(tab.id);

  const detection = await aiAgentDetector.detectAgent(tab.id, tab.url, {
    userAgent: userAgent.userAgent,
    domIndicators,
    hasActiveInput: true
  });

  if (detection.detected) {
    console.log(`[Armorly] AI agent confirmed on tab ${tab.id}:`, detection.agent.type);
    console.log(`[Armorly] Threat multiplier: ${detection.agent.threatMultiplier}x`);

    // Update badge to show heightened protection
    updateBadge(tab.id, 'ai-active');
  } else {
    console.log(`[Armorly] AI agent activity on tab ${tab.id} (low confidence)`);
  }
}

/**
 * Scan a specific page
 * 
 * @param {number} tabId - Tab ID to scan
 * @returns {Promise<Object>} Scan results
 */
async function scanPage(tabId) {
  try {
    const response = await chrome.tabs.sendMessage(tabId, {
      type: 'SCAN_PAGE'
    });
    
    return response;
  } catch (error) {
    console.error('[Armorly] Error scanning page:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Update extension badge
 *
 * @param {number} tabId - Tab ID (null for all tabs)
 * @param {string} status - Status: 'safe', 'medium', 'high', 'critical', 'ai-active'
 *
 * NOTE: Badge updates disabled for silent operation.
 * Extension works silently in the background without visual indicators.
 */
function updateBadge(tabId, status) {
  // Silent mode - no badge updates
  // Users can check status by clicking the extension icon
  return;
}

/**
 * Show desktop notification (DISABLED - Silent operation)
 *
 * @param {Object} threat - Threat details
 */
async function showNotification(threat) {
  // Silent operation - no notifications
  // Threats are logged to console in development mode only
  return;
}

/**
 * Log a threat to the threat log
 */
async function logThreat(threat) {
  const threatEntry = {
    ...threat,
    timestamp: threat.timestamp || Date.now()
  };

  threatLog.unshift(threatEntry);

  // Keep only last 1000 threats
  if (threatLog.length > 1000) {
    threatLog = threatLog.slice(0, 1000);
  }

  await saveThreatLog();

  // Update statistics
  statistics.totalThreatsBlocked++;
  statistics.lastThreatDetected = threatEntry.timestamp;
  if (threat.type) {
    statistics.threatsByType[threat.type] = (statistics.threatsByType[threat.type] || 0) + 1;
  }
  await saveStatistics();
}

/**
 * Save threat log to storage
 */
async function saveThreatLog() {
  await chrome.storage.local.set({ threatLog });
}

/**
 * Save statistics to storage
 */
async function saveStatistics() {
  await chrome.storage.local.set({ statistics });
}

/**
 * Save settings to storage
 */
async function saveSettings() {
  const settings = await chrome.storage.local.get(['settings']);
  settings.settings.protectionEnabled = protectionEnabled;
  await chrome.storage.local.set({ settings: settings.settings });
}

/**
 * Log user action
 * 
 * @param {string} url - URL where action occurred
 * @param {string} action - Action type
 * @param {Object} context - Additional context
 */
function logUserAction(url, action, context) {
  console.log('[Armorly] User action:', action, 'on', url);
  // Could be extended to track user behavior patterns
}

/**
 * Generate unique ID
 * 
 * @returns {string} Unique ID
 */
function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).substring(2);
}

/**
 * Tab update listener
 */
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    // Reset badge for new page
    updateBadge(tabId, 'safe');

    // Clear warning state when navigating to a new page
    const existingWarning = warnedTabs.get(tabId);
    if (existingWarning && existingWarning.url !== tab.url) {
      console.log('[Armorly] Tab navigated to new page, clearing warning state');
      warnedTabs.delete(tabId);
    }

    // Check if navigating to AI browser platform
    const aiPlatform = aiAgentDetector.checkAIBrowserPlatform(tab.url);
    if (aiPlatform.isAIBrowser) {
      console.log(`[Armorly] Navigated to AI platform: ${aiPlatform.platform}`);
      // Detect agent with basic context
      // FIXED: Safe access to navigator.userAgent in service worker
      let userAgent = 'Chrome'; // Safe fallback
      try {
        userAgent = navigator.userAgent || 'Chrome';
      } catch (e) {
        console.warn('[Armorly] Could not access navigator.userAgent:', e);
      }
      await aiAgentDetector.detectAgent(tabId, tab.url, {
        userAgent: userAgent
      });
    } else {
      // Clear AI agent detection when navigating away
      aiAgentTabs.delete(tabId);
      aiAgentDetector.clearAgent(tabId);
    }
  }
});

/**
 * Tab removal listener
 */
chrome.tabs.onRemoved.addListener((tabId) => {
  aiAgentTabs.delete(tabId);
  warnedTabs.delete(tabId);
  aiAgentDetector.clearAgent(tabId);
  console.log('[Armorly] Tab closed, cleared all state');
});

console.log('[Armorly] Service worker initialized');

