/**
 * Popup Script for Armorly
 *
 * Handles the extension popup UI and user interactions
 */

// Debug mode - set to true for verbose logging
const DEBUG_MODE = false;

function debugLog(message, data = null) {
    if (DEBUG_MODE) {
        if (data) {
            console.log(`[Armorly Debug] ${message}`, data);
        } else {
            console.log(`[Armorly Debug] ${message}`);
        }
    }
}

function checkElement(elementId) {
    const element = document.getElementById(elementId);
    const exists = element !== null;
    debugLog(`Element check: ${elementId} - ${exists ? 'EXISTS' : 'MISSING'}`);
    return element;
}

document.addEventListener('DOMContentLoaded', async () => {
    console.log('[Armorly] Popup loaded - Starting initialization');
    debugLog('DOM Content Loaded event fired');

    // Log all available elements in the DOM
    debugLog('Available elements in DOM:', {
        'protection-toggle': !!document.getElementById('protection-toggle'),
        'status-indicator': !!document.getElementById('status-indicator'),
        'status-text': !!document.getElementById('status-text'),
        'threats-blocked': !!document.getElementById('threats-blocked'),
        'pages-scanned': !!document.getElementById('pages-scanned'),
        'avg-overhead': !!document.getElementById('avg-overhead'),
        'perf-status': !!document.getElementById('perf-status'),
        'current-url': !!document.getElementById('current-url'),
        'ai-agent-status': !!document.getElementById('ai-agent-status'),
        'ai-agent-type': !!document.getElementById('ai-agent-type'),
        'ai-multiplier': !!document.getElementById('ai-multiplier'),
        'threat-list': !!document.getElementById('threat-list'),
        'scan-page': !!document.getElementById('scan-page'),
        'check-memory': !!document.getElementById('check-memory'),
        'view-performance': !!document.getElementById('view-performance'),
        'open-settings': !!document.getElementById('open-settings'),
        'view-docs': !!document.getElementById('view-docs')
    });

    try {
        // Initialize UI with detailed logging
        debugLog('Step 1: Loading protection status...');
        await loadProtectionStatus();
        debugLog('Step 1: Complete');

        debugLog('Step 2: Loading statistics...');
        await loadStatistics();
        debugLog('Step 2: Complete');

        debugLog('Step 3: Loading performance stats...');
        await loadPerformanceStats();
        debugLog('Step 3: Complete');

        debugLog('Step 4: Loading current page info...');
        await loadCurrentPageInfo();
        debugLog('Step 4: Complete');

        debugLog('Step 5: Loading AI agent status...');
        await loadAIAgentStatus();
        debugLog('Step 5: Complete');

        debugLog('Step 6: Loading threat log...');
        await loadThreatLog();
        debugLog('Step 6: Complete');

        debugLog('Step 7: Setting up event listeners...');
        setupEventListeners();
        debugLog('Step 7: Complete');

        console.log('[Armorly] Popup initialization complete ✓');
    } catch (error) {
        console.error('[Armorly] Error initializing popup:', error);
        console.error('[Armorly] Error stack:', error.stack);
    }
});

/**
 * Load protection status from background
 */
async function loadProtectionStatus() {
    debugLog('loadProtectionStatus: Starting...');
    try {
        debugLog('loadProtectionStatus: Sending GET_PROTECTION_STATUS message');
        const response = await chrome.runtime.sendMessage({
            type: 'GET_PROTECTION_STATUS'
        });
        debugLog('loadProtectionStatus: Response received', response);

        if (response && response.success) {
            const toggle = checkElement('protection-toggle');
            const statusIndicator = checkElement('status-indicator');
            const statusText = checkElement('status-text');

            if (toggle) {
                toggle.checked = response.enabled;
                debugLog(`loadProtectionStatus: Toggle set to ${response.enabled}`);
            } else {
                debugLog('loadProtectionStatus: WARNING - toggle element not found');
            }

            if (response.enabled) {
                if (statusIndicator) {
                    statusIndicator.style.background = '#10b981';
                    debugLog('loadProtectionStatus: Status indicator set to green');
                }
                if (statusText) {
                    statusText.textContent = 'Protected';
                    statusText.style.color = '#10b981';
                    debugLog('loadProtectionStatus: Status text set to Protected');
                }
            } else {
                if (statusIndicator) {
                    statusIndicator.style.background = '#ef4444';
                    debugLog('loadProtectionStatus: Status indicator set to red');
                }
                if (statusText) {
                    statusText.textContent = 'Disabled';
                    statusText.style.color = '#ef4444';
                    debugLog('loadProtectionStatus: Status text set to Disabled');
                }
            }
        } else {
            debugLog('loadProtectionStatus: Response was not successful', response);
        }
    } catch (error) {
        console.error('[Armorly] Error loading protection status:', error);
        console.error('[Armorly] Error stack:', error.stack);
        debugLog('loadProtectionStatus: FAILED with error', error.message);
    }
}

/**
 * Load statistics from background
 */
async function loadStatistics() {
    debugLog('loadStatistics: Starting...');
    try {
        debugLog('loadStatistics: Sending GET_THREAT_LOG message');
        const response = await chrome.runtime.sendMessage({
            type: 'GET_THREAT_LOG'
        });
        debugLog('loadStatistics: Response received', response);

        if (response && response.success) {
            const { statistics } = response;
            debugLog('loadStatistics: Statistics data', statistics);

            // Update threats blocked
            const threatsBlockedEl = checkElement('threats-blocked');
            if (threatsBlockedEl) {
                const count = statistics.totalThreatsBlocked || 0;
                threatsBlockedEl.textContent = count;
                debugLog(`loadStatistics: Set threats-blocked to ${count}`);
            } else {
                debugLog('loadStatistics: WARNING - threats-blocked element not found');
            }

            // Calculate pages scanned (estimate based on threats)
            const pagesScannedEl = checkElement('pages-scanned');
            if (pagesScannedEl) {
                const pagesScanned = Math.max(statistics.totalThreatsBlocked, 10);
                pagesScannedEl.textContent = pagesScanned;
                debugLog(`loadStatistics: Set pages-scanned to ${pagesScanned}`);
            } else {
                debugLog('loadStatistics: INFO - pages-scanned element not found (optional)');
            }
        } else {
            debugLog('loadStatistics: Response was not successful', response);
        }
    } catch (error) {
        console.error('[Armorly] Error loading statistics:', error);
        console.error('[Armorly] Error stack:', error.stack);
        debugLog('loadStatistics: FAILED with error', error.message);
    }
}

/**
 * Load performance statistics
 */
async function loadPerformanceStats() {
    debugLog('loadPerformanceStats: Starting...');
    try {
        debugLog('loadPerformanceStats: Sending GET_PERFORMANCE_STATS message');
        const response = await chrome.runtime.sendMessage({
            type: 'GET_PERFORMANCE_STATS'
        });
        debugLog('loadPerformanceStats: Response received', response);

        if (response && response.success) {
            const { stats } = response;
            debugLog('loadPerformanceStats: Stats data', stats);

            // Update average overhead
            const avgOverheadEl = checkElement('avg-overhead');
            if (avgOverheadEl) {
                avgOverheadEl.textContent = stats.averageOverhead;
                debugLog(`loadPerformanceStats: Set avg-overhead to ${stats.averageOverhead}`);
            } else {
                debugLog('loadPerformanceStats: INFO - avg-overhead element not found (optional)');
            }

            // Update performance status
            const perfStatusEl = checkElement('perf-status');
            if (perfStatusEl) {
                if (stats.withinThreshold) {
                    perfStatusEl.textContent = '✅';
                    perfStatusEl.title = 'Performance is optimal';
                    debugLog('loadPerformanceStats: Set perf-status to optimal');
                } else {
                    perfStatusEl.textContent = '⚠️';
                    perfStatusEl.title = 'Performance may be slow';
                    debugLog('loadPerformanceStats: Set perf-status to warning');
                }
            } else {
                debugLog('loadPerformanceStats: INFO - perf-status element not found (optional)');
            }
        } else {
            debugLog('loadPerformanceStats: Response was not successful', response);
        }
    } catch (error) {
        console.error('[Armorly] Error loading performance stats:', error);
        console.error('[Armorly] Error stack:', error.stack);
        debugLog('loadPerformanceStats: FAILED with error', error.message);
    }
}

/**
 * Load current page information
 */
async function loadCurrentPageInfo() {
    debugLog('loadCurrentPageInfo: Starting...');
    try {
        debugLog('loadCurrentPageInfo: Querying active tab');
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        debugLog('loadCurrentPageInfo: Active tab', { id: tab?.id, url: tab?.url });

        const currentUrlEl = checkElement('current-url');

        if (!tab || !tab.url) {
            debugLog('loadCurrentPageInfo: No active tab found');
            if (currentUrlEl) {
                currentUrlEl.textContent = 'No active tab';
            }
            return;
        }

        // Check if URL is accessible (not chrome://, about:, etc.)
        const url = tab.url;
        const isAccessible = url.startsWith('http://') || url.startsWith('https://');
        debugLog(`loadCurrentPageInfo: URL accessible: ${isAccessible}`);

        if (!isAccessible) {
            debugLog('loadCurrentPageInfo: Protected/restricted page');
            if (currentUrlEl) {
                currentUrlEl.textContent = 'Protected page';
            }
            return;
        }

        try {
            const urlObj = new URL(url);
            if (currentUrlEl) {
                currentUrlEl.textContent = urlObj.hostname;
                debugLog(`loadCurrentPageInfo: Set current-url to ${urlObj.hostname}`);
            }

            // Try to check if page has threats (content script may not be loaded yet)
            debugLog('loadCurrentPageInfo: Sending GET_THREATS to content script');
            const response = await chrome.tabs.sendMessage(tab.id, {
                type: 'GET_THREATS'
            });
            debugLog('loadCurrentPageInfo: Content script response', response);

            if (response && response.success) {
                const { summary } = response;
                debugLog('loadCurrentPageInfo: Threat summary', summary);
                updateThreatLevel(summary.totalScore || 0);
            }
        } catch (messageError) {
            // Content script not loaded yet or page doesn't support it
            // This is normal for new tabs or restricted pages
            debugLog('loadCurrentPageInfo: Content script not available (normal)', messageError.message);
            console.log('[Armorly] Content script not available on this page');
        }
    } catch (error) {
        console.error('[Armorly] Error loading page info:', error);
        console.error('[Armorly] Error stack:', error.stack);
        debugLog('loadCurrentPageInfo: FAILED with error', error.message);

        const currentUrlEl = checkElement('current-url');
        if (currentUrlEl) {
            currentUrlEl.textContent = 'Unable to scan';
        }
    }
}

/**
 * Update threat level badge
 *
 * @param {number} score - Threat score
 */
function updateThreatLevel(score) {
    debugLog(`updateThreatLevel: Called with score ${score}`);
    const badge = document.querySelector('.threat-badge');

    if (!badge) {
        debugLog('updateThreatLevel: INFO - .threat-badge element not found (optional)');
        return;
    }

    if (score >= 70) {
        badge.className = 'threat-badge high';
        badge.textContent = 'High Risk';
        debugLog('updateThreatLevel: Set to High Risk');
    } else if (score >= 40) {
        badge.className = 'threat-badge medium';
        badge.textContent = 'Medium Risk';
        debugLog('updateThreatLevel: Set to Medium Risk');
    } else {
        badge.className = 'threat-badge safe';
        badge.textContent = 'Safe';
        debugLog('updateThreatLevel: Set to Safe');
    }
}

/**
 * Load AI agent status for current tab
 */
async function loadAIAgentStatus() {
    debugLog('loadAIAgentStatus: Starting...');
    try {
        debugLog('loadAIAgentStatus: Querying active tab');
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        debugLog('loadAIAgentStatus: Active tab', { id: tab?.id, url: tab?.url });

        debugLog('loadAIAgentStatus: Sending GET_AI_AGENT_STATUS message');
        const response = await chrome.runtime.sendMessage({
            type: 'GET_AI_AGENT_STATUS',
            tabId: tab?.id
        });
        debugLog('loadAIAgentStatus: Response received', response);

        const statusDiv = checkElement('ai-agent-status');
        const typeSpan = checkElement('ai-agent-type');
        const multiplierSpan = checkElement('ai-multiplier');

        if (!statusDiv) {
            debugLog('loadAIAgentStatus: INFO - ai-agent-status element not found (optional)');
            return; // Element doesn't exist in HTML
        }

        if (response && response.success && response.agent) {
            // Show AI agent indicator
            statusDiv.style.display = 'block';
            debugLog('loadAIAgentStatus: AI agent detected, showing indicator');

            // Format agent type name
            const agentNames = {
                'atlas': 'ChatGPT Atlas',
                'comet': 'Perplexity Comet',
                'browseros': 'BrowserOS',
                'generic': 'AI Agent'
            };

            const agentName = agentNames[response.agent.type] || 'AI Agent';
            if (typeSpan) {
                typeSpan.textContent = agentName;
                debugLog(`loadAIAgentStatus: Set agent type to ${agentName}`);
            }
            if (multiplierSpan) {
                const multiplierText = `${response.agent.threatMultiplier}x Protection`;
                multiplierSpan.textContent = multiplierText;
                debugLog(`loadAIAgentStatus: Set multiplier to ${multiplierText}`);
            }

            console.log('[Armorly] AI agent active:', response.agent);
        } else {
            // Hide AI agent indicator
            statusDiv.style.display = 'none';
            debugLog('loadAIAgentStatus: No AI agent detected, hiding indicator');
        }
    } catch (error) {
        console.error('[Armorly] Error loading AI agent status:', error);
        console.error('[Armorly] Error stack:', error.stack);
        debugLog('loadAIAgentStatus: FAILED with error', error.message);

        const statusDiv = checkElement('ai-agent-status');
        if (statusDiv) {
            statusDiv.style.display = 'none';
        }
    }
}

/**
 * Load recent threat log
 */
async function loadThreatLog() {
    debugLog('loadThreatLog: Starting...');
    try {
        debugLog('loadThreatLog: Sending GET_THREAT_LOG message');
        const response = await chrome.runtime.sendMessage({
            type: 'GET_THREAT_LOG'
        });
        debugLog('loadThreatLog: Response received', response);

        if (response && response.success) {
            const { threatLog } = response;
            debugLog(`loadThreatLog: Found ${threatLog?.length || 0} threats`);
            displayThreats(threatLog.slice(0, 5)); // Show last 5 threats
        } else {
            debugLog('loadThreatLog: Response was not successful', response);
        }
    } catch (error) {
        console.error('[Armorly] Error loading threat log:', error);
        console.error('[Armorly] Error stack:', error.stack);
        debugLog('loadThreatLog: FAILED with error', error.message);
    }
}

/**
 * Display threats in the UI
 *
 * @param {Array} threats - Array of threat objects
 */
function displayThreats(threats) {
    debugLog(`displayThreats: Called with ${threats?.length || 0} threats`);
    const threatList = checkElement('threat-list');

    if (!threatList) {
        debugLog('displayThreats: WARNING - threat-list element not found');
        return; // Element doesn't exist in HTML
    }

    if (!threats || threats.length === 0) {
        debugLog('displayThreats: No threats to display, showing empty state');
        threatList.innerHTML = `
            <div class="empty-state">
                <span class="empty-icon">✓</span>
                <p>No threats detected today</p>
            </div>
        `;
        return;
    }

    try {
        threatList.innerHTML = threats.map(threat => {
            const url = new URL(threat.url);
            const timeAgo = formatTimeAgo(threat.timestamp);

            return `
                <div class="threat-item">
                    <div class="threat-header">
                        <span class="threat-type">${threat.severity} Threat</span>
                        <span class="threat-time">${timeAgo}</span>
                    </div>
                    <div class="threat-domain">${url.hostname}</div>
                </div>
            `;
        }).join('');
        debugLog(`displayThreats: Successfully displayed ${threats.length} threats`);
    } catch (error) {
        console.error('[Armorly] Error displaying threats:', error);
        debugLog('displayThreats: FAILED with error', error.message);
    }
}

/**
 * Format timestamp as relative time
 * 
 * @param {number} timestamp - Unix timestamp
 * @returns {string} Formatted time string
 */
function formatTimeAgo(timestamp) {
    const seconds = Math.floor((Date.now() - timestamp) / 1000);
    
    if (seconds < 60) return 'Just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
}

/**
 * Set up event listeners
 */
function setupEventListeners() {
    debugLog('setupEventListeners: Starting...');

    // Protection toggle
    const protectionToggle = checkElement('protection-toggle');
    if (protectionToggle) {
        protectionToggle.addEventListener('change', async (e) => {
            const enabled = e.target.checked;
            debugLog(`setupEventListeners: Protection toggle changed to ${enabled}`);

            try {
                await chrome.runtime.sendMessage({
                    type: enabled ? 'ENABLE_PROTECTION' : 'DISABLE_PROTECTION'
                });

                await loadProtectionStatus();
            } catch (error) {
                console.error('[Armorly] Error toggling protection:', error);
                e.target.checked = !enabled; // Revert on error
            }
        });
        debugLog('setupEventListeners: Protection toggle listener added');
    } else {
        debugLog('setupEventListeners: WARNING - protection-toggle not found');
    }

    // Scan page button
    const scanPageBtn = checkElement('scan-page');
    if (scanPageBtn) {
        scanPageBtn.addEventListener('click', async () => {
            debugLog('setupEventListeners: Scan page button clicked');
            const button = document.getElementById('scan-page');
            button.textContent = 'Scanning...';
            button.disabled = true;

            try {
                const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
                debugLog('setupEventListeners: Scanning tab', tab.url);

                // Send message to content script to trigger scan
                const response = await chrome.tabs.sendMessage(tab.id, {
                    type: 'FORCE_SCAN'
                });

                debugLog('setupEventListeners: Scan response', response);

                if (response && response.success) {
                    await loadCurrentPageInfo();
                    await loadThreatLog();
                    button.textContent = '✓ Scan Complete';

                    setTimeout(() => {
                        button.textContent = 'Scan This Page';
                        button.disabled = false;
                    }, 2000);
                } else {
                    throw new Error('Scan failed');
                }
            } catch (error) {
                console.error('[Armorly] Error scanning page:', error);
                button.textContent = 'Scan Failed';

                setTimeout(() => {
                    button.textContent = 'Scan This Page';
                    button.disabled = false;
                }, 2000);
            }
        });
        debugLog('setupEventListeners: Scan page listener added');
    } else {
        debugLog('setupEventListeners: INFO - scan-page button not found (optional)');
    }

    // Check memory button
    const checkMemoryBtn = checkElement('check-memory');
    if (checkMemoryBtn) {
        checkMemoryBtn.addEventListener('click', () => {
            debugLog('setupEventListeners: Check memory button clicked');
            chrome.tabs.create({
                url: 'https://chatgpt.com/settings/data-controls'
            });
        });
        debugLog('setupEventListeners: Check memory listener added');
    } else {
        debugLog('setupEventListeners: INFO - check-memory button not found (optional)');
    }

    // Performance report button
    const viewPerfBtn = checkElement('view-performance');
    if (viewPerfBtn) {
        viewPerfBtn.addEventListener('click', async () => {
            debugLog('setupEventListeners: Performance report button clicked');
            try {
                const response = await chrome.runtime.sendMessage({
                    type: 'GET_PERFORMANCE_REPORT'
                });

                if (response.success) {
                    showPerformanceReport(response.report);
                }
            } catch (error) {
                console.error('[Armorly] Error loading performance report:', error);
            }
        });
        debugLog('setupEventListeners: Performance report listener added');
    } else {
        debugLog('setupEventListeners: INFO - view-performance button not found (optional)');
    }

    // Settings button
    const settingsBtn = checkElement('open-settings');
    if (settingsBtn) {
        settingsBtn.addEventListener('click', () => {
            debugLog('setupEventListeners: Settings button clicked');
            chrome.runtime.openOptionsPage();
        });
        debugLog('setupEventListeners: Settings listener added');
    } else {
        debugLog('setupEventListeners: INFO - open-settings button not found (optional)');
    }

    // Documentation link
    const docsLink = checkElement('view-docs');
    if (docsLink) {
        docsLink.addEventListener('click', (e) => {
            debugLog('setupEventListeners: Documentation link clicked');
            // Don't prevent default - let the link work naturally
        });
        debugLog('setupEventListeners: Documentation listener added');
    } else {
        debugLog('setupEventListeners: INFO - view-docs link not found (optional)');
    }

    debugLog('setupEventListeners: Complete');
}

/**
 * Show performance report in alert
 * @param {Object} report - Performance report
 */
function showPerformanceReport(report) {
    const { summary, operations, recommendations } = report;

    let message = '📊 PERFORMANCE REPORT\n\n';
    message += `Status: ${summary.status}\n`;
    message += `Total Scans: ${summary.totalScans}\n`;
    message += `Total Threats: ${summary.totalThreats}\n`;
    message += `Average Overhead: ${summary.averageOverhead}\n\n`;

    message += '⏱️ OPERATIONS:\n';
    message += `DOM Scans: ${operations.domScans.count} (avg: ${operations.domScans.average})\n`;
    message += `Pattern Matches: ${operations.patternMatches.count} (avg: ${operations.patternMatches.average})\n`;
    message += `CSRF Checks: ${operations.csrfChecks.count} (avg: ${operations.csrfChecks.average})\n`;
    message += `Memory Checks: ${operations.memoryChecks.count} (avg: ${operations.memoryChecks.average})\n\n`;

    message += '💡 RECOMMENDATIONS:\n';
    recommendations.forEach(rec => {
        message += `${rec}\n`;
    });

    alert(message);
}
