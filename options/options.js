/**
 * Options Page Script for Armorly
 */

document.addEventListener('DOMContentLoaded', async () => {
    await loadSettings();
    setupEventListeners();
});

/**
 * Load settings from storage
 */
async function loadSettings() {
    try {
        const result = await chrome.storage.local.get(['settings', 'statistics']);
        
        if (result.settings) {
            const settings = result.settings;
            
            document.getElementById('sensitivity').value = settings.sensitivityLevel || 'balanced';
            document.getElementById('notifications').checked = settings.showNotifications !== false;
            document.getElementById('auto-block').checked = settings.autoBlock !== false;
            document.getElementById('memory-audit').value = settings.memoryAuditFrequency || 'weekly';
        }

        if (result.statistics) {
            const installDate = new Date(result.statistics.protectionStartDate);
            document.getElementById('install-date').textContent = installDate.toLocaleDateString();
        }
    } catch (error) {
        console.error('[Armorly] Error loading settings:', error);
    }
}

/**
 * Save settings to storage
 */
async function saveSettings() {
    try {
        const settings = {
            protectionEnabled: true,
            sensitivityLevel: document.getElementById('sensitivity').value,
            showNotifications: document.getElementById('notifications').checked,
            autoBlock: document.getElementById('auto-block').checked,
            memoryAuditFrequency: document.getElementById('memory-audit').value,
            whitelistedDomains: [],
            blacklistedDomains: []
        };

        await chrome.storage.local.set({ settings });
        
        // Show saved indicator
        const indicator = document.getElementById('saved-indicator');
        indicator.classList.add('show');
        
        setTimeout(() => {
            indicator.classList.remove('show');
        }, 2000);

        console.log('[Armorly] Settings saved');
    } catch (error) {
        console.error('[Armorly] Error saving settings:', error);
        alert('Failed to save settings. Please try again.');
    }
}

/**
 * Clear threat log
 */
async function clearThreatLog() {
    if (!confirm('Are you sure you want to clear all threat logs? This cannot be undone.')) {
        return;
    }

    try {
        await chrome.runtime.sendMessage({ type: 'CLEAR_THREAT_LOG' });
        alert('Threat log cleared successfully.');
    } catch (error) {
        console.error('[Armorly] Error clearing threat log:', error);
        alert('Failed to clear threat log. Please try again.');
    }
}

/**
 * Reset settings to defaults
 */
async function resetSettings() {
    if (!confirm('Are you sure you want to reset all settings to defaults? This cannot be undone.')) {
        return;
    }

    try {
        const defaultSettings = {
            protectionEnabled: true,
            autoBlock: true,
            showNotifications: true,
            sensitivityLevel: 'balanced',
            whitelistedDomains: [],
            blacklistedDomains: [],
            memoryAuditFrequency: 'weekly'
        };

        await chrome.storage.local.set({ settings: defaultSettings });
        await loadSettings();
        
        alert('Settings reset to defaults.');
    } catch (error) {
        console.error('[Armorly] Error resetting settings:', error);
        alert('Failed to reset settings. Please try again.');
    }
}

/**
 * Set up event listeners
 */
function setupEventListeners() {
    document.getElementById('save-settings').addEventListener('click', saveSettings);
    document.getElementById('clear-log').addEventListener('click', clearThreatLog);
    document.getElementById('reset-settings').addEventListener('click', resetSettings);
}

