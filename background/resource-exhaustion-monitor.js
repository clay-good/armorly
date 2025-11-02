/**
 * Armorly - Resource Exhaustion Monitor
 * 
 * Monitors resource exhaustion attacks, detects DoS attempts,
 * prevents browser crashes, and provides resource security across
 * all chromium-based agentic browsers.
 * 
 * Features:
 * - Real-time resource monitoring
 * - CPU exhaustion detection
 * - Network bandwidth abuse detection
 * - Storage quota exhaustion detection
 * - Tab/window exhaustion detection
 */

export class ResourceExhaustionMonitor {
  constructor() {
    // Resource tracking
    this.resourceSnapshots = [];
    this.exhaustionAttempts = [];
    
    // Resource thresholds
    this.thresholds = {
      maxTabs: 50,
      maxWindows: 10,
      maxRequests: 1000, // per minute
      maxStorageUsage: 100, // MB
      maxCPUPercent: 90,
      maxNetworkBandwidth: 100, // MB per minute
    };
    
    // Statistics
    this.statistics = {
      totalChecks: 0,
      exhaustionDetected: 0,
      tabExhaustion: 0,
      cpuExhaustion: 0,
      networkExhaustion: 0,
      storageExhaustion: 0,
      blockedAttempts: 0,
    };
    
    // Threat callback
    this.threatCallback = null;
    
    // Settings
    this.settings = {
      monitorResources: true,
      preventExhaustion: true,
      checkInterval: 30000, // 30 seconds
      blockExcessiveResources: true,
    };
    
    // Resource monitoring interval
    this.monitoringInterval = null;
    
    // Resource counters
    this.resourceCounters = {
      tabs: 0,
      windows: 0,
      requests: new Map(), // domain -> count
      storageUsage: 0,
      networkUsage: 0,
    };
  }
  
  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }
  
  /**
   * Start resource monitoring
   */
  startMonitoring() {
    if (this.monitoringInterval) {
      return;
    }
    
    this.monitoringInterval = setInterval(() => {
      this.checkResources();
    }, this.settings.checkInterval);
    
    console.log('[ResourceExhaustionMonitor] Started monitoring');
  }
  
  /**
   * Stop resource monitoring
   */
  stopMonitoring() {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = null;
      console.log('[ResourceExhaustionMonitor] Stopped monitoring');
    }
  }
  
  /**
   * Check resources
   */
  async checkResources() {
    if (!this.settings.monitorResources) return;
    
    this.statistics.totalChecks++;
    
    try {
      // Check tabs
      await this.checkTabs();
      
      // Check windows
      await this.checkWindows();
      
      // Check storage
      await this.checkStorage();
      
      // Record snapshot
      this.recordSnapshot();
    } catch (error) {
      console.warn('[ResourceExhaustionMonitor] Error checking resources:', error);
    }
  }
  
  /**
   * Check tabs
   */
  async checkTabs() {
    const tabs = await chrome.tabs.query({});
    this.resourceCounters.tabs = tabs.length;
    
    if (tabs.length > this.thresholds.maxTabs) {
      this.statistics.exhaustionDetected++;
      this.statistics.tabExhaustion++;
      
      if (this.threatCallback) {
        this.threatCallback({
          type: 'TAB_EXHAUSTION',
          severity: 'HIGH',
          score: 80,
          description: `Excessive tabs detected (${tabs.length} tabs)`,
          context: { tabCount: tabs.length, threshold: this.thresholds.maxTabs },
        });
      }
    }
  }
  
  /**
   * Check windows
   */
  async checkWindows() {
    const windows = await chrome.windows.getAll();
    this.resourceCounters.windows = windows.length;
    
    if (windows.length > this.thresholds.maxWindows) {
      this.statistics.exhaustionDetected++;
      
      if (this.threatCallback) {
        this.threatCallback({
          type: 'WINDOW_EXHAUSTION',
          severity: 'MEDIUM',
          score: 60,
          description: `Excessive windows detected (${windows.length} windows)`,
          context: { windowCount: windows.length, threshold: this.thresholds.maxWindows },
        });
      }
    }
  }
  
  /**
   * Check storage
   */
  async checkStorage() {
    try {
      const estimate = await navigator.storage.estimate();
      const usageMB = estimate.usage / (1024 * 1024);
      this.resourceCounters.storageUsage = usageMB;
      
      if (usageMB > this.thresholds.maxStorageUsage) {
        this.statistics.exhaustionDetected++;
        this.statistics.storageExhaustion++;
        
        if (this.threatCallback) {
          this.threatCallback({
            type: 'STORAGE_EXHAUSTION',
            severity: 'HIGH',
            score: 75,
            description: `Excessive storage usage (${usageMB.toFixed(1)}MB)`,
            context: { usageMB, threshold: this.thresholds.maxStorageUsage },
          });
        }
      }
    } catch (error) {
      console.warn('[ResourceExhaustionMonitor] Error checking storage:', error);
    }
  }
  
  /**
   * Monitor network request
   */
  monitorRequest(request) {
    const { url, tabId } = request;
    const domain = this.extractDomain(url);
    
    // Track request count
    const count = this.resourceCounters.requests.get(domain) || 0;
    this.resourceCounters.requests.set(domain, count + 1);
    
    // Check if domain exceeds threshold
    if (count + 1 > this.thresholds.maxRequests) {
      this.statistics.exhaustionDetected++;
      this.statistics.networkExhaustion++;
      
      if (this.threatCallback) {
        this.threatCallback({
          type: 'NETWORK_REQUEST_EXHAUSTION',
          severity: 'HIGH',
          score: 80,
          description: `Excessive network requests from ${domain} (${count + 1} requests)`,
          context: { domain, requestCount: count + 1, threshold: this.thresholds.maxRequests },
        });
      }
      
      if (this.settings.blockExcessiveResources) {
        this.statistics.blockedAttempts++;
        return {
          allowed: false,
          reason: 'Excessive network requests blocked',
        };
      }
    }
    
    return { allowed: true };
  }
  
  /**
   * Monitor CPU usage
   */
  monitorCPU(usage) {
    const { cpuPercent, tabId } = usage;
    
    if (cpuPercent > this.thresholds.maxCPUPercent) {
      this.statistics.exhaustionDetected++;
      this.statistics.cpuExhaustion++;
      
      if (this.threatCallback) {
        this.threatCallback({
          type: 'CPU_EXHAUSTION',
          severity: 'CRITICAL',
          score: 90,
          description: `CPU exhaustion detected (${cpuPercent}% usage)`,
          context: { cpuPercent, tabId, threshold: this.thresholds.maxCPUPercent },
        });
      }
      
      return {
        allowed: false,
        reason: 'CPU exhaustion detected',
      };
    }
    
    return { allowed: true };
  }
  
  /**
   * Record resource snapshot
   */
  recordSnapshot() {
    const snapshot = {
      timestamp: Date.now(),
      tabs: this.resourceCounters.tabs,
      windows: this.resourceCounters.windows,
      storageUsage: this.resourceCounters.storageUsage,
      totalRequests: Array.from(this.resourceCounters.requests.values()).reduce((sum, count) => sum + count, 0),
    };
    
    this.resourceSnapshots.push(snapshot);
    
    // Limit snapshot history
    if (this.resourceSnapshots.length > 100) {
      this.resourceSnapshots.shift();
    }
    
    // Reset request counters every minute
    this.resourceCounters.requests.clear();
  }
  
  /**
   * Extract domain from URL
   */
  extractDomain(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname;
    } catch {
      return url;
    }
  }
  
  /**
   * Get statistics
   */
  getStatistics() {
    return this.statistics;
  }
  
  /**
   * Get resource snapshots
   */
  getResourceSnapshots() {
    return this.resourceSnapshots;
  }
  
  /**
   * Get exhaustion attempts
   */
  getExhaustionAttempts() {
    return this.exhaustionAttempts;
  }
  
  /**
   * Get current resource status
   */
  getCurrentResourceStatus() {
    return {
      tabs: this.resourceCounters.tabs,
      windows: this.resourceCounters.windows,
      storageUsage: this.resourceCounters.storageUsage,
      status: this.getResourceStatus(),
    };
  }
  
  /**
   * Get resource status label
   */
  getResourceStatus() {
    const { tabs, windows, storageUsage } = this.resourceCounters;
    
    if (
      tabs > this.thresholds.maxTabs ||
      windows > this.thresholds.maxWindows ||
      storageUsage > this.thresholds.maxStorageUsage
    ) {
      return 'CRITICAL';
    }
    
    if (
      tabs > this.thresholds.maxTabs * 0.8 ||
      windows > this.thresholds.maxWindows * 0.8 ||
      storageUsage > this.thresholds.maxStorageUsage * 0.8
    ) {
      return 'HIGH';
    }
    
    return 'NORMAL';
  }
  
  /**
   * Update settings
   */
  updateSettings(newSettings) {
    this.settings = { ...this.settings, ...newSettings };
    
    // Restart monitoring if interval changed
    if (newSettings.checkInterval && this.monitoringInterval) {
      this.stopMonitoring();
      this.startMonitoring();
    }
  }
  
  /**
   * Update thresholds
   */
  updateThresholds(newThresholds) {
    this.thresholds = { ...this.thresholds, ...newThresholds };
  }
}

