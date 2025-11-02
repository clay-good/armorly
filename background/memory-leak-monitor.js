/**
 * Armorly - Memory Leak Monitor
 * 
 * Monitors memory leaks, detects memory exhaustion attacks,
 * prevents browser crashes, and provides memory security across
 * all chromium-based agentic browsers.
 * 
 * Features:
 * - Real-time memory usage monitoring
 * - Memory leak detection
 * - Memory exhaustion prevention
 * - Garbage collection tracking
 * - Memory growth analysis
 */

export class MemoryLeakMonitor {
  constructor() {
    // Memory tracking
    this.memorySnapshots = [];
    this.leakDetections = [];
    
    // Memory thresholds (in MB)
    this.thresholds = {
      warningLevel: 500, // 500MB
      criticalLevel: 1000, // 1GB
      maxGrowthRate: 50, // 50MB per minute
      maxHeapSize: 2000, // 2GB
    };
    
    // Statistics
    this.statistics = {
      totalChecks: 0,
      leaksDetected: 0,
      memoryExhaustionAttempts: 0,
      criticalMemoryEvents: 0,
      gcEvents: 0,
      averageMemoryUsage: 0,
    };
    
    // Threat callback
    this.threatCallback = null;
    
    // Settings
    this.settings = {
      monitorMemory: true,
      detectLeaks: true,
      preventExhaustion: true,
      checkInterval: 30000, // 30 seconds
      snapshotRetention: 100, // Keep last 100 snapshots
    };
    
    // Memory monitoring interval
    this.monitoringInterval = null;
    
    // Tab memory tracking
    this.tabMemory = new Map(); // tabId -> memory data
  }
  
  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }
  
  /**
   * Start memory monitoring
   */
  startMonitoring() {
    if (this.monitoringInterval) {
      return;
    }
    
    this.monitoringInterval = setInterval(() => {
      this.checkMemory();
    }, this.settings.checkInterval);
    
    console.log('[MemoryLeakMonitor] Started monitoring');
  }
  
  /**
   * Stop memory monitoring
   */
  stopMonitoring() {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = null;
      console.log('[MemoryLeakMonitor] Stopped monitoring');
    }
  }
  
  /**
   * Check memory usage
   */
  async checkMemory() {
    if (!this.settings.monitorMemory) return;
    
    this.statistics.totalChecks++;
    
    try {
      // Get memory info (Chrome-specific API)
      if (chrome.system && chrome.system.memory) {
        const memoryInfo = await chrome.system.memory.getInfo();
        this.analyzeSystemMemory(memoryInfo);
      }
      
      // Get process memory info
      if (chrome.processes && chrome.processes.getProcessInfo) {
        const processes = await chrome.processes.getProcessInfo([], true);
        this.analyzeProcessMemory(processes);
      }
    } catch (error) {
      console.warn('[MemoryLeakMonitor] Error checking memory:', error);
    }
  }
  
  /**
   * Analyze system memory
   */
  analyzeSystemMemory(memoryInfo) {
    const { capacity, availableCapacity } = memoryInfo;
    const usedMemory = capacity - availableCapacity;
    const usagePercent = (usedMemory / capacity) * 100;
    
    // Record snapshot
    const snapshot = {
      timestamp: Date.now(),
      totalMemory: capacity,
      usedMemory,
      availableMemory: availableCapacity,
      usagePercent,
    };
    
    this.recordSnapshot(snapshot);
    
    // Check for memory exhaustion
    if (usagePercent > 90) {
      this.statistics.memoryExhaustionAttempts++;
      
      if (this.threatCallback) {
        this.threatCallback({
          type: 'MEMORY_EXHAUSTION',
          severity: 'CRITICAL',
          score: 95,
          description: `System memory exhaustion detected (${usagePercent.toFixed(1)}% used)`,
          context: { usagePercent, usedMemory, totalMemory: capacity },
        });
      }
    } else if (usagePercent > 80) {
      this.statistics.criticalMemoryEvents++;
      
      if (this.threatCallback) {
        this.threatCallback({
          type: 'HIGH_MEMORY_USAGE',
          severity: 'HIGH',
          score: 75,
          description: `High system memory usage (${usagePercent.toFixed(1)}% used)`,
          context: { usagePercent, usedMemory, totalMemory: capacity },
        });
      }
    }
    
    // Detect memory leaks
    if (this.settings.detectLeaks) {
      this.detectMemoryLeak();
    }
  }
  
  /**
   * Analyze process memory
   */
  analyzeProcessMemory(processes) {
    for (const [processId, process] of Object.entries(processes)) {
      const { privateMemory, type, tabId } = process;
      
      if (type === 'tab' && tabId) {
        // Track tab memory
        const memoryMB = privateMemory / (1024 * 1024);
        
        this.tabMemory.set(tabId, {
          processId,
          memoryMB,
          timestamp: Date.now(),
        });
        
        // Check for excessive tab memory
        if (memoryMB > this.thresholds.criticalLevel) {
          this.statistics.criticalMemoryEvents++;
          
          if (this.threatCallback) {
            this.threatCallback({
              type: 'EXCESSIVE_TAB_MEMORY',
              severity: 'HIGH',
              score: 80,
              description: `Excessive memory usage in tab ${tabId} (${memoryMB.toFixed(0)}MB)`,
              context: { tabId, memoryMB },
            });
          }
        }
      }
    }
  }
  
  /**
   * Detect memory leak
   */
  detectMemoryLeak() {
    if (this.memorySnapshots.length < 5) {
      return; // Need at least 5 snapshots
    }
    
    // Get last 5 snapshots
    const recentSnapshots = this.memorySnapshots.slice(-5);
    
    // Calculate memory growth rate
    const firstSnapshot = recentSnapshots[0];
    const lastSnapshot = recentSnapshots[recentSnapshots.length - 1];
    
    const timeDiff = (lastSnapshot.timestamp - firstSnapshot.timestamp) / 60000; // minutes
    const memoryDiff = lastSnapshot.usedMemory - firstSnapshot.usedMemory;
    const growthRate = memoryDiff / timeDiff; // MB per minute
    
    // Check if growth rate exceeds threshold
    if (growthRate > this.thresholds.maxGrowthRate) {
      this.statistics.leaksDetected++;
      
      this.leakDetections.push({
        timestamp: Date.now(),
        growthRate,
        memoryDiff,
        timeDiff,
      });
      
      if (this.threatCallback) {
        this.threatCallback({
          type: 'MEMORY_LEAK_DETECTED',
          severity: 'HIGH',
          score: 85,
          description: `Memory leak detected (${growthRate.toFixed(1)}MB/min growth)`,
          context: { growthRate, memoryDiff, timeDiff },
        });
      }
      
      // Limit leak detection history
      if (this.leakDetections.length > 100) {
        this.leakDetections.shift();
      }
    }
  }
  
  /**
   * Record memory snapshot
   */
  recordSnapshot(snapshot) {
    this.memorySnapshots.push(snapshot);
    
    // Update average memory usage
    const totalUsage = this.memorySnapshots.reduce((sum, s) => sum + s.usedMemory, 0);
    this.statistics.averageMemoryUsage = totalUsage / this.memorySnapshots.length;
    
    // Limit snapshot history
    if (this.memorySnapshots.length > this.settings.snapshotRetention) {
      this.memorySnapshots.shift();
    }
  }
  
  /**
   * Get memory statistics
   */
  getStatistics() {
    return this.statistics;
  }
  
  /**
   * Get memory snapshots
   */
  getMemorySnapshots() {
    return this.memorySnapshots;
  }
  
  /**
   * Get leak detections
   */
  getLeakDetections() {
    return this.leakDetections;
  }
  
  /**
   * Get tab memory usage
   */
  getTabMemoryUsage() {
    return Array.from(this.tabMemory.entries()).map(([tabId, data]) => ({
      tabId,
      ...data,
    }));
  }
  
  /**
   * Get current memory status
   */
  getCurrentMemoryStatus() {
    if (this.memorySnapshots.length === 0) {
      return null;
    }
    
    const latest = this.memorySnapshots[this.memorySnapshots.length - 1];
    
    return {
      timestamp: latest.timestamp,
      usedMemory: latest.usedMemory,
      availableMemory: latest.availableMemory,
      usagePercent: latest.usagePercent,
      status: this.getMemoryStatus(latest.usagePercent),
    };
  }
  
  /**
   * Get memory status label
   */
  getMemoryStatus(usagePercent) {
    if (usagePercent > 90) return 'CRITICAL';
    if (usagePercent > 80) return 'HIGH';
    if (usagePercent > 60) return 'MODERATE';
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
}

