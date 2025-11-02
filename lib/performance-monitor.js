/**
 * Performance Monitor for Armorly
 * 
 * Tracks extension performance to ensure < 50ms overhead
 * Monitors:
 * - DOM scan duration
 * - Pattern matching time
 * - Memory usage
 * - CPU impact
 * - Network request overhead
 * 
 * @module performance-monitor
 * @author Armorly Security Team
 * @license MIT
 */

class PerformanceMonitor {
  constructor() {
    this.metrics = {
      domScans: [],
      patternMatches: [],
      csrfChecks: [],
      memoryChecks: [],
      totalScans: 0,
      totalThreats: 0,
      averageOverhead: 0
    };
    
    this.thresholds = {
      domScan: 50,        // Max 50ms for DOM scan
      patternMatch: 10,   // Max 10ms for pattern matching
      csrfCheck: 5,       // Max 5ms for CSRF check
      memoryCheck: 20,    // Max 20ms for memory check
      total: 50           // Max 50ms total overhead
    };
    
    this.maxSamples = 100; // Keep last 100 samples
    this.enabled = true;
  }

  /**
   * Start timing an operation
   * @param {string} operation - Operation name
   * @returns {number} Start timestamp
   */
  startTimer(operation) {
    if (!this.enabled) return null;
    return performance.now();
  }

  /**
   * End timing and record metric
   * @param {string} operation - Operation name
   * @param {number} startTime - Start timestamp
   * @param {Object} metadata - Additional metadata
   */
  endTimer(operation, startTime, metadata = {}) {
    if (!this.enabled || !startTime) return;
    
    const duration = performance.now() - startTime;
    const metric = {
      operation,
      duration,
      timestamp: Date.now(),
      ...metadata
    };

    // Store in appropriate array
    switch (operation) {
      case 'domScan':
        this.metrics.domScans.push(metric);
        this.trimArray(this.metrics.domScans);
        break;
      case 'patternMatch':
        this.metrics.patternMatches.push(metric);
        this.trimArray(this.metrics.patternMatches);
        break;
      case 'csrfCheck':
        this.metrics.csrfChecks.push(metric);
        this.trimArray(this.metrics.csrfChecks);
        break;
      case 'memoryCheck':
        this.metrics.memoryChecks.push(metric);
        this.trimArray(this.metrics.memoryChecks);
        break;
    }

    this.metrics.totalScans++;
    this.updateAverageOverhead();

    // Check if threshold exceeded
    if (this.isThresholdExceeded(operation, duration)) {
      this.logPerformanceWarning(operation, duration, metadata);
    }
  }

  /**
   * Trim array to max samples
   * @param {Array} arr - Array to trim
   */
  trimArray(arr) {
    if (arr.length > this.maxSamples) {
      arr.shift();
    }
  }

  /**
   * Check if threshold exceeded
   * @param {string} operation - Operation name
   * @param {number} duration - Duration in ms
   * @returns {boolean}
   */
  isThresholdExceeded(operation, duration) {
    const threshold = this.thresholds[operation];
    return threshold && duration > threshold;
  }

  /**
   * Log performance warning
   * @param {string} operation - Operation name
   * @param {number} duration - Duration in ms
   * @param {Object} metadata - Additional metadata
   */
  logPerformanceWarning(operation, duration, metadata) {
    console.warn(
      `[Armorly Performance] ${operation} took ${duration.toFixed(2)}ms ` +
      `(threshold: ${this.thresholds[operation]}ms)`,
      metadata
    );
  }

  /**
   * Update average overhead
   */
  updateAverageOverhead() {
    const allMetrics = [
      ...this.metrics.domScans,
      ...this.metrics.patternMatches,
      ...this.metrics.csrfChecks,
      ...this.metrics.memoryChecks
    ];

    if (allMetrics.length === 0) {
      this.metrics.averageOverhead = 0;
      return;
    }

    const total = allMetrics.reduce((sum, m) => sum + m.duration, 0);
    this.metrics.averageOverhead = total / allMetrics.length;
  }

  /**
   * Get performance statistics
   * @returns {Object} Performance stats
   */
  getStats() {
    return {
      totalScans: this.metrics.totalScans,
      totalThreats: this.metrics.totalThreats,
      averageOverhead: this.metrics.averageOverhead.toFixed(2) + 'ms',
      domScans: this.getOperationStats(this.metrics.domScans),
      patternMatches: this.getOperationStats(this.metrics.patternMatches),
      csrfChecks: this.getOperationStats(this.metrics.csrfChecks),
      memoryChecks: this.getOperationStats(this.metrics.memoryChecks),
      thresholds: this.thresholds,
      withinThreshold: this.metrics.averageOverhead < this.thresholds.total
    };
  }

  /**
   * Get statistics for specific operation
   * @param {Array} metrics - Metrics array
   * @returns {Object} Operation stats
   */
  getOperationStats(metrics) {
    if (metrics.length === 0) {
      return {
        count: 0,
        average: 0,
        min: 0,
        max: 0,
        p95: 0
      };
    }

    const durations = metrics.map(m => m.duration).sort((a, b) => a - b);
    const sum = durations.reduce((a, b) => a + b, 0);
    const p95Index = Math.floor(durations.length * 0.95);

    return {
      count: metrics.length,
      average: (sum / metrics.length).toFixed(2) + 'ms',
      min: durations[0].toFixed(2) + 'ms',
      max: durations[durations.length - 1].toFixed(2) + 'ms',
      p95: durations[p95Index].toFixed(2) + 'ms'
    };
  }

  /**
   * Get recent slow operations
   * @param {number} limit - Number of operations to return
   * @returns {Array} Slow operations
   */
  getSlowOperations(limit = 10) {
    const allMetrics = [
      ...this.metrics.domScans,
      ...this.metrics.patternMatches,
      ...this.metrics.csrfChecks,
      ...this.metrics.memoryChecks
    ];

    return allMetrics
      .filter(m => this.isThresholdExceeded(m.operation, m.duration))
      .sort((a, b) => b.duration - a.duration)
      .slice(0, limit);
  }

  /**
   * Record threat detection
   * @param {string} threatType - Type of threat
   */
  recordThreat(threatType) {
    this.metrics.totalThreats++;
  }

  /**
   * Get performance report
   * @returns {Object} Detailed performance report
   */
  getReport() {
    const stats = this.getStats();
    const slowOps = this.getSlowOperations();

    return {
      summary: {
        totalScans: stats.totalScans,
        totalThreats: stats.totalThreats,
        averageOverhead: stats.averageOverhead,
        withinThreshold: stats.withinThreshold,
        status: stats.withinThreshold ? '✅ GOOD' : '⚠️ SLOW'
      },
      operations: {
        domScans: stats.domScans,
        patternMatches: stats.patternMatches,
        csrfChecks: stats.csrfChecks,
        memoryChecks: stats.memoryChecks
      },
      thresholds: stats.thresholds,
      slowOperations: slowOps,
      recommendations: this.getRecommendations(stats, slowOps)
    };
  }

  /**
   * Get performance recommendations
   * @param {Object} stats - Performance stats
   * @param {Array} slowOps - Slow operations
   * @returns {Array} Recommendations
   */
  getRecommendations(stats, slowOps) {
    const recommendations = [];

    if (!stats.withinThreshold) {
      recommendations.push('⚠️ Average overhead exceeds 50ms threshold');
    }

    if (slowOps.length > 0) {
      recommendations.push(`⚠️ ${slowOps.length} operations exceeded thresholds`);
    }

    const domAvg = parseFloat(stats.domScans.average);
    if (domAvg > this.thresholds.domScan) {
      recommendations.push('💡 Consider optimizing DOM scanning (use caching, reduce selectors)');
    }

    const patternAvg = parseFloat(stats.patternMatches.average);
    if (patternAvg > this.thresholds.patternMatch) {
      recommendations.push('💡 Consider optimizing pattern matching (use indexed patterns, cache results)');
    }

    if (recommendations.length === 0) {
      recommendations.push('✅ Performance is optimal!');
    }

    return recommendations;
  }

  /**
   * Reset metrics
   */
  reset() {
    this.metrics = {
      domScans: [],
      patternMatches: [],
      csrfChecks: [],
      memoryChecks: [],
      totalScans: 0,
      totalThreats: 0,
      averageOverhead: 0
    };
  }

  /**
   * Enable/disable monitoring
   * @param {boolean} enabled - Enable state
   */
  setEnabled(enabled) {
    this.enabled = enabled;
  }
}

// Make available globally for content scripts
if (typeof window !== 'undefined') {
  window.PerformanceMonitor = PerformanceMonitor;
}

// Export for ES6 modules
export { PerformanceMonitor };

