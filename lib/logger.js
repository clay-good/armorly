/**
 * Centralized Logging System for Armorly
 * 
 * Provides conditional logging that can be toggled for production vs development.
 * In production, only errors and warnings are logged. In development, all logs are shown.
 * 
 * Features:
 * - Environment-aware logging (dev vs production)
 * - Log levels: debug, info, warn, error
 * - Automatic timestamp and component tagging
 * - Performance tracking
 * - Log history for debugging
 * - Configurable via chrome.storage
 * 
 * @module logger
 * @author Armorly Security Team
 * @license MIT
 */

class Logger {
  constructor() {
    /**
     * Log levels
     */
    this.levels = {
      DEBUG: 0,
      INFO: 1,
      WARN: 2,
      ERROR: 3,
    };

    /**
     * Current log level (default: INFO for production)
     */
    this.currentLevel = this.levels.INFO;

    /**
     * Development mode flag
     */
    this.isDevelopment = false;

    /**
     * Log history (last 1000 entries)
     */
    this.history = [];
    this.maxHistorySize = 1000;

    /**
     * Performance tracking
     */
    this.performanceMarks = new Map();

    /**
     * Initialize from storage
     */
    this.initialize();
  }

  /**
   * Initialize logger from storage
   */
  async initialize() {
    try {
      const result = await chrome.storage.local.get(['armorly_log_level', 'armorly_dev_mode']);
      
      if (result.armorly_dev_mode !== undefined) {
        this.isDevelopment = result.armorly_dev_mode;
      }

      if (result.armorly_log_level !== undefined) {
        this.currentLevel = result.armorly_log_level;
      } else {
        // Auto-detect: if extension is unpacked, enable dev mode
        if (chrome.runtime && chrome.runtime.getManifest) {
          const manifest = chrome.runtime.getManifest();
          // Check if running in development (unpacked extension)
          this.isDevelopment = !('update_url' in manifest);
          this.currentLevel = this.isDevelopment ? this.levels.DEBUG : this.levels.INFO;
        }
      }
    } catch (error) {
      // Fallback to production mode
      this.isDevelopment = false;
      this.currentLevel = this.levels.INFO;
    }
  }

  /**
   * Set log level
   */
  setLevel(level) {
    if (typeof level === 'string') {
      this.currentLevel = this.levels[level.toUpperCase()] ?? this.levels.INFO;
    } else {
      this.currentLevel = level;
    }
    chrome.storage.local.set({ armorly_log_level: this.currentLevel });
  }

  /**
   * Set development mode
   */
  setDevelopmentMode(enabled) {
    this.isDevelopment = enabled;
    this.currentLevel = enabled ? this.levels.DEBUG : this.levels.INFO;
    chrome.storage.local.set({ 
      armorly_dev_mode: enabled,
      armorly_log_level: this.currentLevel 
    });
  }

  /**
   * Check if level should be logged
   */
  shouldLog(level) {
    return level >= this.currentLevel;
  }

  /**
   * Format log message
   */
  formatMessage(component, message, data) {
    const timestamp = new Date().toISOString();
    const prefix = `[Armorly${component ? ' ' + component : ''}]`;
    
    if (data !== undefined) {
      return { timestamp, prefix, message, data };
    }
    return { timestamp, prefix, message };
  }

  /**
   * Add to history
   */
  addToHistory(level, component, message, data) {
    const entry = {
      level,
      component,
      message,
      data,
      timestamp: Date.now(),
    };

    this.history.push(entry);

    // Limit history size
    if (this.history.length > this.maxHistorySize) {
      this.history.shift();
    }
  }

  /**
   * Debug log (only in development)
   */
  debug(component, message, data) {
    if (!this.shouldLog(this.levels.DEBUG)) return;

    const formatted = this.formatMessage(component, message, data);
    console.log(formatted.prefix, formatted.message, formatted.data !== undefined ? formatted.data : '');
    this.addToHistory('DEBUG', component, message, data);
  }

  /**
   * Info log
   */
  info(component, message, data) {
    if (!this.shouldLog(this.levels.INFO)) return;

    const formatted = this.formatMessage(component, message, data);
    console.log(formatted.prefix, formatted.message, formatted.data !== undefined ? formatted.data : '');
    this.addToHistory('INFO', component, message, data);
  }

  /**
   * Warning log (always shown)
   */
  warn(component, message, data) {
    if (!this.shouldLog(this.levels.WARN)) return;

    const formatted = this.formatMessage(component, message, data);
    console.warn(formatted.prefix, formatted.message, formatted.data !== undefined ? formatted.data : '');
    this.addToHistory('WARN', component, message, data);
  }

  /**
   * Error log (always shown)
   */
  error(component, message, data) {
    if (!this.shouldLog(this.levels.ERROR)) return;

    const formatted = this.formatMessage(component, message, data);
    console.error(formatted.prefix, formatted.message, formatted.data !== undefined ? formatted.data : '');
    this.addToHistory('ERROR', component, message, data);
  }

  /**
   * Performance: Start timing
   */
  startTimer(label) {
    this.performanceMarks.set(label, performance.now());
  }

  /**
   * Performance: End timing and log
   */
  endTimer(label, component) {
    const start = this.performanceMarks.get(label);
    if (start === undefined) {
      this.warn('Logger', `Timer "${label}" was not started`);
      return;
    }

    const duration = performance.now() - start;
    this.performanceMarks.delete(label);

    if (this.isDevelopment) {
      this.debug(component || 'Performance', `${label}: ${duration.toFixed(2)}ms`);
    }

    return duration;
  }

  /**
   * Get log history
   */
  getHistory(filter = {}) {
    let filtered = this.history;

    if (filter.level) {
      filtered = filtered.filter(entry => entry.level === filter.level);
    }

    if (filter.component) {
      filtered = filtered.filter(entry => entry.component === filter.component);
    }

    if (filter.since) {
      filtered = filtered.filter(entry => entry.timestamp >= filter.since);
    }

    return filtered;
  }

  /**
   * Clear history
   */
  clearHistory() {
    this.history = [];
  }

  /**
   * Export logs
   */
  exportLogs() {
    return {
      isDevelopment: this.isDevelopment,
      currentLevel: Object.keys(this.levels).find(key => this.levels[key] === this.currentLevel),
      history: this.history,
      timestamp: Date.now(),
    };
  }

  /**
   * Get statistics
   */
  getStatistics() {
    const stats = {
      total: this.history.length,
      byLevel: {},
      byComponent: {},
    };

    for (const entry of this.history) {
      // By level
      stats.byLevel[entry.level] = (stats.byLevel[entry.level] || 0) + 1;

      // By component
      if (entry.component) {
        stats.byComponent[entry.component] = (stats.byComponent[entry.component] || 0) + 1;
      }
    }

    return stats;
  }
}

// Create singleton instance
const logger = new Logger();

// Export for ES6 modules (background scripts)
export { logger };

// Also export as default
export default logger;

