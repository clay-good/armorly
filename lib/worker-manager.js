/**
 * Web Worker Manager for Armorly
 * 
 * Manages Web Workers for offloading heavy computation:
 * - Pattern matching worker
 * - Behavioral analysis worker
 * - Network analysis worker
 * 
 * Features:
 * - Worker pooling
 * - Automatic fallback to main thread
 * - Promise-based API
 * - Performance tracking
 * - Error handling
 * 
 * @module worker-manager
 * @author Armorly Security Team
 * @license MIT
 */

class WorkerManager {
  constructor() {
    /**
     * Worker instances
     */
    this.workers = {
      patternMatcher: null,
    };

    /**
     * Worker ready status
     */
    this.workersReady = {
      patternMatcher: false,
    };

    /**
     * Message ID counter
     */
    this.messageId = 0;

    /**
     * Pending promises
     */
    this.pendingPromises = new Map();

    /**
     * Statistics
     */
    this.statistics = {
      totalTasks: 0,
      completedTasks: 0,
      failedTasks: 0,
      fallbackToMainThread: 0,
      averageTaskTime: 0,
    };

    /**
     * Worker support detection
     */
    this.workerSupported = typeof Worker !== 'undefined';

    /**
     * Initialize workers
     */
    if (this.workerSupported) {
      this.initializeWorkers();
    }
  }

  /**
   * Initialize all workers
   */
  initializeWorkers() {
    try {
      // Pattern matcher worker
      this.workers.patternMatcher = new Worker(
        chrome.runtime.getURL('workers/pattern-matcher.worker.js')
      );

      this.workers.patternMatcher.addEventListener('message', (event) => {
        this.handleWorkerMessage('patternMatcher', event.data);
      });

      this.workers.patternMatcher.addEventListener('error', (error) => {
        console.error('[WorkerManager] Pattern matcher worker error:', error);
        this.workersReady.patternMatcher = false;
      });
    } catch (error) {
      console.error('[WorkerManager] Failed to initialize workers:', error);
      this.workerSupported = false;
    }
  }

  /**
   * Handle worker message
   */
  handleWorkerMessage(workerName, data) {
    // Check if worker is ready
    if (data.type === 'ready') {
      this.workersReady[workerName] = true;
      console.log(`[WorkerManager] ${workerName} worker ready`);
      return;
    }

    // Handle task response
    const { id, success, result, error } = data;

    if (!this.pendingPromises.has(id)) {
      return;
    }

    const { resolve, reject, startTime } = this.pendingPromises.get(id);
    this.pendingPromises.delete(id);

    // Update statistics
    this.statistics.completedTasks++;
    const taskTime = performance.now() - startTime;
    this.statistics.averageTaskTime = 
      (this.statistics.averageTaskTime * (this.statistics.completedTasks - 1) + taskTime) / 
      this.statistics.completedTasks;

    if (success) {
      resolve(result);
    } else {
      this.statistics.failedTasks++;
      reject(new Error(error));
    }
  }

  /**
   * Send task to worker
   */
  sendToWorker(workerName, type, data) {
    return new Promise((resolve, reject) => {
      // Check if worker is supported and ready
      if (!this.workerSupported || !this.workersReady[workerName]) {
        this.statistics.fallbackToMainThread++;
        reject(new Error('Worker not available'));
        return;
      }

      // Generate message ID
      const id = ++this.messageId;

      // Store promise
      this.pendingPromises.set(id, {
        resolve,
        reject,
        startTime: performance.now(),
      });

      // Update statistics
      this.statistics.totalTasks++;

      // Send message to worker
      try {
        this.workers[workerName].postMessage({ id, type, data });
      } catch (error) {
        this.pendingPromises.delete(id);
        this.statistics.failedTasks++;
        reject(error);
      }

      // Timeout after 5 seconds
      setTimeout(() => {
        if (this.pendingPromises.has(id)) {
          this.pendingPromises.delete(id);
          this.statistics.failedTasks++;
          reject(new Error('Worker task timeout'));
        }
      }, 5000);
    });
  }

  /**
   * Analyze prompt injection (offloaded to worker)
   */
  async analyzePromptInjection(text) {
    try {
      return await this.sendToWorker('patternMatcher', 'analyze_prompt_injection', { text });
    } catch (error) {
      // Fallback to main thread (simplified version)
      return this.fallbackAnalyzePromptInjection(text);
    }
  }

  /**
   * Analyze credentials (offloaded to worker)
   */
  async analyzeCredentials(text) {
    try {
      return await this.sendToWorker('patternMatcher', 'analyze_credentials', { text });
    } catch (error) {
      // Fallback to main thread
      return this.fallbackAnalyzeCredentials(text);
    }
  }

  /**
   * Analyze sensitive data (offloaded to worker)
   */
  async analyzeSensitiveData(text) {
    try {
      return await this.sendToWorker('patternMatcher', 'analyze_sensitive_data', { text });
    } catch (error) {
      // Fallback to main thread
      return this.fallbackAnalyzeSensitiveData(text);
    }
  }

  /**
   * Analyze URL (offloaded to worker)
   */
  async analyzeURL(url) {
    try {
      return await this.sendToWorker('patternMatcher', 'analyze_url', { url });
    } catch (error) {
      // Fallback to main thread
      return this.fallbackAnalyzeURL(url);
    }
  }

  /**
   * Batch analyze (offloaded to worker)
   */
  async batchAnalyze(texts, analysisType) {
    try {
      return await this.sendToWorker('patternMatcher', 'batch_analyze', { texts, analysisType });
    } catch (error) {
      // Fallback to main thread
      return texts.map(text => ({ error: 'Fallback not implemented' }));
    }
  }

  /**
   * Fallback: Analyze prompt injection on main thread
   */
  fallbackAnalyzePromptInjection(text) {
    // Simplified version for fallback
    const suspiciousKeywords = ['ignore', 'disregard', 'forget', 'override', 'system'];
    const keywordCount = suspiciousKeywords.filter(keyword => 
      text.toLowerCase().includes(keyword)
    ).length;

    return {
      detected: keywordCount >= 2,
      threats: keywordCount >= 2 ? [{ type: 'KEYWORD_MATCH', keywordCount }] : [],
      totalScore: keywordCount * 15,
      severity: keywordCount >= 3 ? 'HIGH' : 'MEDIUM',
    };
  }

  /**
   * Fallback: Analyze credentials on main thread
   */
  fallbackAnalyzeCredentials(text) {
    const hasPassword = /password/gi.test(text);
    const hasToken = /token|api[_-]?key/gi.test(text);

    return {
      detected: hasPassword || hasToken,
      threats: (hasPassword || hasToken) ? [{ type: 'CREDENTIAL_DETECTED' }] : [],
    };
  }

  /**
   * Fallback: Analyze sensitive data on main thread
   */
  fallbackAnalyzeSensitiveData(text) {
    const hasCreditCard = /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/.test(text);
    const hasSSN = /\b\d{3}-\d{2}-\d{4}\b/.test(text);

    return {
      detected: hasCreditCard || hasSSN,
      threats: (hasCreditCard || hasSSN) ? [{ type: 'SENSITIVE_DATA' }] : [],
    };
  }

  /**
   * Fallback: Analyze URL on main thread
   */
  fallbackAnalyzeURL(url) {
    const suspicious = /javascript:|data:|vbscript:/gi.test(url);

    return {
      detected: suspicious,
      threats: suspicious ? [{ type: 'SUSPICIOUS_URL' }] : [],
    };
  }

  /**
   * Get statistics
   */
  getStatistics() {
    return {
      ...this.statistics,
      workerSupported: this.workerSupported,
      workersReady: { ...this.workersReady },
      pendingTasks: this.pendingPromises.size,
    };
  }

  /**
   * Terminate all workers
   */
  terminate() {
    for (const [name, worker] of Object.entries(this.workers)) {
      if (worker) {
        worker.terminate();
        this.workersReady[name] = false;
      }
    }
  }
}

// Create singleton instance
const workerManager = new WorkerManager();

// Export for ES6 modules
export { workerManager };
export default workerManager;

