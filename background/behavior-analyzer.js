/**
 * Armorly - Behavioral Analyzer
 * 
 * Monitors AI agent behavior patterns in real-time to detect anomalies
 * and suspicious actions across all chromium-based agentic browsers.
 * 
 * Features:
 * - Baseline behavior establishment
 * - Anomaly detection
 * - Action frequency analysis
 * - Suspicious pattern recognition
 * - Cross-tab behavior correlation
 */

export class BehaviorAnalyzer {
  constructor() {
    // Behavior baselines
    this.baselines = {
      navigationFrequency: 0,
      formSubmissionFrequency: 0,
      storageAccessFrequency: 0,
      networkRequestFrequency: 0,
      domModificationFrequency: 0,
    };

    // Current session tracking
    this.session = {
      startTime: Date.now(),
      actions: [],
      anomalies: [],
      suspiciousPatterns: [],
    };

    // Action counters (per minute)
    this.actionCounters = {
      navigation: [],
      formSubmission: [],
      storageAccess: [],
      networkRequest: [],
      domModification: [],
      credentialAccess: [],
      sensitiveDataAccess: [],
    };

    // Anomaly thresholds
    this.thresholds = {
      navigationPerMinute: 10,
      formSubmissionPerMinute: 5,
      storageAccessPerMinute: 20,
      networkRequestPerMinute: 50,
      domModificationPerMinute: 100,
      credentialAccessPerMinute: 2,
      sensitiveDataAccessPerMinute: 5,
    };

    // Suspicious patterns
    this.suspiciousPatterns = [
      {
        name: 'RAPID_NAVIGATION',
        description: 'Rapid navigation to multiple domains',
        detector: (actions) => this.detectRapidNavigation(actions),
      },
      {
        name: 'CREDENTIAL_HARVESTING',
        description: 'Multiple credential access attempts',
        detector: (actions) => this.detectCredentialHarvesting(actions),
      },
      {
        name: 'DATA_EXFILTRATION',
        description: 'Large data transfer to suspicious domain',
        detector: (actions) => this.detectDataExfiltration(actions),
      },
      {
        name: 'FORM_AUTOMATION',
        description: 'Automated form filling and submission',
        detector: (actions) => this.detectFormAutomation(actions),
      },
      {
        name: 'STORAGE_POISONING',
        description: 'Suspicious storage modification pattern',
        detector: (actions) => this.detectStoragePoisoning(actions),
      },
      {
        name: 'CROSS_TAB_ATTACK',
        description: 'Coordinated actions across multiple tabs',
        detector: (actions) => this.detectCrossTabAttack(actions),
      },
    ];

    // Callback for anomaly detection
    this.anomalyCallback = null;

    // Start baseline learning
    this.startBaselineLearning();
  }

  /**
   * Set callback for anomaly detection
   */
  setAnomalyCallback(callback) {
    this.anomalyCallback = callback;
  }

  /**
   * Record an action
   */
  recordAction(action) {
    const timestamp = Date.now();
    const actionRecord = {
      ...action,
      timestamp,
      sessionTime: timestamp - this.session.startTime,
    };

    // Add to session
    this.session.actions.push(actionRecord);

    // Add to appropriate counter
    const actionType = action.type;
    if (this.actionCounters[actionType]) {
      this.actionCounters[actionType].push(timestamp);
      
      // Clean old entries (older than 1 minute)
      this.cleanOldCounters(actionType);
    }

    // Check for anomalies
    this.checkForAnomalies(actionRecord);

    // Check for suspicious patterns
    this.checkForSuspiciousPatterns();

    // Limit session history to last 1000 actions
    if (this.session.actions.length > 1000) {
      this.session.actions = this.session.actions.slice(-1000);
    }
  }

  /**
   * Clean old counter entries (older than 1 minute)
   */
  cleanOldCounters(actionType) {
    const oneMinuteAgo = Date.now() - 60000;
    this.actionCounters[actionType] = this.actionCounters[actionType].filter(
      timestamp => timestamp > oneMinuteAgo
    );
  }

  /**
   * Check for anomalies
   */
  checkForAnomalies(action) {
    const actionType = action.type;
    const count = this.actionCounters[actionType]?.length || 0;
    const threshold = this.thresholds[`${actionType}PerMinute`];

    if (threshold && count > threshold) {
      const anomaly = {
        type: 'FREQUENCY_ANOMALY',
        severity: 'HIGH',
        actionType,
        count,
        threshold,
        timestamp: Date.now(),
        description: `${actionType} frequency (${count}/min) exceeds threshold (${threshold}/min)`,
        action,
      };

      this.session.anomalies.push(anomaly);

      // Report anomaly
      if (this.anomalyCallback) {
        this.anomalyCallback(anomaly);
      }
    }
  }

  /**
   * Check for suspicious patterns
   */
  checkForSuspiciousPatterns() {
    const recentActions = this.session.actions.slice(-50); // Last 50 actions

    for (const pattern of this.suspiciousPatterns) {
      const detected = pattern.detector(recentActions);
      
      if (detected) {
        const suspiciousPattern = {
          type: pattern.name,
          severity: 'CRITICAL',
          description: pattern.description,
          timestamp: Date.now(),
          evidence: detected.evidence,
          confidence: detected.confidence,
        };

        // Check if already detected recently
        const alreadyDetected = this.session.suspiciousPatterns.some(
          p => p.type === pattern.name && (Date.now() - p.timestamp) < 60000
        );

        if (!alreadyDetected) {
          this.session.suspiciousPatterns.push(suspiciousPattern);

          // Report pattern
          if (this.anomalyCallback) {
            this.anomalyCallback(suspiciousPattern);
          }
        }
      }
    }
  }

  /**
   * Detect rapid navigation pattern
   */
  detectRapidNavigation(actions) {
    const navigationActions = actions.filter(a => a.type === 'navigation');
    
    if (navigationActions.length < 5) return null;

    // Check if navigations are to different domains
    const domains = new Set(navigationActions.map(a => {
      try {
        return new URL(a.url).hostname;
      } catch {
        return null;
      }
    }).filter(Boolean));

    // Check if navigations happened within 30 seconds
    const timeSpan = navigationActions[navigationActions.length - 1].timestamp - navigationActions[0].timestamp;

    if (domains.size >= 5 && timeSpan < 30000) {
      return {
        confidence: 0.9,
        evidence: {
          navigationCount: navigationActions.length,
          uniqueDomains: domains.size,
          timeSpan: timeSpan,
          domains: Array.from(domains),
        },
      };
    }

    return null;
  }

  /**
   * Detect credential harvesting pattern
   */
  detectCredentialHarvesting(actions) {
    const credentialActions = actions.filter(a => 
      a.type === 'credentialAccess' || 
      (a.type === 'domModification' && a.target?.includes('password'))
    );

    if (credentialActions.length >= 3) {
      return {
        confidence: 0.95,
        evidence: {
          accessCount: credentialActions.length,
          targets: credentialActions.map(a => a.target),
        },
      };
    }

    return null;
  }

  /**
   * Detect data exfiltration pattern
   */
  detectDataExfiltration(actions) {
    const networkActions = actions.filter(a => a.type === 'networkRequest');
    
    // Look for large POST requests to suspicious domains
    const suspiciousDomains = ['.tk', '.ml', '.ga', '.cf', '.gq', '.ru', '.cn'];
    const largeRequests = networkActions.filter(a => {
      const isSuspiciousDomain = suspiciousDomains.some(tld => a.url?.includes(tld));
      const isLargePayload = a.payloadSize && a.payloadSize > 10000; // > 10KB
      return isSuspiciousDomain && isLargePayload;
    });

    if (largeRequests.length > 0) {
      return {
        confidence: 0.85,
        evidence: {
          requestCount: largeRequests.length,
          totalSize: largeRequests.reduce((sum, r) => sum + (r.payloadSize || 0), 0),
          domains: largeRequests.map(r => r.url),
        },
      };
    }

    return null;
  }

  /**
   * Detect form automation pattern
   */
  detectFormAutomation(actions) {
    const formActions = actions.filter(a => 
      a.type === 'formSubmission' || 
      (a.type === 'domModification' && a.target?.includes('input'))
    );

    // Check for rapid form filling and submission
    if (formActions.length >= 5) {
      const timeSpan = formActions[formActions.length - 1].timestamp - formActions[0].timestamp;
      
      // If 5+ form actions in less than 5 seconds, likely automated
      if (timeSpan < 5000) {
        return {
          confidence: 0.8,
          evidence: {
            actionCount: formActions.length,
            timeSpan: timeSpan,
            actionsPerSecond: (formActions.length / (timeSpan / 1000)).toFixed(2),
          },
        };
      }
    }

    return null;
  }

  /**
   * Detect storage poisoning pattern
   */
  detectStoragePoisoning(actions) {
    const storageActions = actions.filter(a => a.type === 'storageAccess');
    
    // Look for suspicious storage writes
    const suspiciousWrites = storageActions.filter(a => {
      const key = a.key?.toLowerCase() || '';
      const value = a.value?.toLowerCase() || '';
      
      // Check for instruction-like content in storage
      const suspiciousKeywords = ['ignore', 'system', 'admin', 'override', 'instruction'];
      return suspiciousKeywords.some(keyword => key.includes(keyword) || value.includes(keyword));
    });

    if (suspiciousWrites.length > 0) {
      return {
        confidence: 0.75,
        evidence: {
          writeCount: suspiciousWrites.length,
          keys: suspiciousWrites.map(a => a.key),
        },
      };
    }

    return null;
  }

  /**
   * Detect cross-tab attack pattern
   */
  detectCrossTabAttack(actions) {
    // Look for coordinated actions across multiple tabs
    const tabIds = new Set(actions.map(a => a.tabId).filter(Boolean));
    
    if (tabIds.size >= 3) {
      // Check if actions are happening in quick succession across tabs
      const timeSpan = actions[actions.length - 1].timestamp - actions[0].timestamp;
      
      if (timeSpan < 10000) { // Within 10 seconds
        return {
          confidence: 0.7,
          evidence: {
            tabCount: tabIds.size,
            actionCount: actions.length,
            timeSpan: timeSpan,
          },
        };
      }
    }

    return null;
  }

  /**
   * Start baseline learning
   */
  startBaselineLearning() {
    // Update baselines every 5 minutes
    setInterval(() => {
      this.updateBaselines();
    }, 300000);
  }

  /**
   * Update baselines based on recent behavior
   */
  updateBaselines() {
    // Calculate average frequencies
    for (const [actionType, counter] of Object.entries(this.actionCounters)) {
      const avgFrequency = counter.length; // Already filtered to last minute
      const baselineKey = `${actionType}Frequency`;
      
      if (this.baselines[baselineKey] !== undefined) {
        // Exponential moving average
        this.baselines[baselineKey] = this.baselines[baselineKey] * 0.8 + avgFrequency * 0.2;
      }
    }
  }

  /**
   * Get current statistics
   */
  getStatistics() {
    return {
      session: {
        duration: Date.now() - this.session.startTime,
        totalActions: this.session.actions.length,
        anomalies: this.session.anomalies.length,
        suspiciousPatterns: this.session.suspiciousPatterns.length,
      },
      baselines: this.baselines,
      currentFrequencies: Object.fromEntries(
        Object.entries(this.actionCounters).map(([type, counter]) => [type, counter.length])
      ),
    };
  }

  /**
   * Get recent anomalies
   */
  getRecentAnomalies(limit = 10) {
    return this.session.anomalies.slice(-limit);
  }

  /**
   * Get suspicious patterns
   */
  getSuspiciousPatterns(limit = 10) {
    return this.session.suspiciousPatterns.slice(-limit);
  }

  /**
   * Reset session
   */
  resetSession() {
    this.session = {
      startTime: Date.now(),
      actions: [],
      anomalies: [],
      suspiciousPatterns: [],
    };
  }
}

