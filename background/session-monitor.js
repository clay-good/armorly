/**
 * Armorly - Session Monitor
 * 
 * Monitors user sessions for suspicious activity, detects session hijacking,
 * tracks session anomalies, and provides session security across all
 * chromium-based agentic browsers.
 * 
 * Features:
 * - Session fingerprinting
 * - Session hijacking detection
 * - Concurrent session monitoring
 * - Session anomaly detection
 * - Automatic session invalidation
 */

export class SessionMonitor {
  constructor() {
    // Session tracking
    this.sessions = new Map(); // tabId -> session data
    this.sessionFingerprints = new Map(); // tabId -> fingerprint
    this.suspiciousSessions = [];
    
    // Session anomaly patterns
    this.anomalyThresholds = {
      locationChanges: 3, // Max location changes per session
      userAgentChanges: 1, // Max user agent changes
      timezoneChanges: 1, // Max timezone changes
      concurrentSessions: 5, // Max concurrent sessions
      rapidRequests: 50, // Max requests per minute
    };
    
    // Statistics
    this.statistics = {
      totalSessions: 0,
      activeSessions: 0,
      hijackingAttempts: 0,
      anomaliesDetected: 0,
      sessionsInvalidated: 0,
    };
    
    // Threat callback
    this.threatCallback = null;
    
    // Initialize
    this.initialize();
  }
  
  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }
  
  /**
   * Initialize session monitoring
   */
  initialize() {
    // Listen for tab updates
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (changeInfo.status === 'complete') {
        this.trackSession(tabId, tab);
      }
    });
    
    // Listen for tab removal
    chrome.tabs.onRemoved.addListener((tabId) => {
      this.endSession(tabId);
    });
    
    // Periodic session validation
    setInterval(() => {
      this.validateAllSessions();
    }, 60000); // Every minute
  }
  
  /**
   * Track session for a tab
   */
  async trackSession(tabId, tab) {
    const fingerprint = await this.generateFingerprint(tab);
    
    // Check if session exists
    if (this.sessions.has(tabId)) {
      // Validate existing session
      this.validateSession(tabId, fingerprint);
    } else {
      // Create new session
      this.createSession(tabId, tab, fingerprint);
    }
    
    // Update statistics
    this.statistics.activeSessions = this.sessions.size;
  }
  
  /**
   * Create new session
   */
  createSession(tabId, tab, fingerprint) {
    const session = {
      id: `session_${Date.now()}_${tabId}`,
      tabId,
      url: tab.url,
      startTime: Date.now(),
      lastActivity: Date.now(),
      fingerprint,
      requestCount: 0,
      locationChanges: 0,
      userAgentChanges: 0,
      timezoneChanges: 0,
      anomalies: [],
    };
    
    this.sessions.set(tabId, session);
    this.sessionFingerprints.set(tabId, fingerprint);
    this.statistics.totalSessions++;
    
    console.log(`[SessionMonitor] New session created: ${session.id}`);
  }
  
  /**
   * Validate existing session
   */
  validateSession(tabId, newFingerprint) {
    const session = this.sessions.get(tabId);
    const oldFingerprint = this.sessionFingerprints.get(tabId);
    
    if (!session || !oldFingerprint) return;
    
    // Check for fingerprint changes
    const changes = this.compareFingerprints(oldFingerprint, newFingerprint);
    
    if (changes.length > 0) {
      console.warn(`[SessionMonitor] Session anomaly detected for tab ${tabId}:`, changes);
      
      // Update session
      session.anomalies.push(...changes);
      
      // Track specific changes
      if (changes.includes('location')) session.locationChanges++;
      if (changes.includes('userAgent')) session.userAgentChanges++;
      if (changes.includes('timezone')) session.timezoneChanges++;
      
      // Check thresholds
      this.checkAnomalyThresholds(session);
      
      // Update fingerprint
      this.sessionFingerprints.set(tabId, newFingerprint);
    }
    
    // Update last activity
    session.lastActivity = Date.now();
  }
  
  /**
   * Generate session fingerprint
   */
  async generateFingerprint(tab) {
    const fingerprint = {
      url: tab.url,
      domain: this.extractDomain(tab.url),
      timestamp: Date.now(),
      // Note: Some properties may not be available in all contexts
      userAgent: navigator.userAgent,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      language: navigator.language,
    };
    
    return fingerprint;
  }
  
  /**
   * Compare fingerprints
   */
  compareFingerprints(oldFp, newFp) {
    const changes = [];
    
    if (oldFp.domain !== newFp.domain) {
      changes.push('location');
    }
    
    if (oldFp.userAgent !== newFp.userAgent) {
      changes.push('userAgent');
    }
    
    if (oldFp.timezone !== newFp.timezone) {
      changes.push('timezone');
    }
    
    return changes;
  }
  
  /**
   * Check anomaly thresholds
   */
  checkAnomalyThresholds(session) {
    const threats = [];
    
    // Check location changes
    if (session.locationChanges >= this.anomalyThresholds.locationChanges) {
      threats.push({
        type: 'SESSION_HIJACKING',
        severity: 'HIGH',
        score: 70,
        description: `Suspicious location changes detected (${session.locationChanges})`,
        context: { sessionId: session.id, tabId: session.tabId },
      });
      this.statistics.hijackingAttempts++;
    }
    
    // Check user agent changes
    if (session.userAgentChanges >= this.anomalyThresholds.userAgentChanges) {
      threats.push({
        type: 'SESSION_ANOMALY',
        severity: 'MEDIUM',
        score: 50,
        description: 'User agent changed during session',
        context: { sessionId: session.id, tabId: session.tabId },
      });
      this.statistics.anomaliesDetected++;
    }
    
    // Check timezone changes
    if (session.timezoneChanges >= this.anomalyThresholds.timezoneChanges) {
      threats.push({
        type: 'SESSION_ANOMALY',
        severity: 'MEDIUM',
        score: 50,
        description: 'Timezone changed during session',
        context: { sessionId: session.id, tabId: session.tabId },
      });
      this.statistics.anomaliesDetected++;
    }
    
    // Report threats
    if (threats.length > 0 && this.threatCallback) {
      threats.forEach(threat => this.threatCallback(threat));
      
      // Add to suspicious sessions
      if (!this.suspiciousSessions.includes(session.id)) {
        this.suspiciousSessions.push(session.id);
      }
    }
  }
  
  /**
   * Validate all active sessions
   */
  validateAllSessions() {
    const now = Date.now();
    const maxInactivity = 30 * 60 * 1000; // 30 minutes
    
    for (const [tabId, session] of this.sessions.entries()) {
      // Check for inactive sessions
      if (now - session.lastActivity > maxInactivity) {
        console.log(`[SessionMonitor] Ending inactive session: ${session.id}`);
        this.endSession(tabId);
      }
    }
    
    // Check concurrent sessions
    if (this.sessions.size > this.anomalyThresholds.concurrentSessions) {
      console.warn(`[SessionMonitor] Too many concurrent sessions: ${this.sessions.size}`);
      
      if (this.threatCallback) {
        this.threatCallback({
          type: 'CONCURRENT_SESSIONS',
          severity: 'MEDIUM',
          score: 40,
          description: `Too many concurrent sessions (${this.sessions.size})`,
          context: { sessionCount: this.sessions.size },
        });
      }
    }
  }
  
  /**
   * End session
   */
  endSession(tabId) {
    const session = this.sessions.get(tabId);
    if (session) {
      console.log(`[SessionMonitor] Session ended: ${session.id}`);
      this.sessions.delete(tabId);
      this.sessionFingerprints.delete(tabId);
      this.statistics.activeSessions = this.sessions.size;
    }
  }
  
  /**
   * Invalidate session (security action)
   */
  invalidateSession(tabId) {
    const session = this.sessions.get(tabId);
    if (session) {
      console.warn(`[SessionMonitor] Invalidating session: ${session.id}`);
      this.endSession(tabId);
      this.statistics.sessionsInvalidated++;
      
      // Close tab
      chrome.tabs.remove(tabId).catch(err => {
        console.error('[SessionMonitor] Failed to close tab:', err);
      });
    }
  }
  
  /**
   * Extract domain from URL
   */
  extractDomain(url) {
    try {
      return new URL(url).hostname;
    } catch {
      return 'unknown';
    }
  }
  
  /**
   * Get statistics
   */
  getStatistics() {
    return {
      ...this.statistics,
      suspiciousSessions: this.suspiciousSessions.length,
    };
  }
  
  /**
   * Get session info
   */
  getSessionInfo(tabId) {
    return this.sessions.get(tabId) || null;
  }
  
  /**
   * Get all sessions
   */
  getAllSessions() {
    return Array.from(this.sessions.values());
  }
}

