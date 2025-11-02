/**
 * Armorly - Media Monitor
 * 
 * Monitors camera and microphone access, detects unauthorized media capture,
 * prevents surveillance attacks, and provides media privacy across all
 * chromium-based agentic browsers.
 * 
 * Features:
 * - Real-time camera/microphone access monitoring
 * - Unauthorized media capture detection
 * - Background recording prevention
 * - Privacy violation detection
 * - Media stream tracking
 */

export class MediaMonitor {
  constructor() {
    // Media access tracking
    this.mediaAccess = [];
    this.activeStreams = new Map(); // streamId -> stream data
    this.suspiciousAccess = [];
    
    // Statistics
    this.statistics = {
      totalMediaRequests: 0,
      cameraRequests: 0,
      microphoneRequests: 0,
      allowedRequests: 0,
      blockedRequests: 0,
      activeStreams: 0,
      backgroundRecordingAttempts: 0,
      privacyViolations: 0,
    };
    
    // Threat callback
    this.threatCallback = null;
    
    // Settings
    this.settings = {
      monitorMedia: true,
      blockBackgroundRecording: true,
      requireUserConsent: true,
      maxStreamsPerTab: 3,
      maxRequestsPerMinute: 5,
    };
    
    // Request rate tracking
    this.requestRates = new Map(); // tabId -> timestamps[]
  }
  
  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }
  
  /**
   * Monitor media request
   */
  monitorMediaRequest(request) {
    if (!this.settings.monitorMedia) return { allowed: true };
    
    this.statistics.totalMediaRequests++;
    
    const { type, url, tabId, timestamp, isBackground } = request;
    
    // Track request type
    if (type === 'camera' || type === 'videoinput') {
      this.statistics.cameraRequests++;
    }
    if (type === 'microphone' || type === 'audioinput') {
      this.statistics.microphoneRequests++;
    }
    
    // Check for background recording
    if (isBackground && this.settings.blockBackgroundRecording) {
      this.statistics.blockedRequests++;
      this.statistics.backgroundRecordingAttempts++;
      
      if (this.threatCallback) {
        this.threatCallback({
          type: 'BACKGROUND_MEDIA_RECORDING',
          severity: 'CRITICAL',
          score: 90,
          description: `Background ${type} recording attempt detected`,
          context: { url, tabId, type },
        });
      }
      
      this.recordSuspiciousAccess({
        type,
        url,
        tabId,
        timestamp: timestamp || Date.now(),
        reason: 'Background recording attempt',
      });
      
      return {
        allowed: false,
        reason: 'Background media recording blocked',
      };
    }
    
    // Check request rate
    const rateCheck = this.checkRequestRate(tabId);
    if (!rateCheck.allowed) {
      this.statistics.blockedRequests++;
      
      if (this.threatCallback) {
        this.threatCallback({
          type: 'EXCESSIVE_MEDIA_REQUESTS',
          severity: 'HIGH',
          score: 70,
          description: `Excessive media requests from tab ${tabId}`,
          context: { tabId, rate: rateCheck.rate },
        });
      }
      
      return {
        allowed: false,
        reason: 'Too many media requests',
      };
    }
    
    // Check active streams per tab
    const tabStreams = Array.from(this.activeStreams.values())
      .filter(stream => stream.tabId === tabId && stream.active);
    
    if (tabStreams.length >= this.settings.maxStreamsPerTab) {
      this.statistics.blockedRequests++;
      
      if (this.threatCallback) {
        this.threatCallback({
          type: 'EXCESSIVE_MEDIA_STREAMS',
          severity: 'MEDIUM',
          score: 50,
          description: `Too many active media streams in tab ${tabId}`,
          context: { tabId, count: tabStreams.length },
        });
      }
      
      return {
        allowed: false,
        reason: 'Too many active media streams',
      };
    }
    
    // Record access
    this.recordMediaAccess({
      type,
      url,
      tabId,
      timestamp: timestamp || Date.now(),
      isBackground,
    });
    
    this.statistics.allowedRequests++;
    
    return { allowed: true };
  }
  
  /**
   * Track media stream
   */
  trackStream(streamId, streamData) {
    this.activeStreams.set(streamId, {
      ...streamData,
      active: true,
      startTime: Date.now(),
    });
    
    this.statistics.activeStreams++;
  }
  
  /**
   * Stop tracking stream
   */
  stopStream(streamId) {
    const stream = this.activeStreams.get(streamId);
    if (stream) {
      stream.active = false;
      stream.endTime = Date.now();
      this.statistics.activeStreams--;
    }
  }
  
  /**
   * Check request rate
   */
  checkRequestRate(tabId) {
    const now = Date.now();
    const oneMinuteAgo = now - 60000;
    
    if (!this.requestRates.has(tabId)) {
      this.requestRates.set(tabId, []);
    }
    
    const rates = this.requestRates.get(tabId);
    
    // Remove old timestamps
    const recentRates = rates.filter(time => time > oneMinuteAgo);
    this.requestRates.set(tabId, recentRates);
    
    // Check if rate exceeded
    if (recentRates.length >= this.settings.maxRequestsPerMinute) {
      return {
        allowed: false,
        rate: recentRates.length,
      };
    }
    
    // Add current timestamp
    recentRates.push(now);
    
    return {
      allowed: true,
      rate: recentRates.length,
    };
  }
  
  /**
   * Record media access
   */
  recordMediaAccess(entry) {
    this.mediaAccess.push(entry);
    
    // Limit history size
    if (this.mediaAccess.length > 1000) {
      this.mediaAccess.shift();
    }
  }
  
  /**
   * Record suspicious access
   */
  recordSuspiciousAccess(entry) {
    this.suspiciousAccess.push(entry);
    this.statistics.privacyViolations++;
    
    // Limit history size
    if (this.suspiciousAccess.length > 100) {
      this.suspiciousAccess.shift();
    }
  }
  
  /**
   * Get statistics
   */
  getStatistics() {
    return this.statistics;
  }
  
  /**
   * Get media access history
   */
  getMediaAccessHistory() {
    return this.mediaAccess;
  }
  
  /**
   * Get active streams
   */
  getActiveStreams() {
    return Array.from(this.activeStreams.values()).filter(stream => stream.active);
  }
  
  /**
   * Get suspicious access
   */
  getSuspiciousAccess() {
    return this.suspiciousAccess;
  }
  
  /**
   * Update settings
   */
  updateSettings(newSettings) {
    this.settings = { ...this.settings, ...newSettings };
  }
}

