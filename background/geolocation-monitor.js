/**
 * Armorly - Geolocation Monitor
 * 
 * Monitors geolocation API access, detects unauthorized location tracking,
 * prevents location data leakage, and provides location privacy across
 * all chromium-based agentic browsers.
 * 
 * Features:
 * - Real-time geolocation API monitoring
 * - Unauthorized location access detection
 * - Location tracking prevention
 * - Privacy violation detection
 * - Location data anonymization
 */

export class GeolocationMonitor {
  constructor() {
    // Location access tracking
    this.locationAccess = [];
    this.suspiciousAccess = [];
    
    // Known tracking domains (common analytics/tracking services)
    this.trackingDomains = [
      'google-analytics.com',
      'googletagmanager.com',
      'facebook.com',
      'doubleclick.net',
      'analytics.google.com',
      'ads.google.com',
      'facebook.net',
      'twitter.com',
    ];
    
    // Statistics
    this.statistics = {
      totalLocationRequests: 0,
      allowedRequests: 0,
      blockedRequests: 0,
      trackingAttempts: 0,
      privacyViolations: 0,
    };
    
    // Threat callback
    this.threatCallback = null;
    
    // Settings
    this.settings = {
      monitorGeolocation: true,
      blockTrackingDomains: true,
      requireUserConsent: false,
      anonymizeLocation: false,
      maxRequestsPerMinute: 10,
    };
    
    // Request rate tracking
    this.requestRates = new Map(); // domain -> timestamps[]
  }
  
  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }
  
  /**
   * Monitor geolocation request
   */
  monitorLocationRequest(request) {
    if (!this.settings.monitorGeolocation) return { allowed: true };
    
    this.statistics.totalLocationRequests++;
    
    const { url, tabId, timestamp } = request;
    const domain = this.extractDomain(url);
    
    // Check if domain is a known tracker
    if (this.settings.blockTrackingDomains && this.isTrackingDomain(domain)) {
      this.statistics.blockedRequests++;
      this.statistics.trackingAttempts++;
      
      if (this.threatCallback) {
        this.threatCallback({
          type: 'LOCATION_TRACKING_ATTEMPT',
          severity: 'HIGH',
          score: 70,
          description: `Location tracking attempt by ${domain}`,
          context: { url, domain, tabId },
        });
      }
      
      this.recordSuspiciousAccess({
        url,
        domain,
        tabId,
        timestamp: timestamp || Date.now(),
        reason: 'Known tracking domain',
      });
      
      return {
        allowed: false,
        reason: 'Location tracking blocked',
      };
    }
    
    // Check request rate
    const rateCheck = this.checkRequestRate(domain);
    if (!rateCheck.allowed) {
      this.statistics.blockedRequests++;
      
      if (this.threatCallback) {
        this.threatCallback({
          type: 'EXCESSIVE_LOCATION_REQUESTS',
          severity: 'MEDIUM',
          score: 50,
          description: `Excessive location requests from ${domain}`,
          context: { domain, rate: rateCheck.rate },
        });
      }
      
      return {
        allowed: false,
        reason: 'Too many location requests',
      };
    }
    
    // Record access
    this.recordLocationAccess({
      url,
      domain,
      tabId,
      timestamp: timestamp || Date.now(),
    });
    
    this.statistics.allowedRequests++;
    
    return { allowed: true };
  }
  
  /**
   * Check if domain is a known tracker
   */
  isTrackingDomain(domain) {
    return this.trackingDomains.some(tracker => 
      domain.includes(tracker) || domain.endsWith(tracker)
    );
  }
  
  /**
   * Check request rate
   */
  checkRequestRate(domain) {
    const now = Date.now();
    const oneMinuteAgo = now - 60000;
    
    if (!this.requestRates.has(domain)) {
      this.requestRates.set(domain, []);
    }
    
    const rates = this.requestRates.get(domain);
    
    // Remove old timestamps
    const recentRates = rates.filter(time => time > oneMinuteAgo);
    this.requestRates.set(domain, recentRates);
    
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
   * Anonymize location data
   */
  anonymizeLocation(coords) {
    if (!this.settings.anonymizeLocation) {
      return coords;
    }
    
    // Reduce precision to ~1km
    return {
      latitude: Math.round(coords.latitude * 100) / 100,
      longitude: Math.round(coords.longitude * 100) / 100,
      accuracy: Math.max(coords.accuracy, 1000),
    };
  }
  
  /**
   * Record location access
   */
  recordLocationAccess(entry) {
    this.locationAccess.push(entry);
    
    // Limit history size
    if (this.locationAccess.length > 1000) {
      this.locationAccess.shift();
    }
  }
  
  /**
   * Record suspicious access
   */
  recordSuspiciousAccess(entry) {
    this.suspiciousAccess.push(entry);
    
    // Limit history size
    if (this.suspiciousAccess.length > 100) {
      this.suspiciousAccess.shift();
    }
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
   * Get location access history
   */
  getLocationAccessHistory() {
    return this.locationAccess;
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
  
  /**
   * Add tracking domain
   */
  addTrackingDomain(domain) {
    if (!this.trackingDomains.includes(domain)) {
      this.trackingDomains.push(domain);
    }
  }
  
  /**
   * Remove tracking domain
   */
  removeTrackingDomain(domain) {
    const index = this.trackingDomains.indexOf(domain);
    if (index > -1) {
      this.trackingDomains.splice(index, 1);
    }
  }
}

