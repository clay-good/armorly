/**
 * Armorly - Network Timing Monitor
 * 
 * Monitors network timing attacks, detects timing-based side channels,
 * prevents cache timing attacks, and provides timing attack protection
 * across all chromium-based agentic browsers.
 * 
 * Features:
 * - Real-time network timing analysis
 * - Cache timing attack detection
 * - Side-channel attack prevention
 * - Timing correlation analysis
 * - Suspicious timing pattern detection
 */

export class NetworkTimingMonitor {
  constructor() {
    // Timing data tracking
    this.timingData = [];
    this.suspiciousTimings = [];
    
    // Timing thresholds (in milliseconds)
    this.thresholds = {
      minResponseTime: 1, // Suspiciously fast (cache timing attack)
      maxResponseTime: 30000, // Suspiciously slow (30 seconds)
      timingVariance: 0.95, // High correlation (>95% similar)
      rapidRequests: 100, // Requests per second
    };
    
    // Statistics
    this.statistics = {
      totalRequests: 0,
      cacheTimingAttacks: 0,
      sideChannelAttacks: 0,
      timingAnomalies: 0,
      suspiciousPatterns: 0,
      blockedRequests: 0,
    };
    
    // Threat callback
    this.threatCallback = null;
    
    // Settings
    this.settings = {
      monitorNetworkTiming: true,
      detectCacheTimingAttacks: true,
      detectSideChannelAttacks: true,
      blockSuspiciousTimings: false, // Don't block by default
    };
    
    // Request timing tracking
    this.requestTimings = new Map(); // domain -> timing[]
  }
  
  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }
  
  /**
   * Monitor network timing
   */
  monitorTiming(request) {
    if (!this.settings.monitorNetworkTiming) return { allowed: true };
    
    this.statistics.totalRequests++;
    
    const { url, startTime, endTime, responseTime, tabId } = request;
    const domain = this.extractDomain(url);
    
    // Analyze timing
    const analysis = this.analyzeTiming({
      url,
      domain,
      startTime,
      endTime,
      responseTime,
      tabId,
    });
    
    // Record timing
    this.recordTiming({
      url,
      domain,
      startTime,
      endTime,
      responseTime,
      tabId,
      timestamp: Date.now(),
      analysis,
    });
    
    // Check for threats
    if (analysis.threats.length > 0) {
      console.warn('[NetworkTimingMonitor] Threats detected:', analysis.threats);
      
      if (this.threatCallback) {
        analysis.threats.forEach(threat => this.threatCallback(threat));
      }
      
      if (analysis.severity === 'CRITICAL' && this.settings.blockSuspiciousTimings) {
        this.statistics.blockedRequests++;
        return {
          allowed: false,
          reason: 'Suspicious network timing blocked',
          threats: analysis.threats,
        };
      }
    }
    
    return { allowed: true };
  }
  
  /**
   * Analyze timing data
   */
  analyzeTiming(timing) {
    const threats = [];
    let maxSeverity = 'LOW';
    
    const { domain, responseTime } = timing;
    
    // Check for suspiciously fast responses (cache timing attack)
    if (this.settings.detectCacheTimingAttacks && responseTime < this.thresholds.minResponseTime) {
      threats.push({
        type: 'CACHE_TIMING_ATTACK',
        severity: 'HIGH',
        score: 70,
        description: `Suspiciously fast response time (${responseTime}ms) - possible cache timing attack`,
        context: { domain, responseTime },
      });
      
      this.statistics.cacheTimingAttacks++;
      maxSeverity = 'HIGH';
    }
    
    // Check for suspiciously slow responses
    if (responseTime > this.thresholds.maxResponseTime) {
      threats.push({
        type: 'SLOW_RESPONSE_TIMING',
        severity: 'MEDIUM',
        score: 40,
        description: `Suspiciously slow response time (${responseTime}ms)`,
        context: { domain, responseTime },
      });
      
      this.statistics.timingAnomalies++;
      
      if (maxSeverity === 'LOW') {
        maxSeverity = 'MEDIUM';
      }
    }
    
    // Check for timing correlation (side-channel attack)
    if (this.settings.detectSideChannelAttacks) {
      const correlation = this.checkTimingCorrelation(domain, responseTime);
      
      if (correlation.suspicious) {
        threats.push({
          type: 'SIDE_CHANNEL_TIMING_ATTACK',
          severity: 'HIGH',
          score: 75,
          description: `High timing correlation detected (${(correlation.score * 100).toFixed(1)}%) - possible side-channel attack`,
          context: { domain, correlation: correlation.score },
        });
        
        this.statistics.sideChannelAttacks++;
        maxSeverity = 'HIGH';
      }
    }
    
    // Check request rate
    const rateCheck = this.checkRequestRate(domain);
    if (!rateCheck.allowed) {
      threats.push({
        type: 'RAPID_TIMING_REQUESTS',
        severity: 'MEDIUM',
        score: 50,
        description: `Rapid timing requests from ${domain} (${rateCheck.rate}/sec)`,
        context: { domain, rate: rateCheck.rate },
      });
      
      this.statistics.suspiciousPatterns++;
      
      if (maxSeverity === 'LOW') {
        maxSeverity = 'MEDIUM';
      }
    }
    
    return {
      threats,
      severity: maxSeverity,
      hasSuspiciousActivity: threats.length > 0,
    };
  }
  
  /**
   * Check timing correlation (detect side-channel attacks)
   */
  checkTimingCorrelation(domain, responseTime) {
    if (!this.requestTimings.has(domain)) {
      this.requestTimings.set(domain, []);
    }
    
    const timings = this.requestTimings.get(domain);
    
    // Need at least 10 samples for correlation
    if (timings.length < 10) {
      timings.push(responseTime);
      return { suspicious: false, score: 0 };
    }
    
    // Calculate mean and variance
    const mean = timings.reduce((sum, t) => sum + t, 0) / timings.length;
    const variance = timings.reduce((sum, t) => sum + Math.pow(t - mean, 2), 0) / timings.length;
    const stdDev = Math.sqrt(variance);
    
    // Calculate coefficient of variation (CV)
    const cv = stdDev / mean;
    
    // Low CV means high correlation (suspicious)
    const correlation = 1 - cv;
    
    // Add current timing
    timings.push(responseTime);
    
    // Keep only last 100 timings
    if (timings.length > 100) {
      timings.shift();
    }
    
    return {
      suspicious: correlation > this.thresholds.timingVariance,
      score: correlation,
    };
  }
  
  /**
   * Check request rate
   */
  checkRequestRate(domain) {
    const now = Date.now();
    const oneSecondAgo = now - 1000;
    
    const recentTimings = this.timingData.filter(
      t => t.domain === domain && t.timestamp > oneSecondAgo
    );
    
    return {
      allowed: recentTimings.length < this.thresholds.rapidRequests,
      rate: recentTimings.length,
    };
  }
  
  /**
   * Record timing
   */
  recordTiming(entry) {
    this.timingData.push(entry);
    
    if (entry.analysis.hasSuspiciousActivity) {
      this.suspiciousTimings.push(entry);
      
      // Limit history size
      if (this.suspiciousTimings.length > 100) {
        this.suspiciousTimings.shift();
      }
    }
    
    // Limit timing history
    if (this.timingData.length > 1000) {
      this.timingData.shift();
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
   * Get suspicious timings
   */
  getSuspiciousTimings() {
    return this.suspiciousTimings;
  }
  
  /**
   * Update settings
   */
  updateSettings(newSettings) {
    this.settings = { ...this.settings, ...newSettings };
  }
}

