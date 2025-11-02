/**
 * Armorly - WebRTC Leak Monitor
 * 
 * Monitors WebRTC leaks, detects IP address exposure,
 * prevents privacy leaks, and provides WebRTC security
 * across all chromium-based agentic browsers.
 * 
 * Features:
 * - Real-time WebRTC connection monitoring
 * - IP address leak detection
 * - STUN/TURN server monitoring
 * - ICE candidate leak detection
 * - Privacy leak prevention
 */

export class WebRTCLeakMonitor {
  constructor() {
    // WebRTC tracking
    this.webrtcConnections = [];
    this.leakDetections = [];
    this.exposedIPs = new Set();
    
    // Statistics
    this.statistics = {
      totalChecks: 0,
      leaksDetected: 0,
      ipExposures: 0,
      stunRequests: 0,
      turnRequests: 0,
      blockedConnections: 0,
    };
    
    // Threat callback
    this.threatCallback = null;
    
    // Settings
    this.settings = {
      monitorWebRTC: true,
      blockLeaks: true,
      checkSTUN: true,
      checkTURN: true,
      preventIPExposure: true,
    };
    
    // Known STUN/TURN servers
    this.knownServers = new Set([
      'stun.l.google.com',
      'stun1.l.google.com',
      'stun2.l.google.com',
      'stun3.l.google.com',
      'stun4.l.google.com',
      'stun.services.mozilla.com',
    ]);
  }
  
  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }
  
  /**
   * Check WebRTC connection
   */
  checkConnection(request) {
    if (!this.settings.monitorWebRTC) return { allowed: true };
    
    this.statistics.totalChecks++;
    
    const { url, type, iceServers, tabId } = request;
    const domain = this.extractDomain(url);
    
    // Analyze connection
    const analysis = this.analyzeConnection({
      url,
      domain,
      type,
      iceServers,
      tabId,
    });
    
    // Record connection
    if (analysis.threats.length > 0) {
      this.recordConnection({
        url,
        domain,
        type,
        iceServers,
        timestamp: Date.now(),
        analysis,
      });
    }
    
    // Check for threats
    if (analysis.threats.length > 0) {
      console.warn('[WebRTCLeakMonitor] Threats detected:', analysis.threats);
      
      if (this.threatCallback) {
        analysis.threats.forEach(threat => this.threatCallback(threat));
      }
      
      if (analysis.severity === 'CRITICAL' && this.settings.blockLeaks) {
        this.statistics.blockedConnections++;
        return {
          allowed: false,
          reason: 'WebRTC leak blocked',
          threats: analysis.threats,
        };
      }
    }
    
    return { allowed: true };
  }
  
  /**
   * Analyze WebRTC connection
   */
  analyzeConnection(request) {
    const threats = [];
    let maxSeverity = 'LOW';
    
    const { domain, iceServers } = request;
    
    // Check ICE servers
    if (iceServers && iceServers.length > 0) {
      for (const server of iceServers) {
        const serverUrl = server.urls || server.url;
        
        if (!serverUrl) continue;
        
        // Check for STUN servers
        if (this.settings.checkSTUN && serverUrl.includes('stun:')) {
          this.statistics.stunRequests++;
          
          const serverDomain = this.extractServerDomain(serverUrl);
          
          if (!this.knownServers.has(serverDomain)) {
            threats.push({
              type: 'UNKNOWN_STUN_SERVER',
              severity: 'MEDIUM',
              score: 60,
              description: `Unknown STUN server detected: ${serverDomain}`,
              context: { domain, serverUrl, serverDomain },
            });
          }
        }
        
        // Check for TURN servers
        if (this.settings.checkTURN && serverUrl.includes('turn:')) {
          this.statistics.turnRequests++;
          
          const serverDomain = this.extractServerDomain(serverUrl);
          
          if (!this.knownServers.has(serverDomain)) {
            threats.push({
              type: 'UNKNOWN_TURN_SERVER',
              severity: 'MEDIUM',
              score: 60,
              description: `Unknown TURN server detected: ${serverDomain}`,
              context: { domain, serverUrl, serverDomain },
            });
          }
        }
      }
    }
    
    return {
      threats,
      severity: maxSeverity,
      hasSuspiciousActivity: threats.length > 0,
    };
  }
  
  /**
   * Check ICE candidate for IP leak
   */
  checkICECandidate(candidate) {
    if (!this.settings.preventIPExposure) return { leaked: false };
    
    const { candidate: candidateStr, sdpMid, sdpMLineIndex } = candidate;
    
    // Extract IP addresses from candidate
    const ipPattern = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g;
    const ips = candidateStr.match(ipPattern);
    
    if (ips && ips.length > 0) {
      for (const ip of ips) {
        // Check if IP is private (leak)
        if (this.isPrivateIP(ip)) {
          this.exposedIPs.add(ip);
          this.statistics.leaksDetected++;
          this.statistics.ipExposures++;
          
          this.leakDetections.push({
            ip,
            candidate: candidateStr,
            timestamp: Date.now(),
          });
          
          if (this.threatCallback) {
            this.threatCallback({
              type: 'WEBRTC_IP_LEAK',
              severity: 'HIGH',
              score: 85,
              description: `WebRTC IP leak detected: ${ip}`,
              context: { ip, candidate: candidateStr },
            });
          }
          
          return { leaked: true, ip };
        }
      }
    }
    
    return { leaked: false };
  }
  
  /**
   * Check if IP is private
   */
  isPrivateIP(ip) {
    const parts = ip.split('.').map(Number);
    
    // 10.0.0.0 - 10.255.255.255
    if (parts[0] === 10) return true;
    
    // 172.16.0.0 - 172.31.255.255
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    
    // 192.168.0.0 - 192.168.255.255
    if (parts[0] === 192 && parts[1] === 168) return true;
    
    // 127.0.0.0 - 127.255.255.255 (localhost)
    if (parts[0] === 127) return true;
    
    return false;
  }
  
  /**
   * Extract server domain from URL
   */
  extractServerDomain(serverUrl) {
    try {
      // Remove stun: or turn: prefix
      const cleanUrl = serverUrl.replace(/^(stun|turn):/, '');
      
      // Extract domain (before port)
      const domain = cleanUrl.split(':')[0];
      
      return domain;
    } catch {
      return serverUrl;
    }
  }
  
  /**
   * Record WebRTC connection
   */
  recordConnection(entry) {
    this.webrtcConnections.push(entry);
    
    // Limit connection history
    if (this.webrtcConnections.length > 1000) {
      this.webrtcConnections.shift();
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
   * Get WebRTC connections
   */
  getWebRTCConnections() {
    return this.webrtcConnections;
  }
  
  /**
   * Get leak detections
   */
  getLeakDetections() {
    return this.leakDetections;
  }
  
  /**
   * Get exposed IPs
   */
  getExposedIPs() {
    return Array.from(this.exposedIPs);
  }
  
  /**
   * Update settings
   */
  updateSettings(newSettings) {
    this.settings = { ...this.settings, ...newSettings };
  }
}

