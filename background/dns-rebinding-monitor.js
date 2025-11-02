/**
 * Armorly - DNS Rebinding Monitor
 * 
 * Monitors DNS rebinding attacks, detects IP address changes,
 * prevents unauthorized access to internal networks, and provides
 * DNS security across all chromium-based agentic browsers.
 * 
 * Features:
 * - Real-time DNS resolution monitoring
 * - IP address change detection
 * - Private IP access prevention
 * - Localhost access detection
 * - DNS rebinding attack prevention
 */

export class DNSRebindingMonitor {
  constructor() {
    // DNS tracking
    this.dnsResolutions = new Map(); // domain -> [ip1, ip2, ...]
    this.rebindingAttempts = [];
    
    // Statistics
    this.statistics = {
      totalChecks: 0,
      rebindingDetected: 0,
      ipChanges: 0,
      privateIPAccess: 0,
      localhostAccess: 0,
      blockedRequests: 0,
    };
    
    // Threat callback
    this.threatCallback = null;
    
    // Settings
    this.settings = {
      monitorDNS: true,
      blockRebinding: true,
      blockPrivateIP: true,
      blockLocalhost: true,
      trackIPChanges: true,
    };
    
    // Whitelist for legitimate services
    this.whitelist = new Set([
      'localhost',
      '127.0.0.1',
      '::1',
    ]);
  }
  
  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }
  
  /**
   * Check DNS request
   */
  checkRequest(request) {
    if (!this.settings.monitorDNS) return { allowed: true };
    
    this.statistics.totalChecks++;
    
    const { url, ip, tabId } = request;
    const domain = this.extractDomain(url);
    
    // Analyze request
    const analysis = this.analyzeRequest({
      url,
      domain,
      ip,
      tabId,
    });
    
    // Record attempt
    if (analysis.threats.length > 0) {
      this.recordAttempt({
        url,
        domain,
        ip,
        timestamp: Date.now(),
        analysis,
      });
    }
    
    // Check for threats
    if (analysis.threats.length > 0) {
      console.warn('[DNSRebindingMonitor] Threats detected:', analysis.threats);
      
      if (this.threatCallback) {
        analysis.threats.forEach(threat => this.threatCallback(threat));
      }
      
      if (analysis.severity === 'CRITICAL' && this.settings.blockRebinding) {
        this.statistics.blockedRequests++;
        return {
          allowed: false,
          reason: 'DNS rebinding attack blocked',
          threats: analysis.threats,
        };
      }
    }
    
    return { allowed: true };
  }
  
  /**
   * Analyze DNS request
   */
  analyzeRequest(request) {
    const threats = [];
    let maxSeverity = 'LOW';
    
    const { domain, ip } = request;
    
    // Check for localhost access
    if (this.settings.blockLocalhost && this.isLocalhost(ip)) {
      if (!this.whitelist.has(domain)) {
        threats.push({
          type: 'LOCALHOST_ACCESS',
          severity: 'HIGH',
          score: 85,
          description: `Localhost access detected from ${domain}`,
          context: { domain, ip },
        });
        
        this.statistics.rebindingDetected++;
        this.statistics.localhostAccess++;
        maxSeverity = 'HIGH';
      }
    }
    
    // Check for private IP access
    if (this.settings.blockPrivateIP && this.isPrivateIP(ip)) {
      if (!this.whitelist.has(domain)) {
        threats.push({
          type: 'PRIVATE_IP_ACCESS',
          severity: 'HIGH',
          score: 80,
          description: `Private IP access detected: ${domain} -> ${ip}`,
          context: { domain, ip },
        });
        
        this.statistics.rebindingDetected++;
        this.statistics.privateIPAccess++;
        maxSeverity = 'HIGH';
      }
    }
    
    // Check for DNS rebinding (IP change)
    if (this.settings.trackIPChanges) {
      const previousIPs = this.dnsResolutions.get(domain) || [];
      
      if (previousIPs.length > 0 && !previousIPs.includes(ip)) {
        // IP changed - potential DNS rebinding
        const wasPublic = previousIPs.some(prevIP => !this.isPrivateIP(prevIP) && !this.isLocalhost(prevIP));
        const nowPrivate = this.isPrivateIP(ip) || this.isLocalhost(ip);
        
        if (wasPublic && nowPrivate) {
          threats.push({
            type: 'DNS_REBINDING_ATTACK',
            severity: 'CRITICAL',
            score: 95,
            description: `DNS rebinding detected: ${domain} changed from public to private IP`,
            context: { domain, previousIPs, currentIP: ip },
          });
          
          this.statistics.rebindingDetected++;
          maxSeverity = 'CRITICAL';
        } else {
          threats.push({
            type: 'DNS_IP_CHANGE',
            severity: 'MEDIUM',
            score: 60,
            description: `DNS IP change detected for ${domain}`,
            context: { domain, previousIPs, currentIP: ip },
          });
          
          this.statistics.ipChanges++;
        }
      }
      
      // Update DNS resolution cache
      if (!previousIPs.includes(ip)) {
        previousIPs.push(ip);
        this.dnsResolutions.set(domain, previousIPs);
        
        // Limit IP history per domain
        if (previousIPs.length > 10) {
          previousIPs.shift();
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
   * Check if IP is localhost
   */
  isLocalhost(ip) {
    return (
      ip === '127.0.0.1' ||
      ip === 'localhost' ||
      ip === '::1' ||
      ip.startsWith('127.')
    );
  }
  
  /**
   * Check if IP is private
   */
  isPrivateIP(ip) {
    // IPv6 private addresses
    if (ip.includes(':')) {
      return (
        ip.startsWith('fc') ||
        ip.startsWith('fd') ||
        ip.startsWith('fe80')
      );
    }
    
    // IPv4 private addresses
    const parts = ip.split('.').map(Number);
    
    if (parts.length !== 4) return false;
    
    // 10.0.0.0 - 10.255.255.255
    if (parts[0] === 10) return true;
    
    // 172.16.0.0 - 172.31.255.255
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    
    // 192.168.0.0 - 192.168.255.255
    if (parts[0] === 192 && parts[1] === 168) return true;
    
    // 169.254.0.0 - 169.254.255.255 (link-local)
    if (parts[0] === 169 && parts[1] === 254) return true;
    
    return false;
  }
  
  /**
   * Record rebinding attempt
   */
  recordAttempt(entry) {
    this.rebindingAttempts.push(entry);
    
    // Limit attempt history
    if (this.rebindingAttempts.length > 1000) {
      this.rebindingAttempts.shift();
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
   * Add to whitelist
   */
  addToWhitelist(domain) {
    this.whitelist.add(domain);
  }
  
  /**
   * Remove from whitelist
   */
  removeFromWhitelist(domain) {
    this.whitelist.delete(domain);
  }
  
  /**
   * Get statistics
   */
  getStatistics() {
    return this.statistics;
  }
  
  /**
   * Get rebinding attempts
   */
  getRebindingAttempts() {
    return this.rebindingAttempts;
  }
  
  /**
   * Get DNS resolutions
   */
  getDNSResolutions() {
    return Array.from(this.dnsResolutions.entries()).map(([domain, ips]) => ({
      domain,
      ips,
    }));
  }
  
  /**
   * Clear DNS cache
   */
  clearDNSCache() {
    this.dnsResolutions.clear();
  }
  
  /**
   * Update settings
   */
  updateSettings(newSettings) {
    this.settings = { ...this.settings, ...newSettings };
  }
}

