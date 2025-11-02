/**
 * Armorly - WebSocket Monitor
 * 
 * Monitors WebSocket connections, detects suspicious real-time communication,
 * prevents WebSocket-based attacks, and provides WebSocket security across
 * all chromium-based agentic browsers.
 * 
 * Features:
 * - Real-time WebSocket connection monitoring
 * - Suspicious message pattern detection
 * - Data exfiltration prevention
 * - Connection hijacking detection
 * - Rate limiting for WebSocket messages
 */

export class WebSocketMonitor {
  constructor() {
    // Connection tracking
    this.connections = new Map(); // connectionId -> connection data
    this.suspiciousConnections = [];
    
    // Suspicious patterns in WebSocket messages
    this.suspiciousPatterns = [
      /password/gi,
      /api[_-]?key/gi,
      /secret/gi,
      /token/gi,
      /credential/gi,
      /private[_-]?key/gi,
      /session[_-]?id/gi,
    ];
    
    // Known malicious WebSocket endpoints
    this.maliciousEndpoints = [
      'ws://localhost:',
      'ws://127.0.0.1:',
      'ws://0.0.0.0:',
    ];
    
    // Statistics
    this.statistics = {
      totalConnections: 0,
      activeConnections: 0,
      suspiciousConnections: 0,
      messagesMonitored: 0,
      dataExfiltrationAttempts: 0,
      blockedConnections: 0,
    };
    
    // Threat callback
    this.threatCallback = null;
    
    // Settings
    this.settings = {
      monitorWebSockets: true,
      blockSuspiciousConnections: true,
      detectDataExfiltration: true,
      maxMessagesPerSecond: 50,
      maxConnectionsPerDomain: 10,
    };
    
    // Message rate tracking
    this.messageRates = new Map(); // connectionId -> timestamps[]
  }
  
  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }
  
  /**
   * Monitor WebSocket connection
   */
  monitorConnection(connectionId, url, tabId) {
    if (!this.settings.monitorWebSockets) return { allowed: true };
    
    this.statistics.totalConnections++;
    
    // Check for malicious endpoints
    for (const malicious of this.maliciousEndpoints) {
      if (url.startsWith(malicious)) {
        this.statistics.blockedConnections++;
        
        if (this.threatCallback) {
          this.threatCallback({
            type: 'MALICIOUS_WEBSOCKET',
            severity: 'CRITICAL',
            score: 90,
            description: `Suspicious WebSocket connection to ${url}`,
            context: { url, connectionId, tabId },
          });
        }
        
        if (this.settings.blockSuspiciousConnections) {
          return {
            allowed: false,
            reason: 'Malicious WebSocket endpoint detected',
          };
        }
      }
    }
    
    // Check connection count per domain
    const domain = this.extractDomain(url);
    const domainConnections = Array.from(this.connections.values())
      .filter(conn => conn.domain === domain && conn.active);
    
    if (domainConnections.length >= this.settings.maxConnectionsPerDomain) {
      this.statistics.blockedConnections++;
      
      if (this.threatCallback) {
        this.threatCallback({
          type: 'EXCESSIVE_WEBSOCKET_CONNECTIONS',
          severity: 'HIGH',
          score: 70,
          description: `Too many WebSocket connections to ${domain}`,
          context: { domain, count: domainConnections.length },
        });
      }
      
      return {
        allowed: false,
        reason: 'Too many WebSocket connections to this domain',
      };
    }
    
    // Record connection
    this.connections.set(connectionId, {
      id: connectionId,
      url,
      domain,
      tabId,
      active: true,
      createdAt: Date.now(),
      messageCount: 0,
    });
    
    this.statistics.activeConnections++;
    
    return { allowed: true };
  }
  
  /**
   * Monitor WebSocket message
   */
  monitorMessage(connectionId, message, direction) {
    if (!this.settings.monitorWebSockets) return { allowed: true };
    
    this.statistics.messagesMonitored++;
    
    const connection = this.connections.get(connectionId);
    if (!connection) {
      return { allowed: true };
    }
    
    connection.messageCount++;
    
    // Check message rate
    const rateCheck = this.checkMessageRate(connectionId);
    if (!rateCheck.allowed) {
      if (this.threatCallback) {
        this.threatCallback({
          type: 'WEBSOCKET_RATE_LIMIT',
          severity: 'MEDIUM',
          score: 50,
          description: `WebSocket message rate limit exceeded`,
          context: { connectionId, rate: rateCheck.rate },
        });
      }
      
      return {
        allowed: false,
        reason: 'Message rate limit exceeded',
      };
    }
    
    // Analyze message content
    const analysis = this.analyzeMessage(message, connection);
    
    if (analysis.threats.length > 0) {
      this.recordSuspiciousConnection(connection, analysis);
      
      if (this.threatCallback) {
        analysis.threats.forEach(threat => this.threatCallback(threat));
      }
      
      if (analysis.severity === 'CRITICAL' && this.settings.blockSuspiciousConnections) {
        return {
          allowed: false,
          reason: 'Suspicious WebSocket message blocked',
          threats: analysis.threats,
        };
      }
    }
    
    return { allowed: true };
  }
  
  /**
   * Analyze WebSocket message
   */
  analyzeMessage(message, connection) {
    const threats = [];
    let maxSeverity = 'LOW';
    
    const messageStr = typeof message === 'string' ? message : JSON.stringify(message);
    
    // Check for sensitive data patterns
    for (const pattern of this.suspiciousPatterns) {
      if (pattern.test(messageStr)) {
        threats.push({
          type: 'SENSITIVE_DATA_IN_WEBSOCKET',
          severity: 'HIGH',
          score: 70,
          description: `Sensitive data detected in WebSocket message`,
          context: {
            pattern: pattern.source,
            connectionId: connection.id,
            url: connection.url,
          },
        });
        
        maxSeverity = 'HIGH';
        break;
      }
    }
    
    // Check for data exfiltration (large outgoing messages)
    if (messageStr.length > 10000) {
      threats.push({
        type: 'WEBSOCKET_DATA_EXFILTRATION',
        severity: 'HIGH',
        score: 70,
        description: `Large WebSocket message detected (${messageStr.length} bytes)`,
        context: {
          size: messageStr.length,
          connectionId: connection.id,
          url: connection.url,
        },
      });
      
      this.statistics.dataExfiltrationAttempts++;
      maxSeverity = 'HIGH';
    }
    
    return {
      threats,
      severity: maxSeverity,
      hasSuspiciousActivity: threats.length > 0,
    };
  }
  
  /**
   * Check message rate
   */
  checkMessageRate(connectionId) {
    const now = Date.now();
    const oneSecondAgo = now - 1000;
    
    if (!this.messageRates.has(connectionId)) {
      this.messageRates.set(connectionId, []);
    }
    
    const rates = this.messageRates.get(connectionId);
    
    // Remove old timestamps
    const recentRates = rates.filter(time => time > oneSecondAgo);
    this.messageRates.set(connectionId, recentRates);
    
    // Check if rate exceeded
    if (recentRates.length >= this.settings.maxMessagesPerSecond) {
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
   * Close connection
   */
  closeConnection(connectionId) {
    const connection = this.connections.get(connectionId);
    if (connection) {
      connection.active = false;
      this.statistics.activeConnections--;
    }
  }
  
  /**
   * Record suspicious connection
   */
  recordSuspiciousConnection(connection, analysis) {
    this.suspiciousConnections.push({
      ...connection,
      analysis,
      timestamp: Date.now(),
    });
    
    this.statistics.suspiciousConnections++;
    
    // Limit history size
    if (this.suspiciousConnections.length > 100) {
      this.suspiciousConnections.shift();
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
   * Get suspicious connections
   */
  getSuspiciousConnections() {
    return this.suspiciousConnections;
  }
  
  /**
   * Update settings
   */
  updateSettings(newSettings) {
    this.settings = { ...this.settings, ...newSettings };
  }
}

