/**
 * Network Monitor for Armorly
 * 
 * Monitors network requests for suspicious patterns:
 * - Excessive fetch/XHR requests
 * - WebSocket hijacking attempts
 * - Data exfiltration via images/beacons
 * - Suspicious request patterns
 * - Cross-origin requests to untrusted domains
 * 
 * @module network-monitor
 * @author Armorly Security Team
 * @license MIT
 */

class NetworkMonitor {
  constructor() {
    /**
     * Request log
     */
    this.requestLog = [];

    /**
     * WebSocket connections
     */
    this.webSockets = new Set();

    /**
     * Suspicious patterns
     */
    this.suspiciousPatterns = {
      exfiltration: {
        // Domains commonly used for data exfiltration
        domains: [
          'pastebin.com',
          'hastebin.com',
          'dpaste.com',
          'ghostbin.com',
          'requestbin.com',
          'webhook.site',
          'pipedream.com'
        ],
        score: 70,
        severity: 'HIGH'
      },
      excessiveRequests: {
        threshold: 50, // Max requests per minute
        score: 50,
        severity: 'MEDIUM'
      },
      suspiciousParams: {
        // URL parameters that might indicate data theft
        params: ['password', 'token', 'secret', 'api_key', 'apikey', 'auth', 'session', 'cookie'],
        score: 60,
        severity: 'HIGH'
      },
      dataURIs: {
        // Large data URIs might be exfiltrating data
        maxSize: 10000, // 10KB
        score: 55,
        severity: 'MEDIUM'
      }
    };

    /**
     * Rate limiting counters
     */
    this.rateLimits = new Map();

    /**
     * Monitoring enabled
     */
    this.enabled = true;
  }

  /**
   * Start monitoring network requests
   */
  startMonitoring() {
    if (!this.enabled) return;

    this.monitorFetch();
    this.monitorXHR();
    this.monitorWebSockets();
    this.monitorBeacons();
    this.monitorImageRequests();

    // Reset rate limits every minute
    setInterval(() => {
      this.rateLimits.clear();
    }, 60000);
  }

  /**
   * Monitor fetch API
   */
  monitorFetch() {
    const originalFetch = window.fetch;
    const self = this;

    window.fetch = function(...args) {
      const url = args[0];
      const options = args[1] || {};

      self.logRequest('fetch', url, options);

      return originalFetch.apply(this, args);
    };
  }

  /**
   * Monitor XMLHttpRequest
   */
  monitorXHR() {
    const originalOpen = XMLHttpRequest.prototype.open;
    const originalSend = XMLHttpRequest.prototype.send;
    const self = this;

    XMLHttpRequest.prototype.open = function(method, url, ...args) {
      this._armorlyMethod = method;
      this._armorlyUrl = url;
      return originalOpen.call(this, method, url, ...args);
    };

    XMLHttpRequest.prototype.send = function(data) {
      self.logRequest('xhr', this._armorlyUrl, {
        method: this._armorlyMethod,
        data: data
      });
      return originalSend.call(this, data);
    };
  }

  /**
   * Monitor WebSocket connections
   */
  monitorWebSockets() {
    const originalWebSocket = window.WebSocket;
    const self = this;

    window.WebSocket = function(url, protocols) {
      self.logWebSocket(url);
      const ws = new originalWebSocket(url, protocols);
      self.webSockets.add(ws);

      // Monitor messages
      const originalSend = ws.send;
      ws.send = function(data) {
        self.logWebSocketMessage(url, data);
        return originalSend.call(this, data);
      };

      return ws;
    };
  }

  /**
   * Monitor navigator.sendBeacon
   */
  monitorBeacons() {
    if (!navigator.sendBeacon) return;

    const originalSendBeacon = navigator.sendBeacon;
    const self = this;

    navigator.sendBeacon = function(url, data) {
      self.logRequest('beacon', url, { data });
      return originalSendBeacon.call(this, url, data);
    };
  }

  /**
   * Monitor image requests (common exfiltration vector)
   */
  monitorImageRequests() {
    const originalImage = window.Image;
    const self = this;

    window.Image = function() {
      const img = new originalImage();
      
      const originalSrcSetter = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src').set;
      Object.defineProperty(img, 'src', {
        set: function(value) {
          self.logRequest('image', value, {});
          return originalSrcSetter.call(this, value);
        },
        get: function() {
          return this.getAttribute('src');
        }
      });

      return img;
    };
  }

  /**
   * Log a network request
   * 
   * @param {string} type - Request type (fetch, xhr, beacon, image)
   * @param {string} url - Request URL
   * @param {Object} options - Request options
   */
  logRequest(type, url, options) {
    const timestamp = Date.now();
    
    // Log the request
    this.requestLog.push({
      type,
      url,
      options,
      timestamp,
      pageUrl: window.location.href
    });

    // Keep only last 200 entries
    if (this.requestLog.length > 200) {
      this.requestLog.shift();
    }

    // Check for suspicious patterns
    this.checkSuspiciousRequest(type, url, options);

    // Check rate limits
    const key = `${type}:${url}`;
    const count = (this.rateLimits.get(key) || 0) + 1;
    this.rateLimits.set(key, count);

    if (count > this.suspiciousPatterns.excessiveRequests.threshold) {
      this.reportThreat({
        type: 'EXCESSIVE_REQUESTS',
        requestType: type,
        url: url,
        count: count,
        severity: 'MEDIUM',
        score: 50,
        description: `Excessive ${type} requests detected: ${count} requests in 1 minute`
      });
    }
  }

  /**
   * Log WebSocket connection
   * 
   * @param {string} url - WebSocket URL
   */
  logWebSocket(url) {
    this.logRequest('websocket', url, {});
    
    // Check if WebSocket URL is suspicious
    if (this.isSuspiciousDomain(url)) {
      this.reportThreat({
        type: 'SUSPICIOUS_WEBSOCKET',
        url: url,
        severity: 'HIGH',
        score: 65,
        description: `WebSocket connection to suspicious domain: ${url}`
      });
    }
  }

  /**
   * Log WebSocket message
   * 
   * @param {string} url - WebSocket URL
   * @param {*} data - Message data
   */
  logWebSocketMessage(url, data) {
    // Check if message contains sensitive data
    if (typeof data === 'string' && this.containsSensitiveData(data)) {
      this.reportThreat({
        type: 'WEBSOCKET_DATA_LEAK',
        url: url,
        severity: 'HIGH',
        score: 70,
        description: 'WebSocket message may contain sensitive data'
      });
    }
  }

  /**
   * Check if request is suspicious
   * 
   * @param {string} type - Request type
   * @param {string} url - Request URL
   * @param {Object} options - Request options
   */
  checkSuspiciousRequest(type, url, options) {
    try {
      const urlObj = new URL(url, window.location.href);

      // Check for exfiltration domains
      if (this.isSuspiciousDomain(url)) {
        this.reportThreat({
          type: 'DATA_EXFILTRATION_ATTEMPT',
          requestType: type,
          url: url,
          severity: 'HIGH',
          score: 70,
          description: `Request to known exfiltration domain: ${urlObj.hostname}`
        });
      }

      // Check for suspicious URL parameters
      const suspiciousParams = this.checkSuspiciousParams(urlObj);
      if (suspiciousParams.length > 0) {
        this.reportThreat({
          type: 'SUSPICIOUS_URL_PARAMS',
          requestType: type,
          url: url,
          params: suspiciousParams,
          severity: 'HIGH',
          score: 60,
          description: `Request contains suspicious parameters: ${suspiciousParams.join(', ')}`
        });
      }

      // Check for data URI exfiltration
      if (url.startsWith('data:') && url.length > this.suspiciousPatterns.dataURIs.maxSize) {
        this.reportThreat({
          type: 'LARGE_DATA_URI',
          requestType: type,
          size: url.length,
          severity: 'MEDIUM',
          score: 55,
          description: `Large data URI detected (${url.length} bytes) - possible data exfiltration`
        });
      }

    } catch (error) {
      // Invalid URL, ignore
    }
  }

  /**
   * Check if domain is suspicious
   * 
   * @param {string} url - URL to check
   * @returns {boolean} True if suspicious
   */
  isSuspiciousDomain(url) {
    try {
      const urlObj = new URL(url, window.location.href);
      const hostname = urlObj.hostname.toLowerCase();

      return this.suspiciousPatterns.exfiltration.domains.some(domain => 
        hostname.includes(domain)
      );
    } catch (error) {
      return false;
    }
  }

  /**
   * Check for suspicious URL parameters
   * 
   * @param {URL} urlObj - URL object
   * @returns {Array} Suspicious parameter names
   */
  checkSuspiciousParams(urlObj) {
    const suspicious = [];
    const params = this.suspiciousPatterns.suspiciousParams.params;

    for (const [key, value] of urlObj.searchParams) {
      const keyLower = key.toLowerCase();
      if (params.some(param => keyLower.includes(param))) {
        suspicious.push(key);
      }
    }

    return suspicious;
  }

  /**
   * Check if data contains sensitive information
   * 
   * @param {string} data - Data to check
   * @returns {boolean} True if sensitive
   */
  containsSensitiveData(data) {
    const sensitivePatterns = [
      /password/i,
      /token/i,
      /api[_-]?key/i,
      /secret/i,
      /auth/i,
      /session/i,
      /cookie/i,
      /credit[_-]?card/i,
      /ssn/i
    ];

    return sensitivePatterns.some(pattern => pattern.test(data));
  }

  /**
   * Report a network threat
   * 
   * @param {Object} threat - Threat details
   */
  reportThreat(threat) {
    // Send to background script
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({
        type: 'THREATS_DETECTED',
        threats: [threat],
        url: window.location.href,
        timestamp: Date.now()
      }).catch(err => {
        console.error('[Armorly] Error reporting network threat:', err);
      });
    }
  }

  /**
   * Get request log
   * 
   * @returns {Array} Request log entries
   */
  getRequestLog() {
    return this.requestLog;
  }

  /**
   * Clear request log
   */
  clearLog() {
    this.requestLog = [];
    this.rateLimits.clear();
  }

  /**
   * Stop monitoring
   */
  stopMonitoring() {
    this.enabled = false;
  }
}

// Export for use in content script
if (typeof window !== 'undefined') {
  window.NetworkMonitor = NetworkMonitor;
}

