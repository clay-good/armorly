/**
 * WebRequest Monitor for Armorly
 * 
 * Monitors ALL network requests across ALL tabs to detect:
 * - Data exfiltration attempts
 * - Suspicious API calls
 * - Cross-origin attacks
 * - Background agent activities
 * - Command & control communications
 */

class WebRequestMonitor {
  constructor() {
    // Track request patterns per domain
    this.requestPatterns = new Map(); // domain -> { count, timestamps, suspicious }
    
    // Track data exfiltration attempts
    this.exfiltrationAttempts = new Map(); // tabId -> { requests, dataSize }
    
    // Known malicious patterns
    this.suspiciousPatterns = {
      // Data exfiltration indicators
      exfiltrationDomains: [
        'pastebin.com',
        'hastebin.com',
        'dpaste.com',
        'ghostbin.com',
        'privatebin.net',
        'transfer.sh',
        'file.io',
        'anonfiles.com',
        'mega.nz',
        'dropbox.com/s/', // Public share links
        'drive.google.com/file/d/', // Public file links
        'webhook.site',
        'requestbin.com',
        'pipedream.com',
        'ngrok.io',
        'localtunnel.me'
      ],
      
      // Suspicious URL patterns
      suspiciousParams: [
        'cmd=',
        'exec=',
        'command=',
        'eval=',
        'system=',
        'shell=',
        'data=',
        'payload=',
        'token=',
        'api_key=',
        'secret=',
        'password=',
        'auth='
      ],
      
      // AI agent API endpoints that could be abused
      aiApiEndpoints: [
        '/api/conversation',
        '/backend-api/conversation',
        '/api/chat',
        '/api/completion',
        '/v1/chat/completions',
        '/v1/completions',
        '/api/generate',
        '/api/memory',
        '/api/context'
      ]
    };
    
    // Rate limiting thresholds
    this.thresholds = {
      maxRequestsPerMinute: 100, // Per domain
      maxDataSizePerMinute: 10 * 1024 * 1024, // 10MB
      maxExfiltrationAttempts: 5
    };
    
    // Cleanup old data every minute
    setInterval(() => this.cleanup(), 60000);
  }

  /**
   * Initialize WebRequest monitoring
   */
  initialize() {
    console.log('[Armorly WebRequest] Initializing browser-level network monitoring');

    // Monitor all requests before they're sent
    chrome.webRequest.onBeforeRequest.addListener(
      (details) => this.handleBeforeRequest(details),
      { urls: ['<all_urls>'] },
      ['requestBody']
    );

    // Monitor request headers
    chrome.webRequest.onBeforeSendHeaders.addListener(
      (details) => this.handleBeforeSendHeaders(details),
      { urls: ['<all_urls>'] },
      ['requestHeaders']
    );

    // Monitor completed requests
    chrome.webRequest.onCompleted.addListener(
      (details) => this.handleCompleted(details),
      { urls: ['<all_urls>'] },
      ['responseHeaders']
    );

    console.log('[Armorly WebRequest] Monitoring active for all tabs');
  }

  /**
   * Handle request before it's sent
   */
  handleBeforeRequest(details) {
    const { url, method, requestBody, tabId, type, initiator } = details;
    
    // Skip chrome:// and extension URLs
    if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')) {
      return;
    }

    const threats = [];
    const urlObj = new URL(url);
    const domain = urlObj.hostname;

    // 1. Check for data exfiltration domains
    const isExfiltrationDomain = this.suspiciousPatterns.exfiltrationDomains.some(
      d => domain.includes(d)
    );
    if (isExfiltrationDomain) {
      threats.push({
        type: 'DATA_EXFILTRATION_DOMAIN',
        severity: 'HIGH',
        description: `Request to known data exfiltration domain: ${domain}`,
        url,
        domain,
        method
      });
    }

    // 2. Check for suspicious URL parameters
    const suspiciousParam = this.suspiciousPatterns.suspiciousParams.find(
      param => url.toLowerCase().includes(param)
    );
    if (suspiciousParam) {
      threats.push({
        type: 'SUSPICIOUS_URL_PARAMETER',
        severity: 'MEDIUM',
        description: `Suspicious parameter in URL: ${suspiciousParam}`,
        url,
        parameter: suspiciousParam
      });
    }

    // 3. Check for large POST data (potential exfiltration)
    if (method === 'POST' && requestBody) {
      const dataSize = this.estimateRequestBodySize(requestBody);
      if (dataSize > 100000) { // 100KB
        threats.push({
          type: 'LARGE_DATA_UPLOAD',
          severity: 'MEDIUM',
          description: `Large POST request detected: ${(dataSize / 1024).toFixed(2)}KB`,
          url,
          dataSize
        });
      }

      // Track exfiltration attempts
      this.trackExfiltration(tabId, url, dataSize);
    }

    // 4. Check for AI API abuse
    const isAiApiEndpoint = this.suspiciousPatterns.aiApiEndpoints.some(
      endpoint => url.includes(endpoint)
    );
    if (isAiApiEndpoint && method === 'POST') {
      // Check if request body contains suspicious patterns
      if (requestBody && requestBody.raw) {
        const bodyText = this.decodeRequestBody(requestBody);
        if (this.containsSuspiciousContent(bodyText)) {
          threats.push({
            type: 'AI_API_ABUSE',
            severity: 'HIGH',
            description: 'Suspicious content in AI API request',
            url,
            endpoint: this.suspiciousPatterns.aiApiEndpoints.find(e => url.includes(e))
          });
        }
      }
    }

    // 5. Track request rate per domain
    this.trackRequestRate(domain, tabId);
    const rateLimit = this.checkRateLimit(domain);
    if (rateLimit.exceeded) {
      threats.push({
        type: 'RATE_LIMIT_EXCEEDED',
        severity: 'MEDIUM',
        description: `Excessive requests to ${domain}: ${rateLimit.count} requests/min`,
        url,
        domain,
        count: rateLimit.count
      });
    }

    // 6. Check for cross-origin data theft
    if (initiator && type === 'xmlhttprequest') {
      try {
        const initiatorUrl = new URL(initiator);
        if (initiatorUrl.hostname !== domain) {
          threats.push({
            type: 'CROSS_ORIGIN_REQUEST',
            severity: 'LOW',
            description: `Cross-origin request from ${initiatorUrl.hostname} to ${domain}`,
            url,
            initiator: initiatorUrl.hostname,
            target: domain
          });
        }
      } catch (e) {
        // Invalid initiator URL
      }
    }

    // Report threats if found
    if (threats.length > 0) {
      this.reportThreats(tabId, url, threats);
    }
  }

  /**
   * Handle request headers before sending
   */
  handleBeforeSendHeaders(details) {
    const { url, requestHeaders, tabId } = details;
    
    if (!requestHeaders) return;

    const threats = [];

    // Check for suspicious headers
    for (const header of requestHeaders) {
      const name = header.name.toLowerCase();
      const value = header.value || '';

      // Check for token/key exfiltration in headers
      if (name.includes('authorization') || name.includes('api-key') || name.includes('token')) {
        if (value.length > 100) { // Long tokens being sent
          threats.push({
            type: 'TOKEN_EXFILTRATION',
            severity: 'HIGH',
            description: `Long authorization token being sent: ${name}`,
            url,
            header: name
          });
        }
      }

      // Check for suspicious user agents (bot indicators)
      if (name === 'user-agent') {
        const suspiciousAgents = ['bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python'];
        if (suspiciousAgents.some(agent => value.toLowerCase().includes(agent))) {
          threats.push({
            type: 'SUSPICIOUS_USER_AGENT',
            severity: 'LOW',
            description: `Suspicious user agent: ${value}`,
            url,
            userAgent: value
          });
        }
      }
    }

    if (threats.length > 0) {
      this.reportThreats(tabId, url, threats);
    }
  }

  /**
   * Handle completed request
   */
  handleCompleted(details) {
    // Track successful requests for pattern analysis
    // This could be extended to analyze response patterns
  }

  /**
   * Estimate request body size
   */
  estimateRequestBodySize(requestBody) {
    if (!requestBody) return 0;
    
    let size = 0;
    if (requestBody.raw) {
      requestBody.raw.forEach(part => {
        if (part.bytes) {
          size += part.bytes.byteLength;
        }
      });
    }
    if (requestBody.formData) {
      size += JSON.stringify(requestBody.formData).length;
    }
    return size;
  }

  /**
   * Decode request body to text
   */
  decodeRequestBody(requestBody) {
    if (!requestBody || !requestBody.raw) return '';
    
    try {
      const decoder = new TextDecoder();
      let text = '';
      requestBody.raw.forEach(part => {
        if (part.bytes) {
          text += decoder.decode(part.bytes);
        }
      });
      return text;
    } catch (e) {
      return '';
    }
  }

  /**
   * Check if content contains suspicious patterns
   */
  containsSuspiciousContent(text) {
    if (!text) return false;
    
    const suspiciousPatterns = [
      /ignore\s+previous\s+instructions/i,
      /disregard\s+all\s+prior/i,
      /system\s*:\s*you\s+are/i,
      /execute\s+command/i,
      /run\s+shell/i,
      /<script>/i,
      /eval\(/i,
      /base64/i
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(text));
  }

  /**
   * Track request rate per domain
   */
  trackRequestRate(domain, tabId) {
    if (!this.requestPatterns.has(domain)) {
      this.requestPatterns.set(domain, {
        count: 0,
        timestamps: [],
        tabIds: new Set()
      });
    }
    
    const pattern = this.requestPatterns.get(domain);
    pattern.count++;
    pattern.timestamps.push(Date.now());
    pattern.tabIds.add(tabId);
    
    // Keep only last minute of timestamps
    const oneMinuteAgo = Date.now() - 60000;
    pattern.timestamps = pattern.timestamps.filter(t => t > oneMinuteAgo);
  }

  /**
   * Check if rate limit is exceeded
   */
  checkRateLimit(domain) {
    const pattern = this.requestPatterns.get(domain);
    if (!pattern) return { exceeded: false, count: 0 };
    
    const oneMinuteAgo = Date.now() - 60000;
    const recentRequests = pattern.timestamps.filter(t => t > oneMinuteAgo);
    
    return {
      exceeded: recentRequests.length > this.thresholds.maxRequestsPerMinute,
      count: recentRequests.length
    };
  }

  /**
   * Track data exfiltration attempts
   */
  trackExfiltration(tabId, url, dataSize) {
    if (!this.exfiltrationAttempts.has(tabId)) {
      this.exfiltrationAttempts.set(tabId, {
        requests: [],
        totalSize: 0
      });
    }
    
    const attempts = this.exfiltrationAttempts.get(tabId);
    attempts.requests.push({ url, dataSize, timestamp: Date.now() });
    attempts.totalSize += dataSize;
    
    // Keep only last minute
    const oneMinuteAgo = Date.now() - 60000;
    attempts.requests = attempts.requests.filter(r => r.timestamp > oneMinuteAgo);
    attempts.totalSize = attempts.requests.reduce((sum, r) => sum + r.dataSize, 0);
  }

  /**
   * Report threats to service worker
   * Note: This is called from within the service worker, so we'll use a callback
   */
  reportThreats(tabId, url, threats) {
    console.log(`[Armorly WebRequest] Reporting ${threats.length} threats from tab ${tabId}`);

    // Call the callback if it exists (set by service worker)
    if (this.onThreatsDetected) {
      this.onThreatsDetected({
        tabId,
        url,
        threats,
        timestamp: Date.now()
      });
    }
  }

  /**
   * Set callback for threat detection
   */
  setThreatCallback(callback) {
    this.onThreatsDetected = callback;
  }

  /**
   * Cleanup old data
   */
  cleanup() {
    const oneMinuteAgo = Date.now() - 60000;
    
    // Cleanup request patterns
    for (const [domain, pattern] of this.requestPatterns.entries()) {
      pattern.timestamps = pattern.timestamps.filter(t => t > oneMinuteAgo);
      if (pattern.timestamps.length === 0) {
        this.requestPatterns.delete(domain);
      }
    }
    
    // Cleanup exfiltration attempts
    for (const [tabId, attempts] of this.exfiltrationAttempts.entries()) {
      attempts.requests = attempts.requests.filter(r => r.timestamp > oneMinuteAgo);
      if (attempts.requests.length === 0) {
        this.exfiltrationAttempts.delete(tabId);
      }
    }
  }

  /**
   * Get statistics
   */
  getStatistics() {
    return {
      monitoredDomains: this.requestPatterns.size,
      activeExfiltrationAttempts: this.exfiltrationAttempts.size,
      totalRequests: Array.from(this.requestPatterns.values())
        .reduce((sum, p) => sum + p.timestamps.length, 0)
    };
  }
}

// Export for ES6 modules
export { WebRequestMonitor };
