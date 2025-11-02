/**
 * Armorly - DOM Mutation Monitor
 * 
 * Monitors DOM mutations in real-time, detects malicious DOM manipulation,
 * prevents DOM-based attacks, and provides DOM security across all
 * chromium-based agentic browsers.
 * 
 * Features:
 * - Real-time DOM mutation monitoring
 * - Malicious script injection detection
 * - Hidden content detection
 * - Suspicious attribute changes
 * - DOM-based XSS prevention
 */

export class DOMMutationMonitor {
  constructor() {
    // Mutation tracking
    this.mutations = [];
    this.suspiciousMutations = [];
    
    // Suspicious patterns
    this.suspiciousScriptPatterns = [
      /eval\s*\(/gi,
      /document\.write/gi,
      /innerHTML\s*=/gi,
      /outerHTML\s*=/gi,
      /\.src\s*=\s*["']javascript:/gi,
      /on\w+\s*=\s*["']/gi, // Event handlers
    ];
    
    this.suspiciousAttributes = [
      'onerror',
      'onload',
      'onclick',
      'onmouseover',
      'onfocus',
      'onblur',
    ];
    
    this.suspiciousUrls = [
      /javascript:/gi,
      /data:text\/html/gi,
      /vbscript:/gi,
    ];
    
    // Statistics
    this.statistics = {
      totalMutations: 0,
      suspiciousMutations: 0,
      scriptInjections: 0,
      hiddenContentDetected: 0,
      attributeChanges: 0,
    };
    
    // Threat callback
    this.threatCallback = null;
    
    // Settings
    this.settings = {
      monitorMutations: true,
      blockSuspiciousScripts: true,
      detectHiddenContent: true,
      maxMutationsPerSecond: 100,
    };
    
    // Rate limiting
    this.mutationRate = [];
  }
  
  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }
  
  /**
   * Analyze DOM mutation
   */
  analyzeMutation(mutation, tabId, url) {
    if (!this.settings.monitorMutations) return;
    
    this.statistics.totalMutations++;
    
    // Check mutation rate
    this.checkMutationRate();
    
    const threats = [];
    
    // Analyze based on mutation type
    switch (mutation.type) {
      case 'childList':
        threats.push(...this.analyzeChildListMutation(mutation));
        break;
      case 'attributes':
        threats.push(...this.analyzeAttributeMutation(mutation));
        break;
      case 'characterData':
        threats.push(...this.analyzeCharacterDataMutation(mutation));
        break;
    }
    
    // Record mutation
    this.recordMutation({
      type: mutation.type,
      timestamp: Date.now(),
      tabId,
      url,
      threats,
    });
    
    // Report threats
    if (threats.length > 0) {
      this.statistics.suspiciousMutations++;
      
      if (this.threatCallback) {
        threats.forEach(threat => this.threatCallback(threat));
      }
    }
    
    return threats;
  }
  
  /**
   * Analyze child list mutation (nodes added/removed)
   */
  analyzeChildListMutation(mutation) {
    const threats = [];
    
    // Check added nodes
    for (const node of mutation.addedNodes) {
      // Check for script injection
      if (node.nodeName === 'SCRIPT') {
        const scriptContent = node.textContent || node.src || '';
        
        // Check for suspicious patterns
        for (const pattern of this.suspiciousScriptPatterns) {
          if (pattern.test(scriptContent)) {
            threats.push({
              type: 'SCRIPT_INJECTION',
              severity: 'CRITICAL',
              score: 90,
              description: 'Suspicious script injection detected',
              context: { 
                pattern: pattern.source,
                scriptContent: scriptContent.substring(0, 100),
              },
            });
            this.statistics.scriptInjections++;
            break;
          }
        }
      }
      
      // Check for hidden content
      if (node.nodeType === Node.ELEMENT_NODE) {
        const element = node;
        if (this.isHiddenElement(element)) {
          const content = element.textContent || '';
          
          // Check if hidden content contains suspicious text
          if (content.length > 50 && this.containsSuspiciousText(content)) {
            threats.push({
              type: 'HIDDEN_CONTENT',
              severity: 'HIGH',
              score: 70,
              description: 'Suspicious hidden content detected',
              context: {
                content: content.substring(0, 100),
                tagName: element.tagName,
              },
            });
            this.statistics.hiddenContentDetected++;
          }
        }
      }
    }
    
    return threats;
  }
  
  /**
   * Analyze attribute mutation
   */
  analyzeAttributeMutation(mutation) {
    const threats = [];
    const attributeName = mutation.attributeName;
    const target = mutation.target;
    
    this.statistics.attributeChanges++;
    
    // Check for suspicious attributes
    if (this.suspiciousAttributes.includes(attributeName)) {
      const attributeValue = target.getAttribute(attributeName) || '';
      
      threats.push({
        type: 'SUSPICIOUS_ATTRIBUTE',
        severity: 'HIGH',
        score: 70,
        description: `Suspicious attribute detected: ${attributeName}`,
        context: {
          attribute: attributeName,
          value: attributeValue.substring(0, 100),
          tagName: target.tagName,
        },
      });
    }
    
    // Check for suspicious URLs in src/href
    if (attributeName === 'src' || attributeName === 'href') {
      const url = target.getAttribute(attributeName) || '';
      
      for (const pattern of this.suspiciousUrls) {
        if (pattern.test(url)) {
          threats.push({
            type: 'SUSPICIOUS_URL',
            severity: 'CRITICAL',
            score: 90,
            description: `Suspicious URL in ${attributeName}`,
            context: {
              attribute: attributeName,
              url: url.substring(0, 100),
            },
          });
          break;
        }
      }
    }
    
    return threats;
  }
  
  /**
   * Analyze character data mutation
   */
  analyzeCharacterDataMutation(mutation) {
    const threats = [];
    const content = mutation.target.textContent || '';
    
    // Check for suspicious patterns in text content
    for (const pattern of this.suspiciousScriptPatterns) {
      if (pattern.test(content)) {
        threats.push({
          type: 'SUSPICIOUS_TEXT_CONTENT',
          severity: 'MEDIUM',
          score: 50,
          description: 'Suspicious text content detected',
          context: {
            pattern: pattern.source,
            content: content.substring(0, 100),
          },
        });
        break;
      }
    }
    
    return threats;
  }
  
  /**
   * Check if element is hidden
   */
  isHiddenElement(element) {
    const style = element.style;
    const computed = window.getComputedStyle ? window.getComputedStyle(element) : null;
    
    return (
      style.display === 'none' ||
      style.visibility === 'hidden' ||
      style.opacity === '0' ||
      (computed && computed.display === 'none') ||
      (computed && computed.visibility === 'hidden') ||
      (computed && parseFloat(computed.opacity) === 0)
    );
  }
  
  /**
   * Check if text contains suspicious content
   */
  containsSuspiciousText(text) {
    const suspiciousKeywords = [
      'ignore previous',
      'disregard',
      'you are now',
      'system:',
      'admin mode',
      'override',
    ];
    
    const lowerText = text.toLowerCase();
    return suspiciousKeywords.some(keyword => lowerText.includes(keyword));
  }
  
  /**
   * Check mutation rate
   */
  checkMutationRate() {
    const now = Date.now();
    this.mutationRate.push(now);
    
    // Keep only last second
    this.mutationRate = this.mutationRate.filter(time => now - time < 1000);
    
    // Check if rate exceeds threshold
    if (this.mutationRate.length > this.settings.maxMutationsPerSecond) {
      console.warn(`[DOMMutationMonitor] High mutation rate: ${this.mutationRate.length}/sec`);
      
      if (this.threatCallback) {
        this.threatCallback({
          type: 'HIGH_MUTATION_RATE',
          severity: 'MEDIUM',
          score: 40,
          description: `Abnormally high DOM mutation rate (${this.mutationRate.length}/sec)`,
          context: { mutationRate: this.mutationRate.length },
        });
      }
    }
  }
  
  /**
   * Record mutation
   */
  recordMutation(entry) {
    this.mutations.push(entry);
    
    if (entry.threats.length > 0) {
      this.suspiciousMutations.push(entry);
    }
    
    // Limit history size
    if (this.mutations.length > 1000) {
      this.mutations.shift();
    }
    
    if (this.suspiciousMutations.length > 100) {
      this.suspiciousMutations.shift();
    }
  }
  
  /**
   * Get statistics
   */
  getStatistics() {
    return {
      ...this.statistics,
      mutationRate: this.mutationRate.length,
    };
  }
  
  /**
   * Get suspicious mutations
   */
  getSuspiciousMutations() {
    return this.suspiciousMutations;
  }
  
  /**
   * Update settings
   */
  updateSettings(newSettings) {
    this.settings = { ...this.settings, ...newSettings };
  }
}

