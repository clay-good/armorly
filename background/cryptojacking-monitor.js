/**
 * Armorly - Cryptojacking Monitor
 * 
 * Monitors cryptojacking attempts, detects cryptocurrency mining scripts,
 * prevents unauthorized CPU usage, and provides mining protection across
 * all chromium-based agentic browsers.
 * 
 * Features:
 * - Real-time mining script detection
 * - CPU usage monitoring
 * - WebAssembly mining detection
 * - Known miner blocking
 * - Resource abuse prevention
 */

export class CryptojackingMonitor {
  constructor() {
    // Mining detection tracking
    this.miningAttempts = [];
    this.suspiciousScripts = new Map(); // scriptUrl -> data
    
    // Known mining pools and services
    this.knownMiners = [
      'coinhive',
      'jsecoin',
      'crypto-loot',
      'coin-hive',
      'minero',
      'webminer',
      'cryptonight',
      'monero',
      'xmrig',
      'deepminer',
      'minergate',
      'authedmine',
    ];
    
    // Mining-related domains
    this.miningDomains = [
      'coinhive.com',
      'coin-hive.com',
      'jsecoin.com',
      'crypto-loot.com',
      'webminepool.com',
      'minero.cc',
      'ppoi.org',
      'reasedoper.pw',
      'mataharirama.xyz',
      'listat.biz',
    ];
    
    // Suspicious WebAssembly patterns
    this.wasmPatterns = [
      /cryptonight/gi,
      /monero/gi,
      /xmrig/gi,
      /mining/gi,
      /miner/gi,
      /hash/gi,
    ];
    
    // Statistics
    this.statistics = {
      totalAttempts: 0,
      knownMinersBlocked: 0,
      wasmMinersDetected: 0,
      cpuAbuseDetected: 0,
      blockedScripts: 0,
    };
    
    // Threat callback
    this.threatCallback = null;
    
    // Settings
    this.settings = {
      monitorCryptojacking: true,
      blockKnownMiners: true,
      blockWasmMiners: true,
      monitorCPUUsage: true,
      cpuThreshold: 80, // Block if CPU > 80%
    };
    
    // CPU usage tracking
    this.cpuUsage = new Map(); // tabId -> usage%
  }
  
  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }
  
  /**
   * Monitor script for mining
   */
  monitorScript(script) {
    if (!this.settings.monitorCryptojacking) return { allowed: true };
    
    this.statistics.totalAttempts++;
    
    const { url, scriptUrl, content, tabId, isWasm } = script;
    const domain = this.extractDomain(url);
    
    // Analyze script
    const analysis = this.analyzeScript({
      url,
      domain,
      scriptUrl,
      content,
      tabId,
      isWasm,
    });
    
    // Record attempt
    this.recordAttempt({
      url,
      domain,
      scriptUrl,
      tabId,
      isWasm,
      timestamp: Date.now(),
      analysis,
    });
    
    // Check for threats
    if (analysis.threats.length > 0) {
      console.warn('[CryptojackingMonitor] Threats detected:', analysis.threats);
      
      if (this.threatCallback) {
        analysis.threats.forEach(threat => this.threatCallback(threat));
      }
      
      if (analysis.severity === 'CRITICAL' && this.settings.blockKnownMiners) {
        this.statistics.blockedScripts++;
        return {
          allowed: false,
          reason: 'Cryptojacking script blocked',
          threats: analysis.threats,
        };
      }
    }
    
    return { allowed: true };
  }
  
  /**
   * Monitor CPU usage
   */
  monitorCPUUsage(usage) {
    if (!this.settings.monitorCPUUsage) return { allowed: true };
    
    const { tabId, cpuPercent, url } = usage;
    const domain = this.extractDomain(url);
    
    // Track CPU usage
    this.cpuUsage.set(tabId, cpuPercent);
    
    // Check if CPU usage is suspicious
    if (cpuPercent > this.settings.cpuThreshold) {
      this.statistics.cpuAbuseDetected++;
      
      if (this.threatCallback) {
        this.threatCallback({
          type: 'HIGH_CPU_USAGE',
          severity: 'HIGH',
          score: 75,
          description: `High CPU usage detected (${cpuPercent}%) - possible cryptojacking`,
          context: { tabId, cpuPercent, domain },
        });
      }
      
      return {
        allowed: false,
        reason: 'High CPU usage detected',
      };
    }
    
    return { allowed: true };
  }
  
  /**
   * Analyze script for mining
   */
  analyzeScript(script) {
    const threats = [];
    let maxSeverity = 'LOW';
    
    const { domain, scriptUrl, content, isWasm } = script;
    
    // Check for known mining domains
    for (const miningDomain of this.miningDomains) {
      if (scriptUrl && scriptUrl.includes(miningDomain)) {
        threats.push({
          type: 'KNOWN_MINING_DOMAIN',
          severity: 'CRITICAL',
          score: 95,
          description: `Known mining domain detected: ${miningDomain}`,
          context: { scriptUrl, domain },
        });
        
        this.statistics.knownMinersBlocked++;
        maxSeverity = 'CRITICAL';
        break;
      }
    }
    
    // Check for known miner names in script URL
    if (scriptUrl) {
      for (const miner of this.knownMiners) {
        if (scriptUrl.toLowerCase().includes(miner)) {
          threats.push({
            type: 'KNOWN_MINER_SCRIPT',
            severity: 'CRITICAL',
            score: 95,
            description: `Known mining script detected: ${miner}`,
            context: { miner, scriptUrl, domain },
          });
          
          this.statistics.knownMinersBlocked++;
          maxSeverity = 'CRITICAL';
          break;
        }
      }
    }
    
    // Check WebAssembly for mining patterns
    if (isWasm && this.settings.blockWasmMiners && content) {
      for (const pattern of this.wasmPatterns) {
        if (pattern.test(content)) {
          threats.push({
            type: 'WASM_MINING_DETECTED',
            severity: 'HIGH',
            score: 85,
            description: `WebAssembly mining script detected`,
            context: { pattern: pattern.source, scriptUrl, domain },
          });
          
          this.statistics.wasmMinersDetected++;
          
          if (maxSeverity !== 'CRITICAL') {
            maxSeverity = 'HIGH';
          }
          break;
        }
      }
    }
    
    // Check for mining-related keywords in content
    if (content) {
      const miningKeywords = [
        /CoinHive/gi,
        /cryptonight/gi,
        /stratum\+tcp/gi,
        /xmr-stak/gi,
        /monero/gi,
      ];
      
      for (const keyword of miningKeywords) {
        if (keyword.test(content)) {
          threats.push({
            type: 'MINING_KEYWORD_DETECTED',
            severity: 'HIGH',
            score: 80,
            description: `Mining-related keyword detected in script`,
            context: { keyword: keyword.source, scriptUrl, domain },
          });
          
          if (maxSeverity !== 'CRITICAL') {
            maxSeverity = 'HIGH';
          }
          break;
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
   * Record mining attempt
   */
  recordAttempt(entry) {
    this.miningAttempts.push(entry);
    
    // Track suspicious scripts
    if (entry.scriptUrl && entry.analysis.hasSuspiciousActivity) {
      this.suspiciousScripts.set(entry.scriptUrl, {
        url: entry.scriptUrl,
        domain: entry.domain,
        severity: entry.analysis.severity,
        timestamp: entry.timestamp,
      });
    }
    
    // Limit attempt history
    if (this.miningAttempts.length > 1000) {
      this.miningAttempts.shift();
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
   * Get mining attempts
   */
  getMiningAttempts() {
    return this.miningAttempts;
  }
  
  /**
   * Get suspicious scripts
   */
  getSuspiciousScripts() {
    return Array.from(this.suspiciousScripts.values());
  }
  
  /**
   * Get CPU usage
   */
  getCPUUsage() {
    return Array.from(this.cpuUsage.entries()).map(([tabId, usage]) => ({
      tabId,
      usage,
    }));
  }
  
  /**
   * Add mining domain
   */
  addMiningDomain(domain) {
    if (!this.miningDomains.includes(domain)) {
      this.miningDomains.push(domain);
    }
  }
  
  /**
   * Update settings
   */
  updateSettings(newSettings) {
    this.settings = { ...this.settings, ...newSettings };
  }
}

