/**
 * Armorly - Credential Harvesting Monitor
 * 
 * Monitors credential harvesting attempts, detects fake login forms,
 * prevents password theft, and provides credential protection across
 * all chromium-based agentic browsers.
 * 
 * Features:
 * - Real-time form monitoring
 * - Fake login form detection
 * - Password field tracking
 * - Credential exfiltration prevention
 * - Suspicious form submission detection
 */

export class CredentialHarvestingMonitor {
  constructor() {
    // Form tracking
    this.forms = new Map(); // formId -> form data
    this.submissions = [];
    this.suspiciousSubmissions = [];
    
    // Known legitimate domains (common login providers)
    this.legitimateDomains = [
      'google.com',
      'accounts.google.com',
      'login.microsoftonline.com',
      'github.com',
      'facebook.com',
      'twitter.com',
      'linkedin.com',
      'apple.com',
      'amazon.com',
    ];
    
    // Suspicious form indicators
    this.suspiciousIndicators = {
      // Suspicious action URLs
      suspiciousActions: [
        /data:/gi,
        /javascript:/gi,
        /about:blank/gi,
        /localhost/gi,
        /127\.0\.0\.1/gi,
        /0\.0\.0\.0/gi,
      ],
      
      // Suspicious form attributes
      suspiciousAttributes: [
        'hidden',
        'display:none',
        'visibility:hidden',
        'opacity:0',
      ],
      
      // Credential field names
      credentialFields: [
        /password/gi,
        /passwd/gi,
        /pwd/gi,
        /pass/gi,
        /credential/gi,
        /secret/gi,
        /pin/gi,
        /security[_-]?code/gi,
      ],
    };
    
    // Statistics
    this.statistics = {
      totalForms: 0,
      passwordForms: 0,
      submissions: 0,
      suspiciousSubmissions: 0,
      harvestingAttempts: 0,
      blockedSubmissions: 0,
    };
    
    // Threat callback
    this.threatCallback = null;
    
    // Settings
    this.settings = {
      monitorForms: true,
      detectFakeLoginForms: true,
      blockSuspiciousSubmissions: true,
      requireHTTPS: true,
    };
  }
  
  /**
   * Set threat callback
   */
  setThreatCallback(callback) {
    this.threatCallback = callback;
  }
  
  /**
   * Monitor form
   */
  monitorForm(form) {
    if (!this.settings.monitorForms) return { allowed: true };
    
    this.statistics.totalForms++;
    
    const { formId, action, method, fields, url, tabId, isHidden } = form;
    
    // Check if form has password fields
    const hasPasswordField = fields.some(field => 
      this.suspiciousIndicators.credentialFields.some(pattern => pattern.test(field.name))
    );
    
    if (hasPasswordField) {
      this.statistics.passwordForms++;
    }
    
    // Analyze form
    const analysis = this.analyzeForm({
      formId,
      action,
      method,
      fields,
      url,
      tabId,
      isHidden,
      hasPasswordField,
    });
    
    // Record form
    this.forms.set(formId, {
      formId,
      action,
      method,
      fields,
      url,
      tabId,
      isHidden,
      hasPasswordField,
      timestamp: Date.now(),
      analysis,
    });
    
    // Check for threats
    if (analysis.threats.length > 0) {
      console.warn('[CredentialHarvestingMonitor] Threats detected:', analysis.threats);
      
      if (this.threatCallback) {
        analysis.threats.forEach(threat => this.threatCallback(threat));
      }
    }
    
    return { allowed: true };
  }
  
  /**
   * Monitor form submission
   */
  monitorSubmission(submission) {
    if (!this.settings.monitorForms) return { allowed: true };
    
    this.statistics.submissions++;
    
    const { formId, action, data, url, tabId } = submission;
    
    // Get form data
    const form = this.forms.get(formId);
    
    // Analyze submission
    const analysis = this.analyzeSubmission({
      formId,
      action,
      data,
      url,
      tabId,
      form,
    });
    
    // Record submission
    this.recordSubmission({
      formId,
      action,
      url,
      tabId,
      timestamp: Date.now(),
      analysis,
    });
    
    // Check for threats
    if (analysis.threats.length > 0) {
      console.warn('[CredentialHarvestingMonitor] Submission threats detected:', analysis.threats);
      
      if (this.threatCallback) {
        analysis.threats.forEach(threat => this.threatCallback(threat));
      }
      
      if (analysis.severity === 'CRITICAL' && this.settings.blockSuspiciousSubmissions) {
        this.statistics.blockedSubmissions++;
        return {
          allowed: false,
          reason: 'Suspicious form submission blocked',
          threats: analysis.threats,
        };
      }
    }
    
    return { allowed: true };
  }
  
  /**
   * Analyze form
   */
  analyzeForm(form) {
    const threats = [];
    let maxSeverity = 'LOW';
    
    const { action, url, isHidden, hasPasswordField } = form;
    
    // Check for fake login forms
    if (this.settings.detectFakeLoginForms && hasPasswordField) {
      // Check for suspicious action URL
      for (const pattern of this.suspiciousIndicators.suspiciousActions) {
        if (pattern.test(action)) {
          threats.push({
            type: 'FAKE_LOGIN_FORM',
            severity: 'CRITICAL',
            score: 95,
            description: `Fake login form detected with suspicious action: ${action}`,
            context: { action, url },
          });
          
          this.statistics.harvestingAttempts++;
          maxSeverity = 'CRITICAL';
          break;
        }
      }
      
      // Check for hidden password form
      if (isHidden) {
        threats.push({
          type: 'HIDDEN_PASSWORD_FORM',
          severity: 'HIGH',
          score: 80,
          description: `Hidden password form detected - possible credential harvesting`,
          context: { action, url },
        });
        
        this.statistics.harvestingAttempts++;
        
        if (maxSeverity !== 'CRITICAL') {
          maxSeverity = 'HIGH';
        }
      }
      
      // Check for non-HTTPS submission
      if (this.settings.requireHTTPS && !action.startsWith('https://')) {
        threats.push({
          type: 'INSECURE_PASSWORD_FORM',
          severity: 'HIGH',
          score: 75,
          description: `Password form submitting over insecure connection`,
          context: { action, url },
        });
        
        if (maxSeverity !== 'CRITICAL') {
          maxSeverity = 'HIGH';
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
   * Analyze submission
   */
  analyzeSubmission(submission) {
    const threats = [];
    let maxSeverity = 'LOW';
    
    const { action, url, form } = submission;
    
    if (!form) {
      return { threats, severity: maxSeverity, hasSuspiciousActivity: false };
    }
    
    // Check if form was flagged as suspicious
    if (form.analysis.hasSuspiciousActivity) {
      threats.push({
        type: 'SUSPICIOUS_FORM_SUBMISSION',
        severity: form.analysis.severity,
        score: 85,
        description: `Submission to suspicious form detected`,
        context: { action, url },
      });
      
      this.statistics.suspiciousSubmissions++;
      maxSeverity = form.analysis.severity;
    }
    
    // Check if submitting to different domain
    const formDomain = this.extractDomain(url);
    const actionDomain = this.extractDomain(action);
    
    if (formDomain !== actionDomain && !this.isLegitimateRedirect(formDomain, actionDomain)) {
      threats.push({
        type: 'CROSS_DOMAIN_CREDENTIAL_SUBMISSION',
        severity: 'HIGH',
        score: 70,
        description: `Cross-domain credential submission: ${formDomain} -> ${actionDomain}`,
        context: { formDomain, actionDomain },
      });
      
      this.statistics.harvestingAttempts++;
      
      if (maxSeverity !== 'CRITICAL') {
        maxSeverity = 'HIGH';
      }
    }
    
    return {
      threats,
      severity: maxSeverity,
      hasSuspiciousActivity: threats.length > 0,
    };
  }
  
  /**
   * Check if domain redirect is legitimate
   */
  isLegitimateRedirect(fromDomain, toDomain) {
    // Check if both domains are in legitimate list
    return this.legitimateDomains.some(domain => 
      (fromDomain.includes(domain) || fromDomain.endsWith(domain)) &&
      (toDomain.includes(domain) || toDomain.endsWith(domain))
    );
  }
  
  /**
   * Record submission
   */
  recordSubmission(entry) {
    this.submissions.push(entry);
    
    if (entry.analysis.hasSuspiciousActivity) {
      this.suspiciousSubmissions.push(entry);
      
      // Limit history size
      if (this.suspiciousSubmissions.length > 100) {
        this.suspiciousSubmissions.shift();
      }
    }
    
    // Limit submission history
    if (this.submissions.length > 1000) {
      this.submissions.shift();
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
   * Get suspicious submissions
   */
  getSuspiciousSubmissions() {
    return this.suspiciousSubmissions;
  }
  
  /**
   * Update settings
   */
  updateSettings(newSettings) {
    this.settings = { ...this.settings, ...newSettings };
  }
}

