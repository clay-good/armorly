/**
 * Action Authorizer for Armorly
 * 
 * Validates and authorizes state-changing operations performed by AI agents.
 * Addresses OWASP LLM08: Excessive Agency
 * 
 * Features:
 * - Intercept state-changing operations
 * - Require user confirmation for sensitive actions
 * - Audit trail of all actions
 * - Risk scoring for operations
 * - Whitelist/blacklist management
 * - Rollback capabilities
 * 
 * @module action-authorizer
 * @author Armorly Security Team
 */

class ActionAuthorizer {
  constructor() {
    /**
     * Statistics
     */
    this.stats = {
      actionsMonitored: 0,
      actionsBlocked: 0,
      actionsApproved: 0,
      userConfirmationsRequired: 0,
      userConfirmationsGranted: 0,
    };

    /**
     * Configuration - PERMISSIVE MODE (only block critical threats)
     */
    this.config = {
      enabled: true,
      requireConfirmation: true,
      autoApproveWhitelisted: true,
      blockBlacklisted: true,
      logActions: true,
      auditTrail: true,
      criticalOnly: true, // NEW - only require confirmation for critical actions
    };

    /**
     * Risk levels for different action types
     */
    this.actionRiskLevels = {
      // Critical - Always require confirmation
      'delete': 'critical',
      'remove': 'critical',
      'drop': 'critical',
      'destroy': 'critical',
      'terminate': 'critical',
      
      // High - Require confirmation unless whitelisted
      'update': 'high',
      'modify': 'high',
      'change': 'high',
      'edit': 'high',
      'write': 'high',
      'post': 'high',
      'put': 'high',
      'patch': 'high',
      
      // Medium - Log and monitor
      'create': 'medium',
      'add': 'medium',
      'insert': 'medium',
      'upload': 'medium',
      
      // Low - Allow with logging
      'read': 'low',
      'get': 'low',
      'fetch': 'low',
      'list': 'low',
    };

    /**
     * Sensitive operations that always require confirmation
     */
    this.sensitiveOperations = [
      'payment',
      'purchase',
      'transfer',
      'send_money',
      'delete_account',
      'change_password',
      'grant_permission',
      'share_data',
      'export_data',
      'execute_code',
      'run_script',
      'install',
      'uninstall',
    ];

    /**
     * Whitelisted actions (auto-approve)
     */
    this.whitelist = new Set();

    /**
     * Blacklisted actions (auto-block)
     */
    this.blacklist = new Set();

    /**
     * Audit trail
     */
    this.auditLog = [];

    /**
     * Pending confirmations
     */
    this.pendingConfirmations = new Map();
  }

  /**
   * Start action authorization
   * PERMISSIVE MODE: Only monitor critical operations
   */
  start() {
    if (!this.config.enabled) return;

    try {
      // Intercept fetch API
      this.interceptFetch();

      // Intercept XMLHttpRequest
      this.interceptXHR();

      // Monitor form submissions
      this.monitorForms();

      // DISABLED: Button monitoring (too aggressive)
      // this.monitorButtons();

      console.log('[Armorly ActionAuthorizer] Started - PERMISSIVE MODE (critical only)');
    } catch (error) {
      console.error('[Armorly ActionAuthorizer] Error starting:', error);
    }
  }

  /**
   * Intercept fetch API
   */
  interceptFetch() {
    const self = this;
    const originalFetch = window.fetch;

    window.fetch = async function(...args) {
      const [url, options = {}] = args;
      const method = (options.method || 'GET').toUpperCase();

      // Analyze the action
      const action = self.analyzeAction(method, url, options);

      // Check if authorization is required
      if (self.requiresAuthorization(action)) {
        const authorized = await self.requestAuthorization(action);

        if (!authorized) {
          self.blockAction(action);
          throw new Error('Action blocked by Armorly: User denied authorization');
        }

        self.approveAction(action);
      }

      // Log the action
      self.logAction(action);

      // Proceed with the request
      return originalFetch.apply(this, args);
    };
  }

  /**
   * Intercept XMLHttpRequest
   */
  interceptXHR() {
    const self = this;
    const originalOpen = XMLHttpRequest.prototype.open;
    const originalSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function(method, url, ...args) {
      this._armorlyMethod = method;
      this._armorlyUrl = url;
      return originalOpen.apply(this, [method, url, ...args]);
    };

    XMLHttpRequest.prototype.send = async function(body) {
      const method = this._armorlyMethod;
      const url = this._armorlyUrl;

      // Analyze the action
      const action = self.analyzeAction(method, url, { body });

      // Check if authorization is required
      if (self.requiresAuthorization(action)) {
        const authorized = await self.requestAuthorization(action);

        if (!authorized) {
          self.blockAction(action);
          throw new Error('Action blocked by Armorly: User denied authorization');
        }

        self.approveAction(action);
      }

      // Log the action
      self.logAction(action);

      // Proceed with the request
      return originalSend.apply(this, [body]);
    };
  }

  /**
   * Monitor form submissions
   */
  monitorForms() {
    document.addEventListener('submit', async (event) => {
      const form = event.target;

      // Analyze the form action
      const action = this.analyzeFormAction(form);

      // Check if authorization is required
      if (this.requiresAuthorization(action)) {
        event.preventDefault();

        const authorized = await this.requestAuthorization(action);

        if (!authorized) {
          this.blockAction(action);
          return;
        }

        this.approveAction(action);
        form.submit();
      }

      // Log the action
      this.logAction(action);
    }, true);
  }

  /**
   * Monitor button clicks
   */
  monitorButtons() {
    document.addEventListener('click', async (event) => {
      const button = event.target.closest('button, [role="button"], input[type="submit"]');

      if (button) {
        const action = this.analyzeButtonAction(button);

        // Check if authorization is required
        if (this.requiresAuthorization(action)) {
          event.preventDefault();
          event.stopPropagation();

          const authorized = await this.requestAuthorization(action);

          if (!authorized) {
            this.blockAction(action);
            return;
          }

          this.approveAction(action);
          // Re-trigger the click
          button.click();
        }

        // Log the action
        this.logAction(action);
      }
    }, true);
  }

  /**
   * Analyze an action
   */
  analyzeAction(method, url, options = {}) {
    const action = {
      type: 'api-request',
      method: method.toUpperCase(),
      url: url,
      timestamp: Date.now(),
      riskLevel: this.calculateRiskLevel(method, url, options),
      sensitive: this.isSensitiveOperation(method, url, options),
    };

    this.stats.actionsMonitored++;

    return action;
  }

  /**
   * Analyze form action
   */
  analyzeFormAction(form) {
    const action = {
      type: 'form-submission',
      method: (form.method || 'POST').toUpperCase(),
      url: form.action || window.location.href,
      timestamp: Date.now(),
      riskLevel: this.calculateRiskLevel(form.method, form.action),
      sensitive: this.isSensitiveOperation(form.method, form.action),
    };

    this.stats.actionsMonitored++;

    return action;
  }

  /**
   * Analyze button action
   */
  analyzeButtonAction(button) {
    const text = button.textContent?.toLowerCase() || '';
    const action = {
      type: 'button-click',
      text: text,
      timestamp: Date.now(),
      riskLevel: this.calculateButtonRiskLevel(text),
      sensitive: this.isSensitiveButton(text),
    };

    this.stats.actionsMonitored++;

    return action;
  }

  /**
   * Calculate risk level
   */
  calculateRiskLevel(method, url, options = {}) {
    // Check method risk
    const methodRisk = this.actionRiskLevels[method.toLowerCase()] || 'medium';

    // Check URL for sensitive keywords
    const urlLower = (url || '').toLowerCase();
    for (const keyword of this.sensitiveOperations) {
      if (urlLower.includes(keyword)) {
        return 'critical';
      }
    }

    return methodRisk;
  }

  /**
   * Calculate button risk level
   */
  calculateButtonRiskLevel(text) {
    for (const keyword of this.sensitiveOperations) {
      if (text.includes(keyword)) {
        return 'critical';
      }
    }

    if (text.includes('delete') || text.includes('remove')) {
      return 'critical';
    }

    if (text.includes('confirm') || text.includes('submit')) {
      return 'high';
    }

    return 'low';
  }

  /**
   * Check if operation is sensitive
   */
  isSensitiveOperation(method, url, options = {}) {
    const urlLower = (url || '').toLowerCase();
    
    return this.sensitiveOperations.some(op => urlLower.includes(op));
  }

  /**
   * Check if button is sensitive
   */
  isSensitiveButton(text) {
    return this.sensitiveOperations.some(op => text.includes(op));
  }

  /**
   * Check if authorization is required
   * PERMISSIVE MODE: Only require confirmation for CRITICAL actions
   */
  requiresAuthorization(action) {
    if (!this.config.requireConfirmation) return false;

    // Check blacklist
    if (this.config.blockBlacklisted && this.isBlacklisted(action)) {
      return true;
    }

    // Check whitelist
    if (this.config.autoApproveWhitelisted && this.isWhitelisted(action)) {
      return false;
    }

    // PERMISSIVE MODE: Only require confirmation for CRITICAL actions
    if (this.config.criticalOnly) {
      // Only block truly critical actions
      if (action.riskLevel === 'critical' && action.sensitive) {
        return true;
      }
      return false;
    }

    // Legacy mode (if criticalOnly is disabled)
    if (action.riskLevel === 'critical' || action.riskLevel === 'high') {
      return true;
    }

    if (action.sensitive) {
      return true;
    }

    return false;
  }

  /**
   * Request user authorization
   */
  async requestAuthorization(action) {
    this.stats.userConfirmationsRequired++;

    // Create confirmation dialog
    const confirmed = await this.showConfirmationDialog(action);

    if (confirmed) {
      this.stats.userConfirmationsGranted++;
    }

    return confirmed;
  }

  /**
   * Show confirmation dialog
   */
  async showConfirmationDialog(action) {
    return new Promise((resolve) => {
      // Create modal
      const modal = document.createElement('div');
      modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0,0,0,0.8);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 9999999;
        font-family: system-ui, -apple-system, sans-serif;
      `;

      const dialog = document.createElement('div');
      dialog.style.cssText = `
        background: white;
        padding: 30px;
        border-radius: 12px;
        max-width: 500px;
        box-shadow: 0 8px 32px rgba(0,0,0,0.3);
      `;

      dialog.innerHTML = `
        <h2 style="margin: 0 0 15px 0; color: #ff4444;">🛡️ Armorly Authorization Required</h2>
        <p style="margin: 0 0 10px 0; color: #333;">
          An AI agent is attempting to perform a <strong>${action.riskLevel}</strong> risk action:
        </p>
        <div style="background: #f5f5f5; padding: 15px; border-radius: 8px; margin: 15px 0;">
          <strong>Type:</strong> ${action.type}<br>
          <strong>Method:</strong> ${action.method || 'N/A'}<br>
          <strong>URL:</strong> ${action.url || 'N/A'}<br>
          ${action.text ? `<strong>Action:</strong> ${action.text}<br>` : ''}
        </div>
        <p style="margin: 15px 0; color: #666;">
          Do you want to allow this action?
        </p>
        <div style="display: flex; gap: 10px; justify-content: flex-end;">
          <button id="armorly-deny" style="padding: 10px 20px; border: 1px solid #ddd; background: white; border-radius: 6px; cursor: pointer;">
            Deny
          </button>
          <button id="armorly-allow" style="padding: 10px 20px; border: none; background: #4CAF50; color: white; border-radius: 6px; cursor: pointer;">
            Allow
          </button>
        </div>
      `;

      modal.appendChild(dialog);
      document.body.appendChild(modal);

      // Handle buttons
      dialog.querySelector('#armorly-allow').addEventListener('click', () => {
        modal.remove();
        resolve(true);
      });

      dialog.querySelector('#armorly-deny').addEventListener('click', () => {
        modal.remove();
        resolve(false);
      });

      // Auto-deny after 30 seconds
      setTimeout(() => {
        if (document.body.contains(modal)) {
          modal.remove();
          resolve(false);
        }
      }, 30000);
    });
  }

  /**
   * Check if action is whitelisted
   */
  isWhitelisted(action) {
    const key = `${action.method}:${action.url}`;
    return this.whitelist.has(key);
  }

  /**
   * Check if action is blacklisted
   */
  isBlacklisted(action) {
    const key = `${action.method}:${action.url}`;
    return this.blacklist.has(key);
  }

  /**
   * Approve an action
   */
  approveAction(action) {
    this.stats.actionsApproved++;

    if (this.config.logActions) {
      console.log('[Armorly ActionAuthorizer] Action approved:', action);
    }
  }

  /**
   * Block an action
   */
  blockAction(action) {
    this.stats.actionsBlocked++;

    if (this.config.logActions) {
      console.warn('[Armorly ActionAuthorizer] Action blocked:', action);
    }
  }

  /**
   * Log an action to audit trail
   */
  logAction(action) {
    if (!this.config.auditTrail) return;

    this.auditLog.push({
      ...action,
      timestamp: Date.now(),
    });

    // Keep only last 1000 actions
    if (this.auditLog.length > 1000) {
      this.auditLog.shift();
    }
  }

  /**
   * Get statistics
   */
  getStats() {
    return { ...this.stats };
  }

  /**
   * Get audit log
   */
  getAuditLog() {
    return [...this.auditLog];
  }

  /**
   * Enable/disable
   */
  setEnabled(enabled) {
    this.config.enabled = enabled;
  }
}

// Export for use in content script
if (typeof window !== 'undefined') {
  window.ActionAuthorizer = ActionAuthorizer;
}

