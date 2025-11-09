/**
 * Accessibility Tree Sanitizer
 * 
 * Analyzes accessibility trees returned by browserOS.getAccessibilityTree()
 * to detect hidden prompt injection attacks.
 * 
 * Attack Vector:
 * - Malicious websites embed invisible text with prompt injections
 * - AI agent reads accessibility tree (includes ALL elements, even hidden)
 * - Agent follows malicious instructions thinking they're legitimate
 * 
 * This module filters suspicious hidden content before it reaches the AI agent.
 */

export class AccessibilitySanitizer {
  constructor() {
    this.enabled = true;
    this.threatsDetected = [];
    this.onThreatDetected = null;
    
    // Prompt injection patterns
    this.promptInjectionPatterns = [
      /ignore\s+(previous|all|prior)\s+(instructions|commands|prompts)/i,
      /disregard\s+(previous|all|prior)\s+(instructions|commands|prompts)/i,
      /forget\s+(previous|all|prior)\s+(instructions|commands|prompts)/i,
      /system\s*:\s*/i,
      /assistant\s*:\s*/i,
      /you\s+are\s+now\s+(a|an|the)/i,
      /new\s+(instructions|commands|prompt)/i,
      /override\s+(instructions|commands|settings)/i,
      /admin\s+mode/i,
      /developer\s+mode/i,
      /debug\s+mode/i,
      /sudo\s+/i,
      /execute\s+as\s+root/i,
      /with\s+elevated\s+privileges/i,
      /bypass\s+(security|safety|restrictions)/i,
      /disable\s+(security|safety|restrictions)/i,
      /ignore\s+safety/i,
      /unrestricted\s+mode/i,
      /jailbreak/i,
      /prompt\s+injection/i,
      /\[SYSTEM\]/i,
      /\[ADMIN\]/i,
      /\[ROOT\]/i,
      /<\|im_start\|>/i, // ChatGPT special tokens
      /<\|im_end\|>/i,
      /\[INST\]/i, // Llama special tokens
      /\[\/INST\]/i
    ];
    
    // Suspicious attribute patterns
    this.suspiciousAttributes = [
      'data-prompt',
      'data-instruction',
      'data-command',
      'data-system',
      'data-override',
      'aria-hidden-instruction',
      'hidden-prompt'
    ];
    
    console.log('[Armorly Accessibility] Sanitizer initialized');
  }
  
  /**
   * Set callback for threat detection
   */
  setThreatCallback(callback) {
    this.onThreatDetected = callback;
  }
  
  /**
   * Sanitize accessibility tree
   * Returns sanitized tree with suspicious nodes filtered/flagged
   */
  sanitizeTree(tree) {
    if (!this.enabled || !tree || !tree.nodes) {
      return tree;
    }
    
    const threats = [];
    const sanitizedNodes = [];
    
    for (const node of tree.nodes) {
      const threat = this.analyzeNode(node);
      
      if (threat) {
        threats.push(threat);
        // Option 1: Remove node entirely
        // continue;
        
        // Option 2: Flag node but keep it (for now, we'll flag)
        node._armorly_flagged = true;
        node._armorly_reason = threat.reason;
      }
      
      sanitizedNodes.push(node);
    }
    
    // Report threats
    if (threats.length > 0) {
      this.reportThreats(threats);
    }
    
    return {
      ...tree,
      nodes: sanitizedNodes,
      _armorly_sanitized: true,
      _armorly_threats_found: threats.length
    };
  }
  
  /**
   * Analyze a single node for threats
   */
  analyzeNode(node) {
    if (!node) return null;
    
    // Check if node is hidden/invisible
    const isHidden = this.isNodeHidden(node);
    
    // Check node text content
    if (node.name || node.value || node.description) {
      const text = `${node.name || ''} ${node.value || ''} ${node.description || ''}`;
      
      // Check for prompt injection patterns
      for (const pattern of this.promptInjectionPatterns) {
        if (pattern.test(text)) {
          return {
            type: 'PROMPT_INJECTION_IN_ACCESSIBILITY_TREE',
            nodeId: node.nodeId,
            role: node.role,
            text: text.substring(0, 200), // Truncate for logging
            pattern: pattern.source,
            hidden: isHidden,
            severity: isHidden ? 'critical' : 'high',
            reason: `Prompt injection pattern detected in ${isHidden ? 'hidden' : 'visible'} node`
          };
        }
      }
      
      // Check for suspicious attributes
      if (node.htmlAttributes) {
        for (const attr of this.suspiciousAttributes) {
          if (node.htmlAttributes[attr]) {
            return {
              type: 'SUSPICIOUS_ATTRIBUTE_IN_ACCESSIBILITY_TREE',
              nodeId: node.nodeId,
              role: node.role,
              attribute: attr,
              value: node.htmlAttributes[attr],
              hidden: isHidden,
              severity: 'high',
              reason: `Suspicious attribute "${attr}" found in node`
            };
          }
        }
      }
      
      // Check for invisible text with suspicious length
      if (isHidden && text.length > 100) {
        // Long hidden text is suspicious
        return {
          type: 'LONG_HIDDEN_TEXT_IN_ACCESSIBILITY_TREE',
          nodeId: node.nodeId,
          role: node.role,
          textLength: text.length,
          textPreview: text.substring(0, 100),
          severity: 'medium',
          reason: 'Long hidden text detected (possible prompt injection)'
        };
      }
    }
    
    return null;
  }
  
  /**
   * Check if node is hidden/invisible
   */
  isNodeHidden(node) {
    if (!node) return false;
    
    // Check role
    if (node.role === 'none' || node.role === 'presentation') {
      return true;
    }
    
    // Check states
    if (node.states) {
      if (node.states.includes('invisible') || 
          node.states.includes('offscreen') ||
          node.states.includes('hidden')) {
        return true;
      }
    }
    
    // Check HTML attributes
    if (node.htmlAttributes) {
      // aria-hidden="true"
      if (node.htmlAttributes['aria-hidden'] === 'true') {
        return true;
      }
      
      // hidden attribute
      if (Object.prototype.hasOwnProperty.call(node.htmlAttributes, 'hidden')) {
        return true;
      }
      
      // style with display:none or visibility:hidden
      const style = node.htmlAttributes.style || '';
      if (style.includes('display:none') || 
          style.includes('display: none') ||
          style.includes('visibility:hidden') ||
          style.includes('visibility: hidden') ||
          style.includes('opacity:0') ||
          style.includes('opacity: 0')) {
        return true;
      }
    }
    
    // Check bounds (off-screen positioning)
    if (node.location) {
      const { x, y, width, height } = node.location;
      
      // Negative coordinates (off-screen left/top)
      if (x < -1000 || y < -1000) {
        return true;
      }
      
      // Zero size
      if (width === 0 || height === 0) {
        return true;
      }
      
      // Very far off-screen
      if (x > 10000 || y > 10000) {
        return true;
      }
    }
    
    return false;
  }
  
  /**
   * Report detected threats
   */
  reportThreats(threats) {
    this.threatsDetected.push(...threats);
    
    // Trim if too many
    if (this.threatsDetected.length > 1000) {
      this.threatsDetected = this.threatsDetected.slice(-1000);
    }
    
    // Call callback
    if (this.onThreatDetected) {
      for (const threat of threats) {
        this.onThreatDetected({
          ...threat,
          timestamp: Date.now(),
          source: 'accessibility_tree'
        });
      }
    }
    
    console.warn(`[Armorly Accessibility] Detected ${threats.length} threats in accessibility tree`);
  }
  
  /**
   * Get statistics
   */
  getStatistics() {
    const stats = {
      totalThreats: this.threatsDetected.length,
      byType: {},
      bySeverity: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      },
      recentThreats: []
    };
    
    for (const threat of this.threatsDetected) {
      // Count by type
      stats.byType[threat.type] = (stats.byType[threat.type] || 0) + 1;
      
      // Count by severity
      stats.bySeverity[threat.severity]++;
    }
    
    // Get recent threats
    stats.recentThreats = this.threatsDetected.slice(-10).reverse();
    
    return stats;
  }
  
  /**
   * Clear threat history
   */
  clearThreats() {
    this.threatsDetected = [];
  }
  
  /**
   * Enable/disable sanitizer
   */
  setEnabled(enabled) {
    this.enabled = enabled;
    console.log(`[Armorly Accessibility] Sanitizer ${enabled ? 'enabled' : 'disabled'}`);
  }
}

