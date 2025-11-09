/**
 * Universal Prompt Injection Patterns
 * 
 * Shared pattern library for detecting prompt injection attacks across all agentic browsers.
 * Works in both content scripts and background service workers.
 * 
 * Based on research:
 * - Brave Security: Perplexity Comet vulnerability (Aug 2025)
 * - OpenAI: ChatGPT Atlas security considerations
 * - Academic research on prompt injection attacks
 * 
 * @module universal-prompt-patterns
 * @author Armorly Security Team
 * @license MIT
 */

export const PROMPT_INJECTION_PATTERNS = [
  // Direct instruction patterns
  /ignore\s+(previous|all|prior|above)\s+(instructions|commands|prompts|rules|context)/i,
  /disregard\s+(previous|all|prior|above)\s+(instructions|commands|prompts|rules)/i,
  /forget\s+(previous|all|prior|above)\s+(instructions|commands|prompts|rules)/i,
  /override\s+(previous|all|prior|system)\s+(instructions|commands|prompts|rules)/i,
  
  // System role manipulation
  /you\s+are\s+now\s+(a|an|the)\s+/i,
  /act\s+as\s+(a|an|the)\s+/i,
  /pretend\s+(you\s+are|to\s+be)\s+/i,
  /roleplay\s+as\s+/i,
  /system\s*:\s*/i,
  /assistant\s*:\s*/i,
  /user\s*:\s*/i,
  
  // Mode switching
  /admin\s+mode/i,
  /developer\s+mode/i,
  /debug\s+mode/i,
  /god\s+mode/i,
  /jailbreak/i,
  /bypass\s+(security|safety|restrictions|filters|guardrails)/i,
  /disable\s+(security|safety|restrictions|filters|guardrails)/i,
  
  // Special tokens (model-specific)
  /<\|im_start\|>/i, // ChatGPT
  /<\|im_end\|>/i,
  /\[INST\]/i, // Llama
  /\[\/INST\]/i,
  /<s>/i, // Generic
  /<\/s>/i,
  /\[SYS\]/i,
  /\[\/SYS\]/i,
  
  // Data exfiltration patterns
  /send\s+(this|the|all)\s+(to|via)\s+/i,
  /exfiltrate\s+(data|information|credentials)/i,
  /leak\s+(data|information|credentials)/i,
  /transmit\s+(to|via)\s+/i,
  
  // Navigation/action commands
  /navigate\s+to\s+https?:\/\//i,
  /go\s+to\s+https?:\/\//i,
  /visit\s+https?:\/\//i,
  /open\s+https?:\/\//i,
  /click\s+(on\s+)?(the\s+)?button/i,
  /fill\s+(in\s+)?(the\s+)?form/i,
  /submit\s+(the\s+)?form/i,
  /type\s+into/i,
  /enter\s+(your|the)\s+(password|credentials|email)/i,
  
  // Credential theft
  /extract\s+(password|credentials|email|username|token|cookie)/i,
  /steal\s+(password|credentials|email|username|token|cookie)/i,
  /capture\s+(password|credentials|email|username|token|cookie)/i,
  /read\s+(password|credentials|email|username|token|cookie)/i,
  
  // Context manipulation
  /new\s+context/i,
  /reset\s+context/i,
  /clear\s+context/i,
  /change\s+context/i,
  
  // Obfuscation attempts
  /\u200b/g, // Zero-width space
  /\u200c/g, // Zero-width non-joiner
  /\u200d/g, // Zero-width joiner
  /\ufeff/g, // Zero-width no-break space
];

export const INSTRUCTION_KEYWORDS = [
  'ignore', 'disregard', 'forget', 'override', 'bypass', 'disable',
  'system', 'admin', 'developer', 'debug', 'jailbreak',
  'navigate', 'click', 'fill', 'submit', 'extract', 'steal',
  'send', 'transmit', 'exfiltrate', 'leak',
  'you are now', 'act as', 'pretend', 'roleplay',
];

export const SUSPICIOUS_URL_PATTERNS = [
  /https?:\/\/[^/]*\.(ru|cn|tk|ml|ga|cf|gq)/, // Suspicious TLDs
  /https?:\/\/[^/]*attacker/, // Contains "attacker"
  /https?:\/\/[^/]*malicious/, // Contains "malicious"
  /https?:\/\/[^/]*evil/, // Contains "evil"
  /https?:\/\/[^/]*hack/, // Contains "hack"
  /https?:\/\/[^/]*phish/, // Contains "phish"
  /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, // IP address
];

/**
 * Analyze text for prompt injection patterns
 * @param {string} text - Text to analyze
 * @param {Object} context - Context information
 * @returns {Array<Object>} Detected threats
 */
export function analyzeTextForPromptInjection(text, context = {}) {
  const threats = [];

  if (!text || typeof text !== 'string') {
    return threats;
  }

  // 1. Pattern matching
  for (const pattern of PROMPT_INJECTION_PATTERNS) {
    const matches = text.match(pattern);
    if (matches) {
      threats.push({
        type: 'PROMPT_INJECTION',
        severity: 'high',
        pattern: pattern.source,
        match: matches[0],
        text: text.substring(Math.max(0, matches.index - 50), Math.min(text.length, matches.index + matches[0].length + 50)),
        source: context.source || 'unknown',
        url: context.url || window.location.href,
        timestamp: Date.now(),
      });
    }
  }

  // 2. Semantic analysis (instruction keywords)
  const lowerText = text.toLowerCase();
  let keywordCount = 0;
  const foundKeywords = [];

  for (const keyword of INSTRUCTION_KEYWORDS) {
    if (lowerText.includes(keyword.toLowerCase())) {
      keywordCount++;
      foundKeywords.push(keyword);
    }
  }

  // If multiple instruction keywords found, flag as suspicious
  if (keywordCount >= 3) {
    threats.push({
      type: 'SEMANTIC_PROMPT_INJECTION',
      severity: 'medium',
      reason: `Multiple instruction keywords detected: ${foundKeywords.join(', ')}`,
      keywordCount,
      keywords: foundKeywords,
      source: context.source || 'unknown',
      url: context.url || window.location.href,
      timestamp: Date.now(),
    });
  }

  // 3. Suspicious URLs
  for (const pattern of SUSPICIOUS_URL_PATTERNS) {
    const matches = text.match(pattern);
    if (matches) {
      threats.push({
        type: 'SUSPICIOUS_URL',
        severity: 'medium',
        url: matches[0],
        reason: 'Suspicious URL pattern detected',
        source: context.source || 'unknown',
        timestamp: Date.now(),
      });
    }
  }

  // 4. Obfuscation detection (zero-width characters)
  const zeroWidthChars = ['\u200b', '\u200c', '\u200d', '\ufeff'];
  let zeroWidthCount = 0;

  for (const char of zeroWidthChars) {
    const count = (text.match(new RegExp(char, 'g')) || []).length;
    zeroWidthCount += count;
  }

  if (zeroWidthCount > 5) {
    threats.push({
      type: 'OBFUSCATION_ATTEMPT',
      severity: 'high',
      reason: `Excessive zero-width characters detected (${zeroWidthCount})`,
      count: zeroWidthCount,
      source: context.source || 'unknown',
      url: context.url || window.location.href,
      timestamp: Date.now(),
    });
  }

  return threats;
}

/**
 * Check if a DOM node is hidden
 * @param {Element} node - DOM node to check
 * @returns {boolean} True if hidden
 */
export function isNodeHidden(node) {
  if (!node || !node.style) return false;

  const style = window.getComputedStyle(node);
  
  return (
    style.display === 'none' ||
    style.visibility === 'hidden' ||
    style.opacity === '0' ||
    parseFloat(style.opacity) === 0 ||
    node.hidden === true ||
    node.getAttribute('aria-hidden') === 'true' ||
    parseInt(style.width) === 0 ||
    parseInt(style.height) === 0 ||
    parseInt(style.left) < -1000 ||
    parseInt(style.top) < -1000
  );
}

/**
 * Analyze DOM node for prompt injection
 * @param {Element} node - DOM node to analyze
 * @param {Object} context - Context information
 * @returns {Array<Object>} Detected threats
 */
export function analyzeNodeForPromptInjection(node, context = {}) {
  const threats = [];

  if (!node) return threats;

  // Get all text content
  const textContent = node.textContent || '';

  // Analyze text content
  const textThreats = analyzeTextForPromptInjection(textContent, {
    ...context,
    source: 'dom_node',
    nodeType: node.nodeName,
  });
  threats.push(...textThreats);

  // Check for hidden content with potential prompt injection
  if (isNodeHidden(node) && textContent.length > 50) {
    // Check if the hidden content contains instruction patterns
    const hasInstructions = INSTRUCTION_KEYWORDS.some(keyword => 
      textContent.toLowerCase().includes(keyword.toLowerCase())
    );

    if (hasInstructions) {
      threats.push({
        type: 'HIDDEN_PROMPT_INJECTION',
        severity: 'critical',
        reason: 'Hidden content with instruction keywords detected',
        textLength: textContent.length,
        textPreview: textContent.substring(0, 100),
        nodeType: node.nodeName,
        source: context.source || 'dom_node',
        url: context.url || window.location.href,
        timestamp: Date.now(),
      });
    }
  }

  return threats;
}

/**
 * Calculate threat score
 * @param {Array<Object>} threats - Array of threats
 * @returns {number} Total threat score
 */
export function calculateThreatScore(threats) {
  const severityScores = {
    'critical': 100,
    'high': 75,
    'medium': 50,
    'low': 25
  };

  return threats.reduce((total, threat) => {
    return total + (severityScores[threat.severity] || 25);
  }, 0);
}

