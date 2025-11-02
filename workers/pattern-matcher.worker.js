/**
 * Pattern Matching Web Worker
 * 
 * Offloads heavy pattern matching operations from the main thread.
 * Handles:
 * - Prompt injection detection
 * - Credential pattern matching
 * - Sensitive data detection
 * - URL analysis
 * - Text analysis
 * 
 * @module pattern-matcher-worker
 * @author Armorly Security Team
 * @license MIT
 */

'use strict';

/**
 * Prompt injection patterns (from universal-prompt-patterns.js)
 */
const PROMPT_INJECTION_PATTERNS = [
  // Direct instruction injection
  /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|commands?)/gi,
  /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|commands?)/gi,
  /forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|commands?)/gi,
  
  // System prompt manipulation
  /you\s+are\s+now\s+(a|an)\s+\w+/gi,
  /act\s+as\s+(a|an)\s+\w+/gi,
  /pretend\s+(you\s+are|to\s+be)\s+(a|an)\s+\w+/gi,
  /roleplay\s+as\s+(a|an)\s+\w+/gi,
  
  // Instruction override
  /new\s+(instructions?|task|role|system\s+prompt)/gi,
  /updated\s+(instructions?|task|role|system\s+prompt)/gi,
  /override\s+(instructions?|settings?|rules?)/gi,
  
  // Delimiter attacks
  /---\s*end\s+(of\s+)?(instructions?|prompt|system)/gi,
  /\[\/?(INST|SYS|SYSTEM)\]/gi,
  /<\|?(end|start)_?(of_)?(turn|prompt|text)\|?>/gi,
  
  // Jailbreak attempts
  /do\s+anything\s+now/gi,
  /DAN\s+mode/gi,
  /developer\s+mode/gi,
  /god\s+mode/gi,
  
  // Data exfiltration
  /repeat\s+(everything|all|your\s+(instructions?|prompt|system))/gi,
  /print\s+(your\s+)?(instructions?|prompt|system)/gi,
  /show\s+(me\s+)?(your\s+)?(instructions?|prompt|system)/gi,
  /reveal\s+(your\s+)?(instructions?|prompt|system)/gi,
  
  // Encoding attacks
  /base64\s*:/gi,
  /rot13\s*:/gi,
  /hex\s*:/gi,
  /\\x[0-9a-f]{2}/gi,
  /\\u[0-9a-f]{4}/gi,
  
  // Prompt leaking
  /what\s+(are|were)\s+your\s+(original|initial)\s+(instructions?|prompt)/gi,
  /tell\s+me\s+your\s+(instructions?|prompt|system)/gi,
  
  // Instruction injection via markdown
  /```\s*(system|instructions?|prompt)/gi,
  /\[system\]/gi,
  /\[instructions?\]/gi,
];

/**
 * Credential patterns
 */
const CREDENTIAL_PATTERNS = [
  /password["\s:=]+[^"\s&]{6,}/gi,
  /api[_-]?key["\s:=]+[^"\s&]{10,}/gi,
  /bearer\s+[a-zA-Z0-9\-._~+/]+=*/gi,
  /authorization["\s:]+[^"\s&]{10,}/gi,
  /token["\s:=]+[^"\s&]{10,}/gi,
  /secret["\s:=]+[^"\s&]{10,}/gi,
  /private[_-]?key["\s:=]+[^"\s&]{20,}/gi,
  /access[_-]?token["\s:=]+[^"\s&]{10,}/gi,
];

/**
 * Sensitive data patterns
 */
const SENSITIVE_DATA_PATTERNS = [
  /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, // Credit card
  /\b\d{3}-\d{2}-\d{4}\b/g, // SSN
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, // Email
];

/**
 * Suspicious URL patterns
 */
const SUSPICIOUS_URL_PATTERNS = [
  /data:text\/html/gi,
  /javascript:/gi,
  /vbscript:/gi,
  /file:\/\//gi,
  /\.(tk|ml|ga|cf|gq)$/gi, // Free TLDs often used for phishing
];

/**
 * Instruction keywords for semantic analysis
 */
const INSTRUCTION_KEYWORDS = [
  'ignore', 'disregard', 'forget', 'override', 'bypass',
  'system', 'admin', 'root', 'sudo', 'execute',
  'reveal', 'show', 'print', 'display', 'output',
  'instructions', 'prompt', 'rules', 'guidelines',
];

/**
 * Analyze text for prompt injection
 */
function analyzePromptInjection(text) {
  const threats = [];
  let totalScore = 0;

  // Pattern matching
  for (const pattern of PROMPT_INJECTION_PATTERNS) {
    const matches = text.match(pattern);
    if (matches) {
      threats.push({
        type: 'PATTERN_MATCH',
        pattern: pattern.source,
        matches: matches.length,
        severity: 'HIGH',
        score: matches.length * 20,
      });
      totalScore += matches.length * 20;
    }
  }

  // Semantic analysis
  const lowerText = text.toLowerCase();
  const keywordCount = INSTRUCTION_KEYWORDS.filter(keyword => 
    lowerText.includes(keyword)
  ).length;

  if (keywordCount >= 3) {
    threats.push({
      type: 'SEMANTIC_ANALYSIS',
      keywordCount,
      severity: 'MEDIUM',
      score: keywordCount * 10,
    });
    totalScore += keywordCount * 10;
  }

  // Obfuscation detection
  const zeroWidthChars = (text.match(/[\u200B-\u200D\uFEFF]/g) || []).length;
  if (zeroWidthChars > 5) {
    threats.push({
      type: 'OBFUSCATION',
      zeroWidthChars,
      severity: 'HIGH',
      score: 50,
    });
    totalScore += 50;
  }

  return {
    detected: threats.length > 0,
    threats,
    totalScore,
    severity: totalScore >= 50 ? 'CRITICAL' : totalScore >= 30 ? 'HIGH' : 'MEDIUM',
  };
}

/**
 * Analyze text for credentials
 */
function analyzeCredentials(text) {
  const threats = [];

  for (const pattern of CREDENTIAL_PATTERNS) {
    const matches = text.match(pattern);
    if (matches) {
      threats.push({
        type: 'CREDENTIAL_DETECTED',
        pattern: pattern.source,
        count: matches.length,
        severity: 'CRITICAL',
      });
    }
  }

  return {
    detected: threats.length > 0,
    threats,
  };
}

/**
 * Analyze text for sensitive data
 */
function analyzeSensitiveData(text) {
  const threats = [];

  for (const pattern of SENSITIVE_DATA_PATTERNS) {
    const matches = text.match(pattern);
    if (matches) {
      threats.push({
        type: 'SENSITIVE_DATA',
        pattern: pattern.source,
        count: matches.length,
        severity: 'HIGH',
      });
    }
  }

  return {
    detected: threats.length > 0,
    threats,
  };
}

/**
 * Analyze URL
 */
function analyzeURL(url) {
  const threats = [];

  for (const pattern of SUSPICIOUS_URL_PATTERNS) {
    if (pattern.test(url)) {
      threats.push({
        type: 'SUSPICIOUS_URL',
        pattern: pattern.source,
        severity: 'HIGH',
      });
    }
  }

  return {
    detected: threats.length > 0,
    threats,
  };
}

/**
 * Batch analyze multiple texts
 */
function batchAnalyze(texts, analysisType) {
  const results = [];

  for (const text of texts) {
    let result;
    
    switch (analysisType) {
      case 'prompt_injection':
        result = analyzePromptInjection(text);
        break;
      case 'credentials':
        result = analyzeCredentials(text);
        break;
      case 'sensitive_data':
        result = analyzeSensitiveData(text);
        break;
      case 'url':
        result = analyzeURL(text);
        break;
      default:
        result = { error: 'Unknown analysis type' };
    }

    results.push(result);
  }

  return results;
}

/**
 * Message handler
 */
self.addEventListener('message', (event) => {
  const { id, type, data } = event.data;

  try {
    let result;

    switch (type) {
      case 'analyze_prompt_injection':
        result = analyzePromptInjection(data.text);
        break;

      case 'analyze_credentials':
        result = analyzeCredentials(data.text);
        break;

      case 'analyze_sensitive_data':
        result = analyzeSensitiveData(data.text);
        break;

      case 'analyze_url':
        result = analyzeURL(data.url);
        break;

      case 'batch_analyze':
        result = batchAnalyze(data.texts, data.analysisType);
        break;

      default:
        result = { error: 'Unknown message type' };
    }

    self.postMessage({
      id,
      success: true,
      result,
    });
  } catch (error) {
    self.postMessage({
      id,
      success: false,
      error: error.message,
    });
  }
});

// Signal that worker is ready
self.postMessage({ type: 'ready' });

