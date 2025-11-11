/**
 * Conversation Integrity Monitor for Armorly
 *
 * Detects conversation tampering by:
 * 1. Hashing conversation history
 * 2. Detecting injected/modified messages
 * 3. Verifying message order and timestamps
 * 4. Protecting against context poisoning
 *
 * This prevents attacks where:
 * - Attacker injects fake "previous conversation" context
 * - Messages are reordered to change meaning
 * - Past messages are modified to manipulate AI
 *
 * @module conversation-integrity
 * @author Armorly Security Team
 * @license MIT
 */

class ConversationIntegrityMonitor {
  constructor() {
    /**
     * Statistics
     */
    this.stats = {
      conversationsTracked: 0,
      messagesHashed: 0,
      tamperingDetected: 0,
      integrityViolations: 0,
    };

    /**
     * Configuration
     * OPTIMIZED: Increased check interval for better performance
     */
    this.config = {
      enabled: true,
      hashAlgorithm: 'SHA-256',
      checkInterval: 2000, // Check every 2 seconds (reduced overhead)
      maxConversationAge: 86400000, // 24 hours in ms
      logActions: false, // Silent operation
      maxMessagesPerConversation: 1000, // Prevent memory bloat
    };

    /**
     * Conversation storage
     * Map<conversationId, ConversationData>
     */
    this.conversations = new Map();

    /**
     * Message hashes for integrity verification
     * Map<messageId, hash>
     */
    this.messageHashes = new Map();

    /**
     * Message order tracking
     */
    this.messageSequence = [];

    /**
     * Integrity check interval
     */
    this.integrityCheckInterval = null;

    /**
     * Current conversation ID (platform-specific)
     */
    this.currentConversationId = null;

    /**
     * Performance optimizations
     */
    this.processedMessages = new WeakSet(); // Track processed message elements
    this.messageObserver = null; // Dedicated observer for messages

    /**
     * Injection patterns (pre-compiled for performance)
     */
    this.injectionPatterns = [
      /\[previous conversation\]/i,
      /\[context from earlier\]/i,
      /\[recalled memory\]/i,
      /continue from:/i,
      /resuming conversation from/i,
    ];
  }

  /**
   * Start monitoring conversation integrity
   */
  start() {
    if (!this.config.enabled) return;

    console.log('[Armorly Conversation Integrity] Starting - monitoring conversation tampering');

    // Detect current conversation
    this.detectConversation();

    // Set up periodic integrity checks
    this.integrityCheckInterval = setInterval(() => {
      this.checkIntegrity();
    }, this.config.checkInterval);

    // Set up MutationObserver for new messages
    this.setupMessageObserver();

    // Clean up old conversations
    this.cleanupOldConversations();
  }

  /**
   * Stop monitoring
   */
  stop() {
    if (this.integrityCheckInterval) {
      clearInterval(this.integrityCheckInterval);
      this.integrityCheckInterval = null;
    }

    if (this.messageObserver) {
      this.messageObserver.disconnect();
      this.messageObserver = null;
    }

    console.log('[Armorly Conversation Integrity] Stopped');
  }

  /**
   * Detect current conversation from URL or DOM
   */
  detectConversation() {
    // Try to extract conversation ID from URL
    const url = window.location.href;

    // ChatGPT: /c/{conversation_id}
    let match = url.match(/\/c\/([a-f0-9-]+)/i);
    if (match) {
      this.currentConversationId = match[1];
      this.initializeConversation(this.currentConversationId);
      return;
    }

    // Claude: /chat/{conversation_id}
    match = url.match(/\/chat\/([a-f0-9-]+)/i);
    if (match) {
      this.currentConversationId = match[1];
      this.initializeConversation(this.currentConversationId);
      return;
    }

    // Gemini: Uses session-based, generate UUID
    if (url.includes('gemini.google.com')) {
      this.currentConversationId = this.generateConversationId();
      this.initializeConversation(this.currentConversationId);
      return;
    }

    // Generic: Use hostname + timestamp
    this.currentConversationId = this.generateConversationId();
    this.initializeConversation(this.currentConversationId);
  }

  /**
   * Generate conversation ID for platforms without explicit IDs
   */
  generateConversationId() {
    const hostname = window.location.hostname;
    const timestamp = Date.now();
    return `${hostname}-${timestamp}`;
  }

  /**
   * Initialize conversation tracking
   */
  initializeConversation(conversationId) {
    if (this.conversations.has(conversationId)) {
      return; // Already tracking
    }

    this.conversations.set(conversationId, {
      id: conversationId,
      startTime: Date.now(),
      messageCount: 0,
      conversationHash: null,
      lastIntegrityCheck: Date.now(),
      messages: [],
    });

    this.stats.conversationsTracked++;

    console.log(`[Armorly Conversation Integrity] Tracking conversation: ${conversationId}`);
  }

  /**
   * Setup MutationObserver to detect new messages
   */
  setupMessageObserver() {
    this.messageObserver = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType === Node.ELEMENT_NODE) {
            this.processNewMessage(node);
          }
        }
      }
    });

    this.messageObserver.observe(document.body, {
      childList: true,
      subtree: true,
    });
  }

  /**
   * Process new message for integrity tracking
   * OPTIMIZED: Uses WeakSet to avoid re-processing
   */
  processNewMessage(element) {
    // Skip if already processed
    if (this.processedMessages.has(element)) {
      return;
    }

    // Check if element is a message
    const isMessage = this.isMessageElement(element);
    if (!isMessage) return;

    // Mark as processed
    this.processedMessages.add(element);

    // Extract message data
    const messageData = this.extractMessageData(element);
    if (!messageData) return;

    // Hash message content
    this.hashMessage(messageData);

    // Add to conversation
    this.addMessageToConversation(messageData);
  }

  /**
   * Check if element is a message
   */
  isMessageElement(element) {
    const messageSelectors = [
      '[data-message-author-role]',
      '[data-message-role]',
      '[class*="message"]',
      '[class*="Message"]',
      '[role="article"]',
      '[class*="turn"]',
    ];

    for (const selector of messageSelectors) {
      if (element.matches && element.matches(selector)) {
        return true;
      }
      if (element.querySelector && element.querySelector(selector)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Extract message data from element
   */
  extractMessageData(element) {
    try {
      const messageId = this.generateMessageId(element);
      const text = element.textContent || element.innerText || '';
      const timestamp = Date.now();

      // Determine role (user or assistant)
      let role = 'unknown';
      if (element.getAttribute('data-message-author-role')) {
        role = element.getAttribute('data-message-author-role');
      } else if (element.getAttribute('data-message-role')) {
        role = element.getAttribute('data-message-role');
      } else if (element.className.includes('user')) {
        role = 'user';
      } else if (element.className.includes('assistant') || element.className.includes('bot')) {
        role = 'assistant';
      }

      return {
        id: messageId,
        text: text.trim(),
        role,
        timestamp,
        element,
      };
    } catch (error) {
      console.error('[Armorly Conversation Integrity] Error extracting message:', error);
      return null;
    }
  }

  /**
   * Generate message ID
   */
  generateMessageId(element) {
    // Try to get existing ID
    const existingId = element.getAttribute('data-message-id') ||
                       element.getAttribute('id') ||
                       element.getAttribute('data-testid');

    if (existingId) {
      return existingId;
    }

    // Generate based on content and position
    const text = (element.textContent || '').substring(0, 50);
    const hash = this.simpleHash(text + Date.now());
    return `msg-${hash}`;
  }

  /**
   * Hash message content for integrity verification
   */
  async hashMessage(messageData) {
    try {
      const content = JSON.stringify({
        id: messageData.id,
        text: messageData.text,
        role: messageData.role,
        timestamp: messageData.timestamp,
      });

      // Use Web Crypto API for hashing
      const encoder = new TextEncoder();
      const data = encoder.encode(content);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

      this.messageHashes.set(messageData.id, hashHex);
      this.stats.messagesHashed++;

      return hashHex;
    } catch (error) {
      console.error('[Armorly Conversation Integrity] Error hashing message:', error);
      return null;
    }
  }

  /**
   * Add message to conversation
   * OPTIMIZED: Implements message limit to prevent memory bloat
   */
  addMessageToConversation(messageData) {
    if (!this.currentConversationId) return;

    const conversation = this.conversations.get(this.currentConversationId);
    if (!conversation) return;

    // Enforce message limit (prevent memory bloat on long conversations)
    if (conversation.messages.length >= this.config.maxMessagesPerConversation) {
      // Remove oldest message
      const removed = conversation.messages.shift();
      this.messageHashes.delete(removed.id);

      // Remove from sequence
      const seqIndex = this.messageSequence.indexOf(removed.id);
      if (seqIndex !== -1) {
        this.messageSequence.splice(seqIndex, 1);
      }
    }

    conversation.messages.push(messageData);
    conversation.messageCount++;
    this.messageSequence.push(messageData.id);

    // Update conversation hash (throttled)
    this.updateConversationHash();
  }

  /**
   * Update conversation hash
   */
  async updateConversationHash() {
    if (!this.currentConversationId) return;

    const conversation = this.conversations.get(this.currentConversationId);
    if (!conversation) return;

    try {
      // Create hash of all messages in order
      const messageIds = conversation.messages.map(m => m.id).join(',');
      const encoder = new TextEncoder();
      const data = encoder.encode(messageIds);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

      conversation.conversationHash = hashHex;
    } catch (error) {
      console.error('[Armorly Conversation Integrity] Error updating conversation hash:', error);
    }
  }

  /**
   * Check conversation integrity
   */
  async checkIntegrity() {
    if (!this.currentConversationId) return;

    const conversation = this.conversations.get(this.currentConversationId);
    if (!conversation) return;

    // Verify message order
    const orderIntact = this.verifyMessageOrder(conversation);
    if (!orderIntact) {
      this.handleIntegrityViolation('MESSAGE_ORDER_TAMPERED', conversation);
      return;
    }

    // Verify message content hasn't changed
    const contentIntact = await this.verifyMessageContent(conversation);
    if (!contentIntact) {
      this.handleIntegrityViolation('MESSAGE_CONTENT_TAMPERED', conversation);
      return;
    }

    // Verify no injected messages
    const noInjection = this.detectInjectedMessages(conversation);
    if (!noInjection) {
      this.handleIntegrityViolation('INJECTED_MESSAGES_DETECTED', conversation);
      return;
    }

    conversation.lastIntegrityCheck = Date.now();
  }

  /**
   * Verify message order
   */
  verifyMessageOrder(conversation) {
    const currentSequence = conversation.messages.map(m => m.id);
    const expectedSequence = this.messageSequence.filter(id =>
      currentSequence.includes(id)
    );

    // Check if order matches
    for (let i = 0; i < currentSequence.length; i++) {
      if (currentSequence[i] !== expectedSequence[i]) {
        return false;
      }
    }

    return true;
  }

  /**
   * Verify message content hasn't changed
   */
  async verifyMessageContent(conversation) {
    for (const message of conversation.messages) {
      const storedHash = this.messageHashes.get(message.id);
      if (!storedHash) continue;

      // Recalculate hash
      const currentHash = await this.hashMessage(message);
      if (currentHash !== storedHash) {
        return false;
      }
    }

    return true;
  }

  /**
   * Detect injected messages
   * OPTIMIZED: Uses pre-compiled patterns
   */
  detectInjectedMessages(conversation) {
    // Check for suspicious patterns in messages using pre-compiled patterns
    for (const message of conversation.messages) {
      for (const pattern of this.injectionPatterns) {
        if (pattern.test(message.text)) {
          return false; // Early exit on first match
        }
      }
    }

    return true;
  }

  /**
   * Handle integrity violation
   */
  handleIntegrityViolation(type, conversation) {
    this.stats.integrityViolations++;
    this.stats.tamperingDetected++;

    console.error(`[Armorly Conversation Integrity] TAMPERING DETECTED: ${type}`, conversation);

    // Show warning to user
    this.showTamperingWarning(type);

    // Report to background
    this.reportTampering(type, conversation);
  }

  /**
   * Show tampering warning
   * OPTIMIZED: Removed emoji for cleaner UI
   */
  showTamperingWarning(type) {
    const warning = document.createElement('div');
    warning.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: #c00;
      color: white;
      padding: 16px 24px;
      border-radius: 8px;
      font-family: system-ui, -apple-system, sans-serif;
      font-size: 14px;
      z-index: 999999;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      max-width: 350px;
    `;

    const header = document.createElement('div');
    header.style.cssText = 'font-weight: bold; margin-bottom: 8px;';
    header.textContent = 'Conversation Tampering Detected';
    warning.appendChild(header);

    const desc = document.createElement('div');
    desc.style.cssText = 'font-size: 13px;';
    desc.textContent = `Armorly detected: ${type.replace(/_/g, ' ')}. Your conversation may have been compromised.`;
    warning.appendChild(desc);

    document.body.appendChild(warning);

    // Auto-dismiss after 10 seconds
    setTimeout(() => {
      warning.style.transition = 'opacity 0.3s';
      warning.style.opacity = '0';
      setTimeout(() => warning.remove(), 300);
    }, 10000);
  }

  /**
   * Report tampering to background
   */
  reportTampering(type, conversation) {
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({
        type: 'CONVERSATION_TAMPERING',
        tamperingType: type,
        conversationId: conversation.id,
        messageCount: conversation.messageCount,
        url: window.location.href,
        timestamp: Date.now(),
      }).catch(() => {
        // Service worker may be inactive
      });
    }
  }

  /**
   * Simple hash function for ID generation
   */
  simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    return Math.abs(hash).toString(36);
  }

  /**
   * Clean up old conversations
   * OPTIMIZED: Also cleans up message hashes to prevent memory leaks
   */
  cleanupOldConversations() {
    const now = Date.now();

    for (const [id, conversation] of this.conversations.entries()) {
      const age = now - conversation.startTime;
      if (age > this.config.maxConversationAge) {
        // Clean up message hashes
        for (const message of conversation.messages) {
          this.messageHashes.delete(message.id);
        }

        // Remove conversation
        this.conversations.delete(id);

        if (this.config.logActions) {
          console.log(`[Armorly Conversation Integrity] Cleaned up old conversation: ${id}`);
        }
      }
    }
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      ...this.stats,
      activeConversations: this.conversations.size,
      currentConversationId: this.currentConversationId,
    };
  }

  /**
   * Enable/disable monitor
   */
  setEnabled(enabled) {
    this.config.enabled = enabled;

    if (enabled) {
      this.start();
    } else {
      this.stop();
    }
  }
}

// Export for use in content script
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { ConversationIntegrityMonitor };
}
