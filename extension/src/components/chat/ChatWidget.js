/**
 * ChatWidget - Main chat interface component
 */
class ChatWidget {
  constructor(container, riskContext) {
    this.container = container;
    this.riskContext = riskContext;
    this.chatService = new ChatService();
    this.messages = [];
    this.sessionId = this.generateNewSessionId();
    this.isMinimized = false;
    this.isTyping = false;
    
    console.log('ChatWidget initialized with context:', riskContext);
    this.init();
  }

  /**
   * Initialize the chat widget
   */
  async init() {
    this.render();
    this.attachEventListeners();
    await this.loadChatHistory();
    await this.showWelcomeMessage();
  }

  /**
   * Render the chat widget HTML
   */
  render() {
    this.container.innerHTML = `
      <div class="shield-bubble" id="shieldBubble">
        <span class="shield-icon">🛡️</span>
        <div class="message-indicator">!</div>
        <div class="bubble-tooltip">Click to view security analysis</div>
      </div>
      <div class="chat-widget" id="chatWidget" style="display: none;">
        <div class="chat-header">
          <div class="chat-title">
            <div class="chat-icon">🛡️</div>
            <h3>HTTPS Shield Assistant</h3>
          </div>
          <div class="chat-controls">
            <button class="chat-minimize" title="Minimize chat">−</button>
            <button class="chat-close" title="Close chat">×</button>
          </div>
        </div>
        <div class="chat-body">
          <div class="chat-messages" id="messageList"></div>
          <div class="quick-actions" id="quickActions">
            <!-- Dynamic suggestion buttons will be inserted here -->
          </div>
          <div class="chat-input-container">
            <input type="text" class="chat-input" id="chatInput" 
                   placeholder="Ask about this security warning..." 
                   maxlength="500">
            <button class="chat-send" id="chatSend" title="Send message">
              <span class="send-icon">➤</span>
            </button>
          </div>
        </div>
      </div>
      <div class="chat-bubble" id="chatBubble" style="display: none;">
        <div class="bubble-icon">🛡️</div>
        <div class="bubble-text">Need help?</div>
      </div>
    `;
  }

  /**
   * Attach event listeners
   */
  attachEventListeners() {
    // Send button
    const sendBtn = document.getElementById('chatSend');
    const input = document.getElementById('chatInput');
    
    sendBtn.addEventListener('click', () => this.handleSendMessage());
    
    // Enter key to send
    input.addEventListener('keypress', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        this.handleSendMessage();
      }
    });

    // Auto-resize input
    input.addEventListener('input', this.handleInputChange.bind(this));

    // Quick action buttons - using event delegation
    this.quickActionsHandler = (e) => {
      if (e.target.classList.contains('quick-action-btn')) {
        const message = e.target.getAttribute('data-message');
        this.sendMessage(message);
      }
    };
    document.getElementById('quickActions').addEventListener('click', this.quickActionsHandler);

    // Minimize/close controls
    document.querySelector('.chat-minimize').addEventListener('click', () => {
      this.toggleMinimize();
    });

    document.querySelector('.chat-close').addEventListener('click', () => {
      this.hide();
    });

    // Chat bubble to reopen
    document.getElementById('chatBubble').addEventListener('click', () => {
      this.show();
    });

    // Shield bubble click handler
    document.getElementById('shieldBubble').addEventListener('click', () => {
      this.openChatFromShield();
    });
  }

  /**
   * Handle input changes (auto-resize, validation)
   */
  handleInputChange(e) {
    const input = e.target;
    const sendBtn = document.getElementById('chatSend');
    
    // Enable/disable send button based on input
    sendBtn.disabled = !input.value.trim();
    
    // Character count indicator could be added here
    const remaining = 500 - input.value.length;
    if (remaining < 50) {
      input.style.borderColor = remaining < 0 ? '#ef4444' : '#f59e0b';
    } else {
      input.style.borderColor = '#d1d5db';
    }
  }

  /**
   * Handle sending a message
   */
  async handleSendMessage() {
    const input = document.getElementById('chatInput');
    const message = input.value.trim();
    
    if (!message) return;
    
    input.value = '';
    input.style.borderColor = '#d1d5db';
    document.getElementById('chatSend').disabled = true;
    
    await this.sendMessage(message);
  }

  /**
   * Send a message to the chatbot
   */
  async sendMessage(message) {
    try {
      // Add user message
      this.addMessage('user', message);
      this.showTypingIndicator();

      // Send to API
      const response = await this.chatService.sendMessage(message, {
        ...this.riskContext,
        sessionId: this.sessionId
      });

      // Remove typing indicator and add response
      this.removeTypingIndicator();
      this.addMessage('assistant', response.response);
      
      // Update quick actions with new suggestions if provided
      if (response.suggestions && Array.isArray(response.suggestions)) {
        this.updateQuickActions(response.suggestions);
      }
      
      // Update session ID if provided
      if (response.sessionId) {
        this.sessionId = response.sessionId;
      }

      // Save chat history
      await this.saveChatHistory();

    } catch (error) {
      console.error('Error sending message:', error);
      this.removeTypingIndicator();
      this.addMessage('assistant', `Error: ${error.message}`, 'error');
    }
  }

  /**
   * Add a message to the chat
   */
  addMessage(sender, content, type = 'normal') {
    const messageObj = {
      id: Date.now() + Math.random(),
      sender,
      content,
      type,
      timestamp: new Date().toISOString()
    };

    this.messages.push(messageObj);
    this.renderMessage(messageObj);
    this.scrollToBottom();
  }

  /**
   * Render a single message
   */
  renderMessage(messageObj) {
    const messageList = document.getElementById('messageList');
    const messageEl = document.createElement('div');
    messageEl.className = `message ${messageObj.sender} ${messageObj.type}`;
    messageEl.setAttribute('data-id', messageObj.id);

    const time = new Date(messageObj.timestamp).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit'
    });

    // Support basic markdown formatting
    const formattedContent = this.formatMessage(messageObj.content);

    messageEl.innerHTML = `
      <div class="message-content">
        <div class="message-text">${formattedContent}</div>
        <div class="message-time">${time}</div>
      </div>
    `;

    messageList.appendChild(messageEl);
  }

  /**
   * Format message content (basic markdown support)
   */
  formatMessage(content) {
    return content
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/`(.*?)`/g, '<code>$1</code>')
      .replace(/\n/g, '<br>')
      .replace(/(https?:\/\/[^\s]+)/g, '<a href="$1" target="_blank">$1</a>');
  }

  /**
   * Show typing indicator
   */
  showTypingIndicator() {
    if (this.isTyping) return;
    
    this.isTyping = true;
    const messageList = document.getElementById('messageList');
    const typingEl = document.createElement('div');
    typingEl.className = 'message assistant typing';
    typingEl.id = 'typingIndicator';
    typingEl.innerHTML = `
      <div class="message-content">
        <div class="typing-dots">
          <span></span><span></span><span></span>
        </div>
      </div>
    `;
    
    messageList.appendChild(typingEl);
    this.scrollToBottom();
  }

  /**
   * Remove typing indicator
   */
  removeTypingIndicator() {
    const typingEl = document.getElementById('typingIndicator');
    if (typingEl) {
      typingEl.remove();
    }
    this.isTyping = false;
  }

  /**
   * Scroll to bottom of messages
   */
  scrollToBottom() {
    const messageList = document.getElementById('messageList');
    messageList.scrollTop = messageList.scrollHeight;
  }

  /**
   * Show welcome message with context from API
   */
  async showWelcomeMessage() {
    try {
      // Start shield bubble animation
      this.animateShieldBubble();

      // Send 'auto' message to get initial AI assessment with suggestions
      const response = await this.chatService.sendMessage('auto', {
        ...this.riskContext,
        sessionId: this.sessionId
      });

      // Message is ready, transform bubble
      this.transformToMessageBubble();
      
      // Store the response for when user opens chat
      this.pendingWelcomeMessage = response;
      
      // Update session ID if provided
      if (response.sessionId) {
        this.sessionId = response.sessionId;
      }

    } catch (error) {
      console.error('Error loading welcome message:', error);
      this.removeTypingIndicator();
      
      // Fallback to basic welcome message if API fails
      const url = this.riskContext?.url || 'this site';
      const riskLevel = this.riskContext?.riskLevel || 'UNKNOWN';
      const riskScore = this.riskContext?.riskScore || 0;
      
      const fallbackMessage = `Hello! I'm here to help with security questions about **${url}** (Risk: ${riskLevel} ${riskScore}/100). Please type your questions below.`;
      this.addMessage('assistant', fallbackMessage);
      
      // Add basic fallback suggestions
      this.updateQuickActions([
        { title: "Risk Details", question: "What does this risk score mean?" },
        { title: "Stay Safe", question: "Is it safe to continue to this site?" },
        { title: "Next Steps", question: "What should I do?" }
      ]);
    }
  }

  /**
   * Toggle minimize state
   */
  toggleMinimize() {
    this.isMinimized = !this.isMinimized;
    const widget = document.getElementById('chatWidget');
    const minimizeBtn = document.querySelector('.chat-minimize');
    
    if (this.isMinimized) {
      widget.classList.add('minimized');
      minimizeBtn.textContent = '+';
      minimizeBtn.title = 'Maximize chat';
    } else {
      widget.classList.remove('minimized');
      minimizeBtn.textContent = '−';
      minimizeBtn.title = 'Minimize chat';
    }
  }

  /**
   * Hide the chat widget and show bubble
   */
  hide() {
    document.getElementById('chatWidget').style.display = 'none';
    document.getElementById('chatBubble').style.display = 'flex';
  }

  /**
   * Show the chat widget and hide bubble
   */
  show() {
    document.getElementById('chatWidget').style.display = 'flex';
    document.getElementById('chatBubble').style.display = 'none';
    document.getElementById('shieldBubble').style.display = 'none';
    this.isMinimized = false;
    document.getElementById('chatWidget').classList.remove('minimized');
  }

  /**
   * Open chat from shield bubble with animation
   */
  openChatFromShield() {
    const shieldBubble = document.getElementById('shieldBubble');
    shieldBubble.style.display = 'none';
    this.show();
    
    // Show the pending welcome message if available
    if (this.pendingWelcomeMessage) {
      this.addMessage('assistant', this.pendingWelcomeMessage.response);
      
      // Update quick actions with initial suggestions
      if (this.pendingWelcomeMessage.suggestions && Array.isArray(this.pendingWelcomeMessage.suggestions)) {
        this.updateQuickActions(this.pendingWelcomeMessage.suggestions);
      }
      
      // Clear pending message
      this.pendingWelcomeMessage = null;
    }
  }

  /**
   * Animate shield bubble during loading
   */
  animateShieldBubble() {
    const shieldBubble = document.getElementById('shieldBubble');
    if (shieldBubble) {
      shieldBubble.classList.add('expanded');
    }
  }

  /**
   * Transform shield bubble to message bubble
   */
  transformToMessageBubble() {
    const shieldBubble = document.getElementById('shieldBubble');
    if (shieldBubble) {
      shieldBubble.classList.remove('expanded');
      shieldBubble.classList.add('message-ready');
      
      // Update tooltip text
      const tooltip = shieldBubble.querySelector('.bubble-tooltip');
      if (tooltip) {
        tooltip.textContent = 'Security analysis complete! Click me to ask questions if anything seems unclear';
      }
    }
  }

  /**
   * Generate a new unique session ID for each conversation
   */
  generateNewSessionId() {
    // Always generate a new session ID for each chat widget instance
    // Include URL context to make it unique per site
    const urlHash = this.riskContext?.url ? 
      btoa(this.riskContext.url).substring(0, 8) : 'unknown';
    
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2, 9);
    
    return `chat_${urlHash}_${timestamp}_${random}`;
  }

  /**
   * Save chat history to Chrome storage
   */
  async saveChatHistory() {
    try {
      if (chrome?.storage?.local) {
        const key = `chat_history_${this.sessionId}`;
        await chrome.storage.local.set({
          [key]: {
            messages: this.messages,
            timestamp: Date.now(),
            riskContext: this.riskContext
          }
        });
      } else {
        // Fallback to localStorage
        localStorage.setItem(`chat_history_${this.sessionId}`, JSON.stringify({
          messages: this.messages,
          timestamp: Date.now(),
          riskContext: this.riskContext
        }));
      }
    } catch (error) {
      console.error('Error saving chat history:', error);
    }
  }

  /**
   * Load chat history from Chrome storage
   * Note: Since we generate new session IDs every time, no history will be found
   */
  async loadChatHistory() {
    // Skip loading chat history since each conversation should start fresh
    // with a new session ID. This method is kept for potential future use.
    console.log('Starting fresh conversation with session ID:', this.sessionId);
    return;
  }

  /**
   * Render all messages from history
   */
  renderAllMessages() {
    const messageList = document.getElementById('messageList');
    messageList.innerHTML = '';
    
    this.messages.forEach(message => {
      this.renderMessage(message);
    });
    
    this.scrollToBottom();
  }

  /**
   * Update quick actions with new suggestions from API response
   */
  updateQuickActions(suggestions) {
    const quickActionsContainer = document.getElementById('quickActions');
    if (!quickActionsContainer) return;

    // Clear existing quick actions
    quickActionsContainer.innerHTML = '';

    // Add new suggestion buttons
    suggestions.forEach((suggestion, index) => {
      if (suggestion.title && suggestion.question) {
        const button = document.createElement('button');
        button.className = 'quick-action-btn';
        button.setAttribute('data-message', suggestion.question);
        button.innerHTML = `${this.getSuggestionIcon(index)} ${suggestion.title}`;
        quickActionsContainer.appendChild(button);
      }
    });

    // Event listener is already attached to the container via event delegation
    // No need to re-attach listeners when updating suggestions
  }

  /**
   * Get appropriate icon for suggestion based on index
   */
  getSuggestionIcon(index) {
    const icons = ['📊', '🔒', '⚠️', '💡', '🛡️', '❓'];
    return icons[index] || '💬';
  }

  /**
   * Clean up old chat history (utility method for maintenance)
   */
  static async cleanupOldChatHistory(maxAgeHours = 24) {
    try {
      const cutoffTime = Date.now() - (maxAgeHours * 60 * 60 * 1000);
      
      if (chrome?.storage?.local) {
        // Get all stored data
        const allData = await chrome.storage.local.get(null);
        const keysToRemove = [];
        
        for (const [key, value] of Object.entries(allData)) {
          if (key.startsWith('chat_history_') && value.timestamp < cutoffTime) {
            keysToRemove.push(key);
          }
        }
        
        if (keysToRemove.length > 0) {
          await chrome.storage.local.remove(keysToRemove);
          console.log(`Cleaned up ${keysToRemove.length} old chat history entries`);
        }
      } else {
        // Fallback: clean localStorage
        Object.keys(localStorage).forEach(key => {
          if (key.startsWith('chat_history_')) {
            try {
              const data = JSON.parse(localStorage.getItem(key));
              if (data.timestamp < cutoffTime) {
                localStorage.removeItem(key);
              }
            } catch (e) {
              // Remove malformed entries
              localStorage.removeItem(key);
            }
          }
        });
      }
    } catch (error) {
      console.error('Error cleaning up chat history:', error);
    }
  }
}

// Make ChatWidget available globally
window.ChatWidget = ChatWidget;