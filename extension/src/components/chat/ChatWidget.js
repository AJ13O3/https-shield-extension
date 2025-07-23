/**
 * ChatWidget - Main chat interface component
 */
class ChatWidget {
  constructor(container, riskContext) {
    this.container = container;
    this.riskContext = riskContext;
    this.chatService = new ChatService();
    this.messages = [];
    this.sessionId = this.loadOrCreateSession();
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
    this.showWelcomeMessage();
  }

  /**
   * Render the chat widget HTML
   */
  render() {
    this.container.innerHTML = `
      <div class="chat-widget" id="chatWidget">
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
            <button class="quick-action-btn" data-message="What does this risk score mean?">
              📊 Explain Risk Score
            </button>
            <button class="quick-action-btn" data-message="Is it safe to continue to this site?">
              🔒 Is It Safe?
            </button>
            <button class="quick-action-btn" data-message="What threats were detected?">
              ⚠️ Detected Threats
            </button>
            <button class="quick-action-btn" data-message="What should I do?">
              💡 What Should I Do?
            </button>
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

    // Quick action buttons
    document.getElementById('quickActions').addEventListener('click', (e) => {
      if (e.target.classList.contains('quick-action-btn')) {
        const message = e.target.getAttribute('data-message');
        this.sendMessage(message);
      }
    });

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
      
      // Update session ID if provided
      if (response.sessionId) {
        this.sessionId = response.sessionId;
      }

      // Save chat history
      await this.saveChatHistory();

    } catch (error) {
      console.error('Error sending message:', error);
      this.removeTypingIndicator();
      this.addMessage('assistant', `❌ ${error.message}`, 'error');
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
   * Show welcome message with context
   */
  showWelcomeMessage() {
    const riskLevel = this.riskContext?.riskLevel || 'UNKNOWN';
    const riskScore = this.riskContext?.riskScore || 0;
    const url = this.riskContext?.url || 'this site';

    let welcomeMessage = `Hello! I'm here to help you understand the security risks for **${url}**.

**Risk Level**: ${riskLevel} (${riskScore}/100)

You can ask me about:
• What this risk score means
• Whether it's safe to continue
• What threats were detected
• What you should do next

Feel free to click the quick action buttons below or type your own question!`;

    this.addMessage('assistant', welcomeMessage);
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
    this.isMinimized = false;
    document.getElementById('chatWidget').classList.remove('minimized');
  }

  /**
   * Load or create session ID
   */
  loadOrCreateSession() {
    const stored = localStorage.getItem('chatSessionId');
    if (stored) {
      return stored;
    }
    
    const newSession = this.chatService.generateSessionId();
    localStorage.setItem('chatSessionId', newSession);
    return newSession;
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
   */
  async loadChatHistory() {
    try {
      let data = null;
      
      if (chrome?.storage?.local) {
        const key = `chat_history_${this.sessionId}`;
        const result = await chrome.storage.local.get(key);
        data = result[key];
      } else {
        // Fallback to localStorage
        const stored = localStorage.getItem(`chat_history_${this.sessionId}`);
        data = stored ? JSON.parse(stored) : null;
      }

      if (data && data.messages) {
        // Only load recent messages (last 24 hours)
        const dayAgo = Date.now() - (24 * 60 * 60 * 1000);
        if (data.timestamp > dayAgo) {
          this.messages = data.messages;
          this.renderAllMessages();
        }
      }
    } catch (error) {
      console.error('Error loading chat history:', error);
    }
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
}

// Make ChatWidget available globally
window.ChatWidget = ChatWidget;