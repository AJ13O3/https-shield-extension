/**
 * ChatService - Handles API communication with the chatbot Lambda function
 */
class ChatService {
  constructor() {
    // API configuration - using same API Gateway as risk assessment
    this.apiBaseUrl = 'https://7razok9dpj.execute-api.eu-west-2.amazonaws.com/prod';
    this.chatEndpoint = '/chat';
    this.apiKey = null; // Will be loaded from secure storage
    this.timeout = 30000; // 30 second timeout
    this.initialize();
  }

  /**
   * Initialize API configuration from secure storage
   */
  async initialize() {
    try {
      // Load API configuration from Chrome storage (same as risk assessment)
      const config = await chrome.storage.sync.get(['apiConfig']);
      if (config.apiConfig) {
        this.apiBaseUrl = config.apiConfig.baseUrl || this.apiBaseUrl;
        this.apiKey = config.apiConfig.apiKey;
      }
    } catch (error) {
      console.warn('Failed to load API configuration:', error);
    }
  }

  /**
   * Send a message to the chatbot and get a response
   * @param {string} message - User's message
   * @param {Object} context - Risk assessment context
   * @returns {Promise<Object>} - Chatbot response
   */
  async sendMessage(message, context) {
    try {
      // Ensure API key is loaded before making request
      if (!this.apiKey) {
        console.log('Chat API key not loaded, reinitializing...');
        await this.initialize();
      }

      // If still no API key, throw error
      if (!this.apiKey) {
        throw new Error('API key not configured. Please configure in extension settings.');
      }

      console.log('ChatService: Sending message', { message, context });

      const requestBody = {
        message: message,
        sessionId: context.sessionId || this.generateSessionId(),
        riskContext: {
          url: context.url,
          riskScore: context.riskScore,
          riskLevel: context.riskLevel,
          threats: context.threats,
          timestamp: new Date().toISOString()
        }
      };

      const fullEndpoint = `${this.apiBaseUrl}${this.chatEndpoint}`;
      const response = await fetch(fullEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Api-Key': this.apiKey,
          'Accept': 'application/json'
        },
        body: JSON.stringify(requestBody),
        signal: AbortSignal.timeout(this.timeout)
      });

      console.log('ChatService: Response status', response.status);

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`HTTP ${response.status}: ${errorText}`);
      }

      const data = await response.json();
      console.log('ChatService: Response data', data);

      // Handle different response formats from Lambda
      if (data.body) {
        // If Lambda returns wrapped response
        const bodyData = typeof data.body === 'string' ? JSON.parse(data.body) : data.body;
        return {
          response: bodyData.response || bodyData.message || 'I received your message but had trouble responding.',
          sessionId: bodyData.sessionId || context.sessionId,
          timestamp: new Date().toISOString()
        };
      } else {
        // Direct response format
        return {
          response: data.response || data.message || 'I received your message but had trouble responding.',
          sessionId: data.sessionId || context.sessionId,
          timestamp: new Date().toISOString()
        };
      }

    } catch (error) {
      console.error('ChatService error:', error);
      
      // Return appropriate error messages based on error type
      if (error.name === 'TimeoutError') {
        throw new Error('The request timed out. Please try again.');
      } else if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
        throw new Error('Network error. Please check your connection and try again.');
      } else if (error.message.includes('429')) {
        throw new Error('Too many requests. Please wait a moment and try again.');
      } else {
        throw new Error(`Unable to get response: ${error.message}`);
      }
    }
  }

  /**
   * Generate a unique session ID for conversation tracking
   * @returns {string} - Unique session ID
   */
  generateSessionId() {
    return 'chat_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }

  /**
   * Test the API connection
   * @returns {Promise<boolean>} - True if connection successful
   */
  async testConnection() {
    try {
      const testResponse = await this.sendMessage('Hello', {
        url: 'http://test.com',
        riskScore: 50,
        riskLevel: 'MEDIUM',
        threats: {}
      });
      return !!testResponse.response;
    } catch (error) {
      console.error('ChatService connection test failed:', error);
      return false;
    }
  }
}

// Make ChatService available globally
window.ChatService = ChatService;