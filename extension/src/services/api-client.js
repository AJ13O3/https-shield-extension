/**
 * HTTPS Shield API Client
 * 
 * Handles communication with AWS API Gateway and Lambda functions
 * Provides fallback to mock data when API is unavailable
 * 
 * @author HTTPS Shield Extension Team
 * @version 1.0.0
 */

class HTTPSShieldAPIClient {
    constructor() {
        this.apiBaseUrl = 'https://7razok9dpj.execute-api.eu-west-2.amazonaws.com/prod';
        this.apiKey = null; // Will be loaded from secure storage
        this.timeout = 5000; // 5 second timeout
        this.retryAttempts = 2;
        
        this.initialize();
    }

    async initialize() {
        try {
            // Load API configuration from storage
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
     * Analyze URL risk using AWS Lambda
     * @param {string} url - URL to analyze
     * @param {string} errorCode - Browser error code (optional)
     * @param {string} userAgent - User agent string (optional)
     * @returns {Promise<Object>} Risk assessment result
     */
    async analyzeUrlRisk(url, errorCode = '', userAgent = '') {
        // Ensure API key is loaded before making request
        if (!this.apiKey) {
            console.log('API key not loaded, reinitializing...');
            await this.initialize();
        }

        const requestData = {
            url: url,
            errorCode: errorCode,
            userAgent: userAgent || navigator.userAgent,
            timestamp: new Date().toISOString()
        };

        try {
            console.log('Analyzing URL risk via API:', url);
            console.log('API key available:', !!this.apiKey);
            
            const result = await this.makeRequest('/analyze-url', 'POST', requestData);
            
            // Validate response structure
            if (!this.isValidRiskAssessment(result)) {
                throw new Error('Invalid risk assessment response structure');
            }
            
            console.log('API risk analysis complete:', result.riskLevel);
            return result;
            
        } catch (error) {
            console.error('API risk analysis failed:', error);
            
            // No fallback - AI functionality is crucial
            throw error;
        }
    }

    /**
     * Make HTTP request to API
     * @private
     * @param {string} endpoint - API endpoint
     * @param {string} method - HTTP method
     * @param {Object} data - Request data
     * @returns {Promise<Object>} Response data
     */
    async makeRequest(endpoint, method = 'GET', data = null) {
        let lastError;
        
        for (let attempt = 0; attempt < this.retryAttempts; attempt++) {
            try {
                const response = await this.executeRequest(endpoint, method, data);
                return response;
            } catch (error) {
                lastError = error;
                
                // Don't retry on client errors (4xx)
                if (error.status >= 400 && error.status < 500) {
                    break;
                }
                
                // Wait before retry (exponential backoff)
                if (attempt < this.retryAttempts - 1) {
                    await this.delay(Math.pow(2, attempt) * 1000);
                }
            }
        }
        
        throw lastError;
    }

    /**
     * Execute HTTP request
     * @private
     * @param {string} endpoint - API endpoint
     * @param {string} method - HTTP method
     * @param {Object} data - Request data
     * @returns {Promise<Object>} Response data
     */
    async executeRequest(endpoint, method, data) {
        const url = `${this.apiBaseUrl}${endpoint}`;
        
        const requestOptions = {
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'X-Extension-Version': chrome.runtime.getManifest().version,
                'X-User-Agent': navigator.userAgent
            }
        };

        // Add API key if available
        if (this.apiKey) {
            requestOptions.headers['X-Api-Key'] = this.apiKey;
        }

        // Add request body for POST requests
        if (method === 'POST' && data) {
            requestOptions.body = JSON.stringify(data);
        }

        // Create abort controller for timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        requestOptions.signal = controller.signal;

        try {
            const response = await fetch(url, requestOptions);
            clearTimeout(timeoutId);

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
                const error = new Error(errorData.error || `HTTP ${response.status}`);
                error.status = response.status;
                throw error;
            }

            return await response.json();
            
        } catch (error) {
            clearTimeout(timeoutId);
            
            if (error.name === 'AbortError') {
                throw new Error('Request timeout');
            }
            
            throw error;
        }
    }

    /**
     * Validate risk assessment response structure
     * @private
     * @param {Object} assessment - Risk assessment object
     * @returns {boolean} True if valid
     */
    isValidRiskAssessment(assessment) {
        // Updated to match actual Lambda response structure
        // Lambda doesn't return recommendations or analysis - those are generated by LLM
        return (
            assessment &&
            typeof assessment.riskScore === 'number' &&
            typeof assessment.riskLevel === 'string' &&
            typeof assessment.url === 'string' &&
            typeof assessment.timestamp === 'string'
        );
    }


    /**
     * Update API configuration
     * @param {Object} config - New configuration
     */
    async updateConfig(config) {
        try {
            await chrome.storage.sync.set({ apiConfig: config });
            
            if (config.baseUrl) {
                this.apiBaseUrl = config.baseUrl;
            }
            if (config.apiKey) {
                this.apiKey = config.apiKey;
            }
            
            console.log('API configuration updated');
        } catch (error) {
            console.error('Failed to update API configuration:', error);
        }
    }


    /**
     * Delay utility for retry logic
     * @private
     * @param {number} ms - Milliseconds to delay
     * @returns {Promise} Promise that resolves after delay
     */
    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = HTTPSShieldAPIClient;
}

// Export for ES6 modules
export default HTTPSShieldAPIClient;