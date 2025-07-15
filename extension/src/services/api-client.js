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
        this.apiBaseUrl = 'https://api.https-shield.com'; // Will be configured after AWS setup
        this.apiKey = null;
        this.timeout = 5000; // 5 second timeout
        this.retryAttempts = 2;
        this.fallbackEnabled = true;
        
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
        const requestData = {
            url: url,
            errorCode: errorCode,
            userAgent: userAgent || navigator.userAgent,
            timestamp: new Date().toISOString()
        };

        try {
            console.log('Analyzing URL risk via API:', url);
            
            const result = await this.makeRequest('/analyze-url', 'POST', requestData);
            
            // Validate response structure
            if (!this.isValidRiskAssessment(result)) {
                throw new Error('Invalid risk assessment response structure');
            }
            
            console.log('API risk analysis complete:', result.riskLevel);
            return result;
            
        } catch (error) {
            console.error('API risk analysis failed:', error);
            
            if (this.fallbackEnabled) {
                console.log('Falling back to mock risk analysis');
                return this.getMockRiskAssessment(url, errorCode);
            }
            
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
        return (
            assessment &&
            typeof assessment.riskScore === 'number' &&
            typeof assessment.riskLevel === 'string' &&
            typeof assessment.url === 'string' &&
            Array.isArray(assessment.recommendations) &&
            assessment.analysis &&
            typeof assessment.timestamp === 'string'
        );
    }

    /**
     * Generate mock risk assessment for fallback
     * @private
     * @param {string} url - URL to analyze
     * @param {string} errorCode - Browser error code
     * @returns {Object} Mock risk assessment
     */
    getMockRiskAssessment(url, errorCode) {
        const parsedUrl = new URL(url);
        
        // Calculate mock risk score
        let riskScore = 0;
        
        // Protocol analysis (40% weight)
        if (parsedUrl.protocol === 'http:') {
            riskScore += 40;
        }
        
        // Error code analysis (30% weight)
        const errorScores = {
            'ERR_CERT_DATE_INVALID': 30,
            'ERR_CERT_AUTHORITY_INVALID': 30,
            'ERR_CERT_COMMON_NAME_INVALID': 30,
            'ERR_SSL_PROTOCOL_ERROR': 20,
            'ERR_INSECURE_RESPONSE': 20
        };
        riskScore += errorScores[errorCode] || 0;
        
        // Domain analysis (20% weight)
        const suspiciousTlds = ['tk', 'ml', 'ga', 'cf'];
        if (suspiciousTlds.some(tld => parsedUrl.hostname.endsWith(`.${tld}`))) {
            riskScore += 20;
        }
        
        // URL length analysis (10% weight)
        if (url.length > 100) {
            riskScore += 10;
        }
        
        // Random variation
        riskScore += Math.random() * 10;
        riskScore = Math.min(Math.floor(riskScore), 100);
        
        const riskLevel = this.getRiskLevel(riskScore);
        
        return {
            url: url,
            riskScore: riskScore,
            riskLevel: riskLevel,
            analysis: {
                protocol_analysis: {
                    protocol: parsedUrl.protocol.replace(':', ''),
                    secure: parsedUrl.protocol === 'https:'
                },
                error_analysis: {
                    error_code: errorCode,
                    severity: errorCode ? 'HIGH' : 'LOW'
                },
                domain_analysis: {
                    domain: parsedUrl.hostname,
                    length: parsedUrl.hostname.length
                },
                url_structure: {
                    length: url.length
                }
            },
            recommendations: this.getMockRecommendations(riskLevel),
            timestamp: new Date().toISOString(),
            source: 'mock'
        };
    }

    /**
     * Get risk level from score
     * @private
     * @param {number} score - Risk score
     * @returns {string} Risk level
     */
    getRiskLevel(score) {
        if (score >= 80) return 'CRITICAL';
        if (score >= 60) return 'HIGH';
        if (score >= 40) return 'MEDIUM';
        return 'LOW';
    }

    /**
     * Get mock recommendations
     * @private
     * @param {string} riskLevel - Risk level
     * @returns {Array<string>} Recommendations
     */
    getMockRecommendations(riskLevel) {
        const recommendations = {
            'CRITICAL': [
                'Do not proceed to this site',
                'This site poses significant security risks',
                'Consider reporting this site if it appears fraudulent'
            ],
            'HIGH': [
                'Exercise extreme caution',
                'Do not enter sensitive information',
                'Consider finding an alternative secure site'
            ],
            'MEDIUM': [
                'Proceed with caution',
                'Verify the site is legitimate',
                'Avoid entering sensitive data'
            ],
            'LOW': [
                'Site appears relatively safe',
                'Still verify the URL is correct',
                'Look for HTTPS when possible'
            ]
        };
        
        return recommendations[riskLevel] || recommendations['MEDIUM'];
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
     * Enable or disable fallback mode
     * @param {boolean} enabled - Whether fallback is enabled
     */
    setFallbackEnabled(enabled) {
        this.fallbackEnabled = enabled;
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