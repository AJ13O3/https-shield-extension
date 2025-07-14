// HTTPS Shield Extension - Content Script
// Detects security warnings and provides real-time risk assessment

class HTTPSShieldContent {
    constructor() {
        this.isInitialized = false;
        this.currentURL = window.location.href;
        this.riskOverlay = null;
        this.init();
    }

    async init() {
        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.setup());
        } else {
            this.setup();
        }
    }

    async setup() {
        console.log('HTTPS Shield Content Script initializing on:', this.currentURL);
        
        // Set up message listeners
        this.setupMessageListeners();
        
        // Check if this is an HTTP site
        if (this.currentURL.startsWith('http://')) {
            await this.handleHTTPSite();
        }
        
        // Set up observers for dynamic content
        this.setupObservers();
        
        this.isInitialized = true;
        console.log('HTTPS Shield Content Script ready');
    }

    setupMessageListeners() {
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
            switch (message.type) {
                case 'HTTP_SITE_DETECTED':
                    this.handleHTTPSiteMessage(message);
                    break;
                
                case 'SHOW_RISK_ASSESSMENT':
                    this.showRiskAssessment(message.data);
                    break;
                
                case 'HIDE_RISK_OVERLAY':
                    this.hideRiskOverlay();
                    break;
                
                default:
                    console.log('Unknown message type:', message.type);
            }
            sendResponse({ received: true });
        });
    }

    async handleHTTPSite() {
        console.log('HTTP site detected, requesting risk analysis');
        
        // Request risk analysis from background script
        try {
            const response = await chrome.runtime.sendMessage({
                type: 'ANALYZE_URL',
                url: this.currentURL
            });
            
            if (response.success) {
                this.showRiskAssessment(response.data);
                
                // Log the event
                await chrome.runtime.sendMessage({
                    type: 'LOG_EVENT',
                    event: {
                        type: 'http_site_visited',
                        url: this.currentURL,
                        riskScore: response.data.riskScore
                    }
                });
            }
        } catch (error) {
            console.error('Error requesting risk analysis:', error);
        }
    }

    handleHTTPSiteMessage(message) {
        if (message.url === this.currentURL) {
            this.handleHTTPSite();
        }
    }

    showRiskAssessment(riskData) {
        // Remove existing overlay if present
        this.hideRiskOverlay();
        
        // Create risk overlay
        this.riskOverlay = this.createRiskOverlay(riskData);
        document.body.appendChild(this.riskOverlay);
        
        // Add show animation
        setTimeout(() => {
            this.riskOverlay.classList.add('https-shield-show');
        }, 100);
    }

    createRiskOverlay(riskData) {
        const overlay = document.createElement('div');
        overlay.className = `https-shield-overlay https-shield-${riskData.riskLevel}`;
        overlay.innerHTML = `
            <div class="https-shield-content">
                <div class="https-shield-header">
                    <div class="https-shield-icon">🛡️</div>
                    <h3>HTTPS Shield Warning</h3>
                    <button class="https-shield-close">&times;</button>
                </div>
                <div class="https-shield-body">
                    <div class="https-shield-risk">
                        <span class="https-shield-score">${riskData.riskScore}/100</span>
                        <span class="https-shield-level">${riskData.riskLevel.toUpperCase()} RISK</span>
                    </div>
                    <div class="https-shield-url">${riskData.url}</div>
                    <div class="https-shield-recommendations">
                        <h4>Recommendations:</h4>
                        <ul>
                            ${riskData.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                        </ul>
                    </div>
                    <div class="https-shield-actions">
                        <button class="https-shield-btn https-shield-btn-primary">Continue with Caution</button>
                        <button class="https-shield-btn https-shield-btn-secondary">Find HTTPS Version</button>
                    </div>
                </div>
            </div>
        `;
        
        // Add styles
        this.injectStyles();
        
        // Add event listeners
        this.setupOverlayEvents(overlay, riskData);
        
        return overlay;
    }

    setupOverlayEvents(overlay, riskData) {
        // Close button
        const closeBtn = overlay.querySelector('.https-shield-close');
        closeBtn.addEventListener('click', () => this.hideRiskOverlay());
        
        // Continue button
        const continueBtn = overlay.querySelector('.https-shield-btn-primary');
        continueBtn.addEventListener('click', () => {
            this.logAction('continue_with_caution', riskData);
            this.hideRiskOverlay();
        });
        
        // Find HTTPS button
        const httpsBtn = overlay.querySelector('.https-shield-btn-secondary');
        httpsBtn.addEventListener('click', () => {
            this.logAction('find_https_version', riskData);
            const httpsURL = this.currentURL.replace('http://', 'https://');
            window.location.href = httpsURL;
        });
        
        // Close on overlay click (not content)
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) {
                this.hideRiskOverlay();
            }
        });
    }

    hideRiskOverlay() {
        if (this.riskOverlay) {
            this.riskOverlay.classList.add('https-shield-hide');
            setTimeout(() => {
                if (this.riskOverlay && this.riskOverlay.parentNode) {
                    this.riskOverlay.parentNode.removeChild(this.riskOverlay);
                }
                this.riskOverlay = null;
            }, 300);
        }
    }

    async logAction(action, riskData) {
        try {
            await chrome.runtime.sendMessage({
                type: 'LOG_EVENT',
                event: {
                    type: 'user_action',
                    action,
                    url: this.currentURL,
                    riskScore: riskData.riskScore,
                    riskLevel: riskData.riskLevel
                }
            });
        } catch (error) {
            console.error('Error logging action:', error);
        }
    }

    setupObservers() {
        // Monitor for URL changes (SPA navigation)
        let lastURL = this.currentURL;
        const observer = new MutationObserver(() => {
            if (window.location.href !== lastURL) {
                lastURL = window.location.href;
                this.currentURL = lastURL;
                
                // Check new URL
                if (this.currentURL.startsWith('http://')) {
                    this.handleHTTPSite();
                } else {
                    this.hideRiskOverlay();
                }
            }
        });
        
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    injectStyles() {
        // Only inject once
        if (document.getElementById('https-shield-styles')) return;
        
        const style = document.createElement('style');
        style.id = 'https-shield-styles';
        style.textContent = `
            .https-shield-overlay {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.7);
                z-index: 2147483647;
                display: flex;
                justify-content: center;
                align-items: center;
                opacity: 0;
                transition: opacity 0.3s ease;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            }
            
            .https-shield-overlay.https-shield-show {
                opacity: 1;
            }
            
            .https-shield-overlay.https-shield-hide {
                opacity: 0;
            }
            
            .https-shield-content {
                background: white;
                border-radius: 12px;
                box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
                max-width: 500px;
                width: 90%;
                max-height: 80vh;
                overflow-y: auto;
            }
            
            .https-shield-header {
                display: flex;
                align-items: center;
                padding: 20px;
                border-bottom: 1px solid #e1e5e9;
                background: #f8f9fa;
                border-radius: 12px 12px 0 0;
            }
            
            .https-shield-icon {
                font-size: 24px;
                margin-right: 12px;
            }
            
            .https-shield-header h3 {
                margin: 0;
                flex-grow: 1;
                color: #2c3e50;
                font-size: 18px;
                font-weight: 600;
            }
            
            .https-shield-close {
                background: none;
                border: none;
                font-size: 24px;
                cursor: pointer;
                color: #6c757d;
                padding: 0;
                width: 24px;
                height: 24px;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            
            .https-shield-close:hover {
                color: #dc3545;
            }
            
            .https-shield-body {
                padding: 20px;
            }
            
            .https-shield-risk {
                display: flex;
                align-items: center;
                gap: 12px;
                margin-bottom: 16px;
            }
            
            .https-shield-score {
                font-size: 32px;
                font-weight: bold;
                color: #2c3e50;
            }
            
            .https-shield-level {
                font-size: 14px;
                font-weight: 600;
                padding: 4px 8px;
                border-radius: 4px;
                background: #e9ecef;
                color: #495057;
            }
            
            .https-shield-high .https-shield-level {
                background: #f8d7da;
                color: #721c24;
            }
            
            .https-shield-medium .https-shield-level {
                background: #fff3cd;
                color: #856404;
            }
            
            .https-shield-low .https-shield-level {
                background: #d4edda;
                color: #155724;
            }
            
            .https-shield-url {
                font-family: monospace;
                background: #f8f9fa;
                padding: 8px 12px;
                border-radius: 4px;
                word-break: break-all;
                margin-bottom: 16px;
                font-size: 14px;
                color: #495057;
            }
            
            .https-shield-recommendations h4 {
                margin: 0 0 8px 0;
                color: #2c3e50;
                font-size: 16px;
            }
            
            .https-shield-recommendations ul {
                margin: 0;
                padding-left: 20px;
                color: #495057;
            }
            
            .https-shield-recommendations li {
                margin-bottom: 4px;
            }
            
            .https-shield-actions {
                display: flex;
                gap: 12px;
                margin-top: 20px;
            }
            
            .https-shield-btn {
                padding: 10px 16px;
                border: none;
                border-radius: 6px;
                font-size: 14px;
                font-weight: 500;
                cursor: pointer;
                flex: 1;
                transition: all 0.2s ease;
            }
            
            .https-shield-btn-primary {
                background: #007bff;
                color: white;
            }
            
            .https-shield-btn-primary:hover {
                background: #0056b3;
            }
            
            .https-shield-btn-secondary {
                background: #6c757d;
                color: white;
            }
            
            .https-shield-btn-secondary:hover {
                background: #545b62;
            }
        `;
        
        document.head.appendChild(style);
    }
}

// Initialize the content script
new HTTPSShieldContent();