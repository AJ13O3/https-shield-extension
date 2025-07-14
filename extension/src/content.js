// HTTPS Shield Extension - Content Script
// Detects security warnings and injects UI elements

class HTTPSShieldContent {
    constructor() {
        this.isInitialized = false;
        this.warningDetectors = [];
        this.riskOverlay = null;
        this.init();
    }

    async init() {
        if (this.isInitialized) return;
        
        console.log('HTTPS Shield Content Script initializing on:', window.location.href);
        
        // Set up message listener for background script
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
            this.handleMessage(message, sender, sendResponse);
            return true;
        });

        // Set up warning detection
        this.setupWarningDetectors();
        
        // Monitor for HTTP sites
        this.checkCurrentSite();
        
        // Set up DOM mutation observer for dynamic warnings
        this.setupMutationObserver();
        
        this.isInitialized = true;
        console.log('HTTPS Shield Content Script initialized');
    }

    setupWarningDetectors() {
        // Chrome's "Not secure" warning in address bar
        this.warningDetectors.push({
            name: 'chrome-not-secure',
            selector: '[data-value="Not secure"]',
            check: () => document.querySelector('[data-value="Not secure"]') !== null
        });

        // Generic SSL/TLS error pages
        this.warningDetectors.push({
            name: 'ssl-error-page',
            selector: '#security-error-page, .ssl-error-container',
            check: () => {
                return document.title.toLowerCase().includes('privacy error') ||
                       document.title.toLowerCase().includes('security error') ||
                       document.body.textContent.includes('ERR_CERT_');
            }
        });

        // Mixed content warnings
        this.warningDetectors.push({
            name: 'mixed-content',
            selector: '[class*="mixed-content"], [class*="insecure-content"]',
            check: () => {
                // Check for mixed content in console (limited access from content script)
                return window.location.protocol === 'https:' && 
                       document.querySelector('script[src^="http:"], img[src^="http:"], link[href^="http:"]');
            }
        });

        console.log('Warning detectors configured:', this.warningDetectors.length);
    }

    async checkCurrentSite() {
        const currentUrl = window.location.href;
        
        // Check if current site is HTTP
        if (currentUrl.startsWith('http://')) {
            console.log('HTTP site detected:', currentUrl);
            await this.handleHTTPSite(currentUrl);
        }

        // Run all warning detectors
        this.runWarningDetection();
    }

    runWarningDetection() {
        let warningsFound = [];
        
        this.warningDetectors.forEach(detector => {
            try {
                if (detector.check()) {
                    console.log('Warning detected:', detector.name);
                    warningsFound.push(detector.name);
                }
            } catch (error) {
                console.warn('Error running detector:', detector.name, error);
            }
        });

        if (warningsFound.length > 0) {
            this.handleWarningsDetected(warningsFound);
        }
    }

    async handleHTTPSite(url) {
        try {
            // Request risk analysis from background script
            const response = await chrome.runtime.sendMessage({
                type: 'ANALYZE_URL',
                url: url
            });

            if (response.success) {
                this.showRiskAssessment(response.data);
                
                // Log the event
                chrome.runtime.sendMessage({
                    type: 'LOG_EVENT',
                    event: {
                        type: 'http_site_visited',
                        url: url,
                        riskScore: response.data.riskScore,
                        riskLevel: response.data.riskLevel
                    }
                });
            }
        } catch (error) {
            console.error('Error analyzing URL:', error);
        }
    }

    handleWarningsDetected(warnings) {
        console.log('Security warnings detected:', warnings);
        
        // Log the warning detection event
        chrome.runtime.sendMessage({
            type: 'LOG_EVENT',
            event: {
                type: 'security_warnings_detected',
                warnings: warnings,
                url: window.location.href
            }
        });

        // Show enhanced warning UI
        this.showEnhancedWarning(warnings);
    }

    showRiskAssessment(analysis) {
        // Create or update risk overlay
        if (!this.riskOverlay) {
            this.createRiskOverlay();
        }

        this.updateRiskOverlay(analysis);
    }

    createRiskOverlay() {
        // Create floating risk assessment overlay
        this.riskOverlay = document.createElement('div');
        this.riskOverlay.id = 'https-shield-overlay';
        this.riskOverlay.innerHTML = `
            <div class="shield-overlay-content">
                <div class="shield-header">
                    <span class="shield-icon">🛡️</span>
                    <span class="shield-title">HTTPS Shield</span>
                    <button class="shield-close" onclick="this.parentElement.parentElement.parentElement.style.display='none'">×</button>
                </div>
                <div class="shield-body">
                    <div class="risk-indicator">
                        <div class="risk-score"></div>
                        <div class="risk-level"></div>
                    </div>
                    <div class="risk-details">
                        <p class="risk-message"></p>
                        <ul class="risk-recommendations"></ul>
                    </div>
                    <div class="shield-actions">
                        <button class="btn-primary" onclick="window.location.href = window.location.href.replace('http://', 'https://')">Try HTTPS</button>
                        <button class="btn-secondary" onclick="document.getElementById('https-shield-overlay').style.display='none'">Continue Anyway</button>
                    </div>
                </div>
            </div>
        `;

        // Add styles
        this.addOverlayStyles();
        
        // Append to body
        document.body.appendChild(this.riskOverlay);
    }

    updateRiskOverlay(analysis) {
        if (!this.riskOverlay) return;

        const riskScore = this.riskOverlay.querySelector('.risk-score');
        const riskLevel = this.riskOverlay.querySelector('.risk-level');
        const riskMessage = this.riskOverlay.querySelector('.risk-message');
        const recommendations = this.riskOverlay.querySelector('.risk-recommendations');

        // Update content
        riskScore.textContent = `${analysis.riskScore}/100`;
        riskLevel.textContent = analysis.riskLevel.toUpperCase();
        riskLevel.className = `risk-level risk-${analysis.riskLevel}`;
        
        riskMessage.textContent = `Risk assessment for ${analysis.url}`;
        
        // Update recommendations
        recommendations.innerHTML = '';
        analysis.recommendations.forEach(rec => {
            const li = document.createElement('li');
            li.textContent = rec;
            recommendations.appendChild(li);
        });

        // Show overlay
        this.riskOverlay.style.display = 'block';
    }

    showEnhancedWarning(warnings) {
        // Create enhanced warning banner for detected security issues
        const warningBanner = document.createElement('div');
        warningBanner.id = 'https-shield-warning-banner';
        warningBanner.innerHTML = `
            <div class="warning-content">
                <span class="warning-icon">⚠️</span>
                <span class="warning-text">Security issues detected on this page</span>
                <button class="warning-details">Details</button>
                <button class="warning-close">×</button>
            </div>
        `;

        this.addWarningStyles();
        document.body.insertBefore(warningBanner, document.body.firstChild);

        // Add event listeners
        warningBanner.querySelector('.warning-close').onclick = () => {
            warningBanner.remove();
        };

        warningBanner.querySelector('.warning-details').onclick = () => {
            alert(`Security warnings detected:\n\n${warnings.join('\n')}`);
        };
    }

    addOverlayStyles() {
        if (document.getElementById('https-shield-styles')) return;

        const styles = document.createElement('style');
        styles.id = 'https-shield-styles';
        styles.textContent = `
            #https-shield-overlay {
                position: fixed;
                top: 20px;
                right: 20px;
                width: 350px;
                background: white;
                border: 2px solid #e74c3c;
                border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                z-index: 10000;
                font-family: Arial, sans-serif;
                display: none;
            }
            
            .shield-overlay-content {
                padding: 0;
            }
            
            .shield-header {
                background: #34495e;
                color: white;
                padding: 12px 16px;
                display: flex;
                align-items: center;
                justify-content: space-between;
                border-radius: 6px 6px 0 0;
            }
            
            .shield-title {
                font-weight: bold;
                margin-left: 8px;
            }
            
            .shield-close {
                background: none;
                border: none;
                color: white;
                font-size: 18px;
                cursor: pointer;
                padding: 0;
                width: 24px;
                height: 24px;
            }
            
            .shield-body {
                padding: 16px;
            }
            
            .risk-indicator {
                text-align: center;
                margin-bottom: 16px;
            }
            
            .risk-score {
                font-size: 24px;
                font-weight: bold;
                color: #e74c3c;
            }
            
            .risk-level {
                font-size: 14px;
                font-weight: bold;
                padding: 4px 8px;
                border-radius: 4px;
                margin-top: 8px;
                display: inline-block;
            }
            
            .risk-level.risk-low {
                background: #2ecc71;
                color: white;
            }
            
            .risk-level.risk-medium {
                background: #f39c12;
                color: white;
            }
            
            .risk-level.risk-high {
                background: #e74c3c;
                color: white;
            }
            
            .risk-details {
                margin-bottom: 16px;
            }
            
            .risk-message {
                margin-bottom: 12px;
                font-size: 14px;
                color: #555;
            }
            
            .risk-recommendations {
                margin: 0;
                padding-left: 20px;
                font-size: 13px;
                color: #666;
            }
            
            .shield-actions {
                display: flex;
                gap: 8px;
            }
            
            .shield-actions button {
                flex: 1;
                padding: 8px 12px;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-size: 13px;
            }
            
            .btn-primary {
                background: #3498db;
                color: white;
            }
            
            .btn-secondary {
                background: #95a5a6;
                color: white;
            }
        `;

        document.head.appendChild(styles);
    }

    addWarningStyles() {
        if (document.getElementById('https-shield-warning-styles')) return;

        const styles = document.createElement('style');
        styles.id = 'https-shield-warning-styles';
        styles.textContent = `
            #https-shield-warning-banner {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                background: #e74c3c;
                color: white;
                z-index: 10001;
                font-family: Arial, sans-serif;
            }
            
            .warning-content {
                display: flex;
                align-items: center;
                padding: 12px 16px;
                gap: 12px;
            }
            
            .warning-text {
                flex: 1;
                font-weight: bold;
            }
            
            .warning-details, .warning-close {
                background: rgba(255,255,255,0.2);
                border: none;
                color: white;
                padding: 6px 12px;
                border-radius: 4px;
                cursor: pointer;
                font-size: 12px;
            }
            
            .warning-close {
                width: 28px;
                height: 28px;
                border-radius: 50%;
                padding: 0;
            }
        `;

        document.head.appendChild(styles);
    }

    setupMutationObserver() {
        // Watch for dynamic content changes that might indicate new warnings
        const observer = new MutationObserver((mutations) => {
            let shouldRecheck = false;
            
            mutations.forEach((mutation) => {
                // Check if any new nodes were added that might contain warnings
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        const element = node;
                        // Check if the added element matches any warning patterns
                        this.warningDetectors.forEach(detector => {
                            if (element.matches && element.matches(detector.selector)) {
                                shouldRecheck = true;
                            }
                        });
                    }
                });
            });
            
            if (shouldRecheck) {
                setTimeout(() => this.runWarningDetection(), 100);
            }
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    handleMessage(message, sender, sendResponse) {
        switch (message.type) {
            case 'HTTP_SITE_DETECTED':
                this.handleHTTPSite(message.url);
                sendResponse({ success: true });
                break;
                
            case 'RUN_WARNING_CHECK':
                this.runWarningDetection();
                sendResponse({ success: true });
                break;
                
            default:
                console.log('Unknown message type:', message.type);
                sendResponse({ success: false, error: 'Unknown message type' });
        }
    }
}

// Initialize content script when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        new HTTPSShieldContent();
    });
} else {
    new HTTPSShieldContent();
}