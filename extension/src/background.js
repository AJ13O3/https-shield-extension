// HTTPS Shield Extension - Background Service Worker (MV3)
// Simple implementation that works with Chrome's limitations

class HTTPSShieldBackground {
    constructor() {
        this.setupEventListeners();
        this.initializeExtension();
    }

    setupEventListeners() {
        // Extension installation
        chrome.runtime.onInstalled.addListener((details) => {
            console.log('HTTPS Shield installed:', details.reason);
            this.handleInstallation(details);
        });

        // Message handling
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
            this.handleMessage(message, sender, sendResponse);
            return true; // Keep message channel open
        });

        // Monitor tab navigation to detect HTTP sites
        chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
            if (changeInfo.status === 'loading' && tab.url) {
                this.checkForHTTPSite(tabId, tab);
            }
        });

        // Monitor navigation errors to detect HTTPS-only blocks
        chrome.webNavigation.onErrorOccurred.addListener((details) => {
            if (details.frameId === 0) { // Main frame only
                this.handleNavigationError(details);
            }
        });
    }

    async checkForHTTPSite(tabId, tab) {
        // Check if this is an HTTP site
        if (tab.url.startsWith('http://') && !this.isLocalAddress(tab.url)) {
            console.log('HTTP site detected:', tab.url);
            
            // Store the HTTP URL for the content script
            await chrome.storage.session.set({
                [`tab_${tabId}_http_url`]: tab.url
            });

            // Since we can't block the request in MV3, we'll inject a warning
            // The content script will handle showing the risk assessment
            try {
                await chrome.tabs.sendMessage(tabId, {
                    type: 'HTTP_SITE_LOADING',
                    url: tab.url
                });
            } catch (error) {
                // Content script might not be ready yet
                console.log('Will retry when content script is ready');
            }
        }
    }

    isLocalAddress(url) {
        try {
            const urlObj = new URL(url);
            const hostname = urlObj.hostname;
            
            const localPatterns = [
                'localhost',
                '127.0.0.1',
                '[::1]',
                /^192\.168\.\d+\.\d+$/,
                /^10\.\d+\.\d+\.\d+$/,
                /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/
            ];

            return localPatterns.some(pattern => {
                if (typeof pattern === 'string') {
                    return hostname === pattern;
                }
                return pattern.test(hostname);
            });
        } catch {
            return false;
        }
    }

    async handleMessage(message, sender, sendResponse) {
        try {
            switch (message.type || message.action) {
                case 'analyzeRisk':
                    const analysis = await this.analyzeURL(message.url);
                    sendResponse({ success: true, data: analysis });
                    break;

                case 'GET_SETTINGS':
                    const settings = await this.getSettings();
                    sendResponse({ success: true, data: settings });
                    break;

                case 'closeTab':
                    if (message.tabId) {
                        chrome.tabs.remove(parseInt(message.tabId));
                    }
                    sendResponse({ success: true });
                    break;

                case 'openRiskAssessment':
                    // Open risk assessment in a new tab
                    const assessmentUrl = chrome.runtime.getURL(
                        `/src/pages/risk-assessment.html?target=${encodeURIComponent(message.url)}&tabId=${sender.tab?.id}`
                    );
                    chrome.tabs.create({ url: assessmentUrl });
                    sendResponse({ success: true });
                    break;

                default:
                    console.warn('Unknown message type:', message.type || message.action);
                    sendResponse({ success: false, error: 'Unknown message type' });
            }
        } catch (error) {
            console.error('Error handling message:', error);
            sendResponse({ success: false, error: error.message });
        }
    }

    async analyzeURL(url) {
        console.log('Analyzing URL:', url);
        
        try {
            const urlObj = new URL(url);
            const isHTTP = urlObj.protocol === 'http:';
            
            let riskScore = 0;
            let details = [];

            // Base risk for HTTP
            if (isHTTP) {
                riskScore += 50;
                details.push('No encryption for data transmission');
                details.push('Vulnerable to man-in-the-middle attacks');
                details.push('Cannot verify site authenticity');
            }

            // Check for suspicious patterns
            if (urlObj.hostname.includes('-')) {
                riskScore += 10;
                details.push('Domain contains hyphens (common in phishing)');
            }

            // Non-standard ports
            if (urlObj.port && urlObj.port !== '80' && urlObj.port !== '443') {
                riskScore += 20;
                details.push(`Non-standard port ${urlObj.port} detected`);
            }

            // Ensure score is within bounds
            riskScore = Math.min(Math.max(riskScore, 0), 100);

            return {
                url,
                riskScore,
                riskLevel: this.getRiskLevel(riskScore),
                details,
                timestamp: new Date().toISOString(),
                recommendations: this.getRecommendations(riskScore)
            };
            
        } catch (error) {
            console.error('Error analyzing URL:', error);
            return {
                url,
                riskScore: 75,
                riskLevel: 'high',
                details: ['Error analyzing URL', 'Proceeding with caution advised'],
                timestamp: new Date().toISOString(),
                recommendations: ['Verify the URL manually', 'Proceed with extreme caution']
            };
        }
    }

    getRiskLevel(score) {
        if (score >= 80) return 'critical';
        if (score >= 60) return 'high';
        if (score >= 40) return 'medium';
        return 'low';
    }

    getRecommendations(score) {
        if (score >= 60) {
            return [
                'Do not enter any sensitive information',
                'Avoid this site if possible',
                'Look for secure HTTPS alternatives'
            ];
        } else if (score >= 40) {
            return [
                'Be cautious with this site',
                'Verify the URL is correct',
                'Avoid entering passwords or personal data'
            ];
        } else {
            return [
                'Site appears relatively safe',
                'Still verify the URL is correct',
                'Prefer HTTPS when available'
            ];
        }
    }

    async initializeExtension() {
        // Set up default settings
        const defaultSettings = {
            enabled: true,
            riskThreshold: 50,
            showNotifications: true
        };

        // Load or initialize settings
        const result = await chrome.storage.sync.get(['settings']);
        if (!result.settings) {
            await chrome.storage.sync.set({ settings: defaultSettings });
        }

        console.log('HTTPS Shield Background initialized');
    }

    handleInstallation(details) {
        if (details.reason === 'install') {
            // First-time installation
            chrome.tabs.create({
                url: chrome.runtime.getURL('/src/pages/welcome.html')
            });
        }
    }

    async getSettings() {
        const result = await chrome.storage.sync.get(['settings']);
        return result.settings || {};
    }

    async handleNavigationError(details) {
        console.log('Navigation error:', details);
        
        // Check if this might be an HTTPS-only mode block
        if (details.url.startsWith('http://') && 
            (details.error === 'net::ERR_SSL_PROTOCOL_ERROR' ||
             details.error === 'net::ERR_CONNECTION_REFUSED' ||
             details.error === 'net::ERR_CONNECTION_RESET')) {
            
            console.log('Possible HTTPS-only mode block detected');
            
            // Store the blocked URL
            await chrome.storage.session.set({
                [`blocked_${details.tabId}`]: {
                    url: details.url,
                    timestamp: Date.now()
                }
            });
            
            // Update extension badge
            chrome.action.setBadgeText({ 
                text: '!',
                tabId: details.tabId 
            });
            chrome.action.setBadgeBackgroundColor({ 
                color: '#f44336',
                tabId: details.tabId 
            });
            
            // Show notification
            chrome.notifications.create({
                type: 'basic',
                iconUrl: chrome.runtime.getURL('/icons/icon-48.png'),
                title: 'HTTP Site Blocked',
                message: `Chrome blocked ${new URL(details.url).hostname}. Click the HTTPS Shield icon for risk assessment.`,
                priority: 2
            });
        }
    }
}

// Initialize the background service worker
new HTTPSShieldBackground();