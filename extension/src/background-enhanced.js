// HTTPS Shield Extension - Enhanced Background Service Worker
// Handles pre-warning interception and HTTP request blocking

class HTTPSShieldBackground {
    constructor() {
        this.httpBypassList = new Map(); // Temporary bypass for user-allowed HTTP sites
        this.httpsOnlyModeEnabled = true; // Assume enabled by default
        this.pendingNavigations = new Map(); // Track navigation flows
        
        this.setupEventListeners();
        this.initializeExtension();
        this.setupWebRequestInterception();
    }

    setupEventListeners() {
        // Extension installation and startup
        chrome.runtime.onInstalled.addListener((details) => {
            console.log('HTTPS Shield installed:', details.reason);
            this.handleInstallation(details);
        });

        // Message handling from content scripts and popup
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
            this.handleMessage(message, sender, sendResponse);
            return true; // Keep message channel open for async responses
        });

        // Tab updates to detect navigation
        chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
            if (changeInfo.status === 'complete' && tab.url) {
                this.handleTabUpdate(tabId, tab);
            }
        });

        // Clean up bypass list when tabs are closed
        chrome.tabs.onRemoved.addListener((tabId) => {
            this.httpBypassList.delete(tabId);
            this.pendingNavigations.delete(tabId);
        });
    }

    setupWebRequestInterception() {
        // Intercept HTTP requests before they happen
        chrome.webRequest.onBeforeRequest.addListener(
            (details) => this.handleBeforeRequest(details),
            {
                urls: ["http://*/*"],
                types: ["main_frame"]
            },
            ["blocking"]
        );

        // Monitor navigation errors (including HTTPS-only mode blocks)
        chrome.webNavigation.onErrorOccurred.addListener((details) => {
            if (details.frameId === 0) { // Main frame only
                this.handleNavigationError(details);
            }
        });
    }

    handleBeforeRequest(details) {
        // Skip if extension is disabled
        const isEnabled = this.isExtensionEnabled();
        if (!isEnabled) {
            return {};
        }

        // Check if this domain is in the bypass list for this tab
        const url = new URL(details.url);
        const tabBypass = this.httpBypassList.get(details.tabId);
        if (tabBypass && tabBypass.has(url.hostname)) {
            console.log('Allowing bypassed HTTP request:', url.hostname);
            return {};
        }

        // Skip local addresses
        if (this.isLocalAddress(url.hostname)) {
            return {};
        }

        // Check if we should intercept this request
        if (this.shouldInterceptHTTPRequest(url)) {
            console.log('Intercepting HTTP request:', details.url);
            
            // Store the pending navigation
            this.pendingNavigations.set(details.tabId, {
                originalUrl: details.url,
                timestamp: Date.now()
            });

            // Redirect to our risk assessment page
            const assessmentUrl = chrome.runtime.getURL(
                `/src/pages/risk-assessment.html?target=${encodeURIComponent(details.url)}&tabId=${details.tabId}`
            );
            
            return { redirectUrl: assessmentUrl };
        }

        return {};
    }

    handleNavigationError(details) {
        // Check if this is an HTTPS-only mode error
        if (details.error === 'net::ERR_CONNECTION_REFUSED' || 
            details.error === 'net::ERR_SSL_PROTOCOL_ERROR') {
            
            const pending = this.pendingNavigations.get(details.tabId);
            if (pending && Date.now() - pending.timestamp < 5000) {
                // This might be related to our interception
                console.log('Navigation error detected:', details.error);
            }
        }
    }

    async handleMessage(message, sender, sendResponse) {
        try {
            switch (message.type || message.action) {
                case 'ANALYZE_URL':
                case 'analyzeRisk':
                    const analysis = await this.analyzeURL(message.url);
                    sendResponse({ success: true, data: analysis });
                    break;

                case 'GET_SETTINGS':
                    const settings = await this.getSettings();
                    sendResponse({ success: true, data: settings });
                    break;

                case 'UPDATE_SETTINGS':
                    await this.updateSettings(message.settings);
                    sendResponse({ success: true });
                    break;

                case 'LOG_EVENT':
                    await this.logEvent(message.event, sender.tab);
                    sendResponse({ success: true });
                    break;

                case 'addHttpBypass':
                    this.addHttpBypass(message.url, message.tabId);
                    sendResponse({ success: true });
                    break;

                case 'closeTab':
                    if (message.tabId) {
                        chrome.tabs.remove(parseInt(message.tabId));
                    }
                    sendResponse({ success: true });
                    break;

                case 'checkHttpsOnlyMode':
                    sendResponse({ 
                        success: true, 
                        enabled: this.httpsOnlyModeEnabled 
                    });
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

    addHttpBypass(url, tabId) {
        try {
            const urlObj = new URL(url);
            const hostname = urlObj.hostname;
            
            // Get or create bypass set for this tab
            if (!this.httpBypassList.has(tabId)) {
                this.httpBypassList.set(tabId, new Set());
            }
            
            // Add hostname to bypass list
            this.httpBypassList.get(tabId).add(hostname);
            console.log(`Added HTTP bypass for ${hostname} in tab ${tabId}`);
            
            // Remove bypass after 30 minutes
            setTimeout(() => {
                const tabBypass = this.httpBypassList.get(tabId);
                if (tabBypass) {
                    tabBypass.delete(hostname);
                    if (tabBypass.size === 0) {
                        this.httpBypassList.delete(tabId);
                    }
                }
            }, 30 * 60 * 1000);
            
        } catch (error) {
            console.error('Error adding HTTP bypass:', error);
        }
    }

    shouldInterceptHTTPRequest(url) {
        // Don't intercept if HTTPS-only mode is detected as disabled
        if (!this.httpsOnlyModeEnabled) {
            return false;
        }

        // Always intercept non-local HTTP requests when HTTPS-only mode is enabled
        return true;
    }

    isLocalAddress(hostname) {
        // Check for local addresses that should not be intercepted
        const localPatterns = [
            'localhost',
            '127.0.0.1',
            '[::1]',
            /^192\.168\.\d+\.\d+$/,
            /^10\.\d+\.\d+\.\d+$/,
            /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/,
            /\.local$/,
            /\.localhost$/
        ];

        return localPatterns.some(pattern => {
            if (typeof pattern === 'string') {
                return hostname === pattern;
            }
            return pattern.test(hostname);
        });
    }

    async isExtensionEnabled() {
        const settings = await this.getSettings();
        return settings?.enabled !== false;
    }

    async analyzeURL(url) {
        console.log('Analyzing URL:', url);
        
        try {
            const urlObj = new URL(url);
            const isHTTP = urlObj.protocol === 'http:';
            
            // Enhanced risk analysis
            let riskScore = 0;
            let details = [];
            let advancedDetails = {
                domainInfo: {},
                securityIssues: [],
                reputation: {}
            };

            // Base risk for HTTP
            if (isHTTP) {
                riskScore += 50;
                details.push('No encryption for data transmission');
                details.push('Vulnerable to man-in-the-middle attacks');
                advancedDetails.securityIssues.push('HTTP protocol lacks encryption');
            }

            // Check for suspicious patterns
            if (urlObj.hostname.includes('-')) {
                riskScore += 10;
                advancedDetails.securityIssues.push('Domain contains hyphens (common in phishing)');
            }

            if (urlObj.hostname.split('.').length > 3) {
                riskScore += 15;
                advancedDetails.securityIssues.push('Suspicious subdomain structure');
            }

            // Check for non-standard ports
            if (urlObj.port && urlObj.port !== '80' && urlObj.port !== '443') {
                riskScore += 20;
                details.push(`Non-standard port ${urlObj.port} detected`);
                advancedDetails.securityIssues.push(`Service running on port ${urlObj.port}`);
            }

            // Mock domain age check
            const domainAge = Math.floor(Math.random() * 365 * 5); // Random age up to 5 years
            if (domainAge < 30) {
                riskScore += 25;
                details.push('Recently registered domain');
                advancedDetails.domainInfo.age = `${domainAge} days`;
            } else {
                advancedDetails.domainInfo.age = `${Math.floor(domainAge / 365)} years`;
            }

            // Ensure score is within bounds
            riskScore = Math.min(Math.max(riskScore, 0), 100);

            return {
                url,
                riskScore,
                riskLevel: this.getRiskLevel(riskScore),
                details,
                advancedDetails,
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
        if (score >= 80) {
            return [
                'Do not enter any sensitive information',
                'Avoid this site if possible',
                'Look for secure HTTPS alternatives'
            ];
        } else if (score >= 60) {
            return [
                'Exercise extreme caution',
                'Verify the site is legitimate',
                'Avoid entering passwords or payment info'
            ];
        } else if (score >= 40) {
            return [
                'Be cautious with this site',
                'Double-check the URL',
                'Limit sensitive data sharing'
            ];
        } else {
            return [
                'Site risk appears manageable',
                'Still verify the URL is correct',
                'Prefer HTTPS when available'
            ];
        }
    }

    async handleTabUpdate(tabId, tab) {
        // Clean up any pending navigation for this tab
        this.pendingNavigations.delete(tabId);
        
        // Check if tab is loading HTTP site
        if (tab.url && tab.url.startsWith('http://')) {
            // Notify content script about potential security concern
            try {
                await chrome.tabs.sendMessage(tabId, {
                    type: 'HTTP_SITE_DETECTED',
                    url: tab.url
                });
            } catch (error) {
                // Content script may not be ready yet
                console.log('Content script not ready for tab:', tabId);
            }
        }
    }

    async initializeExtension() {
        // Set up default settings
        const defaultSettings = {
            enabled: true,
            riskThreshold: 50,
            showNotifications: true,
            httpsOnlyInterception: true,
            apiEndpoint: 'https://api.https-shield.com/v1' // Placeholder for Week 4
        };

        // Load or initialize settings
        const result = await chrome.storage.sync.get(['settings']);
        if (!result.settings) {
            await chrome.storage.sync.set({ settings: defaultSettings });
        }

        // Try to detect if HTTPS-only mode is enabled
        this.detectHttpsOnlyMode();

        console.log('HTTPS Shield Background Enhanced initialized');
    }

    async detectHttpsOnlyMode() {
        // This is a heuristic approach since we can't directly access Chrome settings
        // We'll refine this based on observed behavior
        try {
            // Check if we've seen HTTPS-only warnings before
            const result = await chrome.storage.local.get(['httpsOnlyModeDetected']);
            if (result.httpsOnlyModeDetected !== undefined) {
                this.httpsOnlyModeEnabled = result.httpsOnlyModeDetected;
            }
        } catch (error) {
            console.error('Error detecting HTTPS-only mode:', error);
        }
    }

    handleInstallation(details) {
        if (details.reason === 'install') {
            // First-time installation
            this.showWelcomeNotification();
            
            // Open onboarding page only on first install
            chrome.tabs.create({
                url: chrome.runtime.getURL('/src/pages/welcome.html')
            });
        } else if (details.reason === 'update') {
            // Extension update
            console.log('Extension updated to enhanced version');
        }
    }

    async getSettings() {
        const result = await chrome.storage.sync.get(['settings']);
        return result.settings;
    }

    async updateSettings(newSettings) {
        await chrome.storage.sync.set({ settings: newSettings });
    }

    async logEvent(eventData, tab) {
        // Store event for analytics (local storage for now)
        const timestamp = new Date().toISOString();
        const event = {
            ...eventData,
            timestamp,
            tabId: tab?.id,
            url: tab?.url
        };

        // Get existing events
        const result = await chrome.storage.local.get(['events']);
        const events = result.events || [];
        
        // Add new event (keep last 1000 events)
        events.push(event);
        if (events.length > 1000) {
            events.shift();
        }

        await chrome.storage.local.set({ events });
    }

    showWelcomeNotification() {
        // Show welcome notification on first install
        chrome.notifications?.create({
            type: 'basic',
            iconUrl: chrome.runtime.getURL('/icons/icon-48.png'),
            title: 'HTTPS Shield Installed',
            message: 'Your AI-powered HTTPS security assistant is now protecting you!'
        });
    }
}

// Initialize the enhanced background service worker
new HTTPSShieldBackground();