// HTTPS Shield Extension - Background Service Worker with HTTP Interception
// Uses declarativeNetRequest to intercept HTTP requests BEFORE Chrome's HTTPS-only warning

class HTTPSShieldBackground {
    constructor() {
        this.bypassedDomains = new Map(); // Track temporarily allowed domains
        this.pendingNavigations = new Map(); // Track pending HTTP navigations
        this.setupEventListeners();
        this.initializeExtension();
    }

    // Check if a domain should be intercepted (not local/private)
    shouldInterceptDomain(hostname) {
        return !['localhost', '127.0.0.1', '[::1]'].includes(hostname) && 
               !hostname.match(/^192\.168\./) && 
               !hostname.match(/^10\./) && 
               !hostname.match(/^172\.(1[6-9]|2[0-9]|3[01])\./) &&
               !hostname.endsWith('.local') &&
               !hostname.endsWith('.localhost');
    }

    setupEventListeners() {
        // Extension installation
        chrome.runtime.onInstalled.addListener(async (details) => {
            console.log('HTTPS Shield installed:', details.reason);
            await this.handleInstallation(details);
            await this.setupInterceptionRules();
        });

        // Browser startup - re-establish intercept rules
        chrome.runtime.onStartup.addListener(async () => {
            console.log('HTTPS Shield starting up...');
            await this.setupInterceptionRules();
            this.bypassedDomains.clear(); // Clear any stale bypass data
        });

        // Message handling
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
            this.handleMessage(message, sender, sendResponse);
            return true; // Keep message channel open
        });

        // Clean up bypass list when tabs are closed
        chrome.tabs.onRemoved.addListener((tabId) => {
            // Clean up any bypasses associated with this tab
            this.cleanupTabBypasses(tabId);
        });

        // Periodically clean up old bypass rules
        setInterval(async () => {
            const now = Date.now();
            for (const [domain, bypass] of this.bypassedDomains) {
                if (now - bypass.timestamp > 30 * 60 * 1000) {
                    await this.removeBypass(domain);
                }
            }
        }, 5 * 60 * 1000); // Check every 5 minutes

        // Early navigation detection with immediate redirect
        chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
            if (details.frameId === 0 && details.url.startsWith('http://')) {
                const url = new URL(details.url);
                
                // Only intercept public domains, not local/private ones
                if (this.shouldInterceptDomain(url.hostname)) {
                    console.log('HTTP navigation detected, attempting immediate redirect:', details.url);
                    
                    // Store pending navigation
                    this.pendingNavigations.set(details.tabId, {
                        url: details.url,
                        timestamp: Date.now()
                    });
                    
                    // Immediately redirect to our risk assessment page
                    const riskAssessmentUrl = chrome.runtime.getURL(
                        `/src/pages/risk-assessment.html?target=${encodeURIComponent(details.url)}&intercepted=true`
                    );
                    
                    try {
                        await chrome.tabs.update(details.tabId, { url: riskAssessmentUrl });
                        console.log('Successfully redirected to risk assessment page');
                    } catch (error) {
                        console.error('Failed to redirect immediately:', error);
                    }
                } else {
                    console.log('Skipping local/private domain:', url.hostname);
                }
            }
        });
        

        // Monitor for Chrome's HTTPS-Only warning page and HTTP URLs
        chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
            // Case 1: Chrome's error page detected
            if (changeInfo.url && changeInfo.url.includes('chrome-error://chromewebdata/')) {
                console.log('Chrome error page detected:', changeInfo.url);
                const pending = this.pendingNavigations.get(tabId);
                if (pending && Date.now() - pending.timestamp < 3000) {
                    // Quickly redirect to our warning page
                    console.log('Chrome HTTPS-Only warning detected, redirecting to our page');
                    chrome.tabs.update(tabId, {
                        url: chrome.runtime.getURL(
                            `/src/pages/risk-assessment.html?target=${encodeURIComponent(pending.url)}&intercepted=true`
                        )
                    });
                    this.pendingNavigations.delete(tabId);
                }
            }
            
        });
    }

    async setupInterceptionRules() {
        console.log('Setting up bypass rule management...');
        
        try {
            // Clean up any old non-bypass rules
            const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
            const oldInterceptRules = existingRules.filter(rule => rule.id < 10000);
            
            if (oldInterceptRules.length > 0) {
                const rulesToRemove = oldInterceptRules.map(rule => rule.id);
                await chrome.declarativeNetRequest.updateDynamicRules({
                    removeRuleIds: rulesToRemove
                });
                console.log('Removed old dynamic intercept rules');
            }
            
            // Log current bypass rules
            const bypassRules = existingRules.filter(rule => rule.id >= 10000);
            console.log(`Active bypass rules: ${bypassRules.length}`);
            
            console.log('HTTP interception using webNavigation API');
            
        } catch (error) {
            console.error('Error setting up interception rules:', error);
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

                case 'allowHttpOnce':
                    // Use sender tab ID if available, otherwise use provided tabId
                    const effectiveTabId = sender.tab?.id || message.tabId;
                    await this.allowHttpDomainOnce(message.url, effectiveTabId);
                    sendResponse({ success: true });
                    break;


                case 'closeTab':
                    if (message.tabId) {
                        chrome.tabs.remove(parseInt(message.tabId));
                    }
                    sendResponse({ success: true });
                    break;

                case 'openRiskAssessment':
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

    async allowHttpDomainOnce(url, tabId) {
        try {
            const urlObj = new URL(url);
            const domain = urlObj.hostname;
            
            console.log(`Temporarily allowing HTTP for ${domain} on tab ${tabId}`);
            
            // Generate unique rule ID
            const ruleId = 10000 + Date.now() % 90000;
            
            // Create a regex pattern that matches the specific domain
            // Escape special regex characters in the domain
            const escapedDomain = domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            const regexPattern = `^http://${escapedDomain}(/.*)?(\\\?.*)?$`;
            
            console.log(`Creating bypass rule with pattern: ${regexPattern}`);
            
            // Create bypass rule with high priority
            const bypassRule = {
                id: ruleId,
                priority: 2147483647, // Maximum priority
                action: { type: 'allow' },
                condition: {
                    regexFilter: regexPattern,
                    resourceTypes: ['main_frame']
                }
            };
            
            await chrome.declarativeNetRequest.updateDynamicRules({
                addRules: [bypassRule]
            });
            
            console.log(`Bypass rule ${ruleId} created successfully`);
            
            // Track the bypass
            this.bypassedDomains.set(domain, {
                ruleId,
                tabId,
                timestamp: Date.now()
            });
            
            // Remove bypass after 30 minutes
            setTimeout(async () => {
                await this.removeBypass(domain);
            }, 30 * 60 * 1000);
            
            // Add a small delay to ensure the rule is processed by Chrome
            setTimeout(() => {
                // Navigate to the HTTP URL
                if (tabId) {
                    console.log(`Navigating tab ${tabId} to ${url} after bypass rule is active`);
                    chrome.tabs.update(tabId, { url: url }, (tab) => {
                        if (chrome.runtime.lastError) {
                            console.error('Navigation error:', chrome.runtime.lastError);
                        } else {
                            console.log('Navigation initiated successfully');
                        }
                    });
                } else {
                    console.log('No tab ID provided, letting page handle navigation');
                }
            }, 100); // 100ms delay to ensure rule is active
            
        } catch (error) {
            console.error('Error allowing HTTP domain:', error);
        }
    }

    async removeBypass(domain) {
        const bypass = this.bypassedDomains.get(domain);
        if (bypass) {
            try {
                await chrome.declarativeNetRequest.updateDynamicRules({
                    removeRuleIds: [bypass.ruleId]
                });
                this.bypassedDomains.delete(domain);
                console.log(`Removed bypass for ${domain}`);
            } catch (error) {
                console.error('Error removing bypass:', error);
            }
        }
    }

    cleanupTabBypasses(tabId) {
        // Remove any bypasses associated with closed tab
        for (const [domain, bypass] of this.bypassedDomains) {
            if (bypass.tabId === tabId) {
                this.removeBypass(domain);
            }
        }
    }

    async analyzeURL(url) {
        console.log('Analyzing URL:', url);
        
        try {
            const urlObj = new URL(url);
            const isHTTP = urlObj.protocol === 'http:';
            
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
                details.push('Cannot verify site authenticity');
                advancedDetails.securityIssues.push('HTTP protocol lacks encryption');
            }

            // Check for suspicious patterns
            if (urlObj.hostname.includes('-')) {
                riskScore += 10;
                details.push('Domain contains hyphens (common in phishing)');
                advancedDetails.securityIssues.push('Suspicious domain pattern');
            }

            // Check for excessive subdomains
            if (urlObj.hostname.split('.').length > 3) {
                riskScore += 15;
                advancedDetails.securityIssues.push('Excessive subdomain depth');
            }

            // Non-standard ports
            if (urlObj.port && urlObj.port !== '80' && urlObj.port !== '443') {
                riskScore += 20;
                details.push(`Non-standard port ${urlObj.port} detected`);
                advancedDetails.securityIssues.push(`Service on port ${urlObj.port}`);
            }

            // Mock domain age check (in production, this would use real data)
            const domainAge = Math.floor(Math.random() * 365 * 5);
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
            showNotifications: true,
            httpsOnlyInterception: true
        };

        // Load or initialize settings
        const result = await chrome.storage.sync.get(['settings']);
        if (!result.settings) {
            await chrome.storage.sync.set({ settings: defaultSettings });
        }

        // CRITICAL: Always ensure interception rules are active on initialization
        // This handles cases where the extension was already installed but Chrome restarted
        console.log('Initializing HTTPS Shield - checking interception rules...');
        await this.setupInterceptionRules();
        
        console.log('HTTPS Shield Background initialized with interception');
    }

    async handleInstallation(details) {
        if (details.reason === 'install') {
            // First-time installation
            chrome.tabs.create({
                url: chrome.runtime.getURL('/src/pages/welcome.html')
            });
        }
        // Note: setupInterceptionRules is called after this in the onInstalled listener
    }

    async getSettings() {
        const result = await chrome.storage.sync.get(['settings']);
        return result.settings || {};
    }
}

// Initialize the background service worker
new HTTPSShieldBackground();