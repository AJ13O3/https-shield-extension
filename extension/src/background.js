// HTTPS Shield Extension - Background Service Worker
// Handles extension lifecycle, API calls, and message routing

class HTTPSShieldBackground {
    constructor() {
        this.setupEventListeners();
        this.initializeExtension();
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
    }

    async initializeExtension() {
        // Set up default settings
        const defaultSettings = {
            enabled: true,
            riskThreshold: 50,
            showNotifications: true,
            apiEndpoint: 'https://api.https-shield.com/v1' // Placeholder for Week 4
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
            this.showWelcomeNotification();
        } else if (details.reason === 'update') {
            // Extension update
            console.log('Extension updated');
        }
    }

    async handleMessage(message, sender, sendResponse) {
        try {
            switch (message.type) {
                case 'ANALYZE_URL':
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

                default:
                    console.warn('Unknown message type:', message.type);
                    sendResponse({ success: false, error: 'Unknown message type' });
            }
        } catch (error) {
            console.error('Error handling message:', error);
            sendResponse({ success: false, error: error.message });
        }
    }

    async analyzeURL(url) {
        // Mock implementation for Week 2
        // Will integrate with AWS Lambda in Week 4
        console.log('Analyzing URL:', url);
        
        // Simple heuristic analysis for now
        const isHTTP = url.startsWith('http://');
        const hasCommonPorts = url.includes(':8080') || url.includes(':3000');
        
        let riskScore = 0;
        if (isHTTP) riskScore += 40;
        if (hasCommonPorts) riskScore += 20;
        
        // Add some randomness for testing
        riskScore += Math.floor(Math.random() * 30);
        
        return {
            url,
            riskScore: Math.min(riskScore, 100),
            riskLevel: this.getRiskLevel(riskScore),
            timestamp: new Date().toISOString(),
            recommendations: this.getRecommendations(riskScore)
        };
    }

    getRiskLevel(score) {
        if (score >= 70) return 'high';
        if (score >= 40) return 'medium';
        return 'low';
    }

    getRecommendations(score) {
        if (score >= 70) {
            return [
                'Avoid entering sensitive information',
                'Consider if you really need to visit this site',
                'Look for HTTPS alternatives'
            ];
        } else if (score >= 40) {
            return [
                'Exercise caution with this site',
                'Verify the URL is correct',
                'Avoid entering passwords or personal data'
            ];
        } else {
            return [
                'Site appears relatively safe',
                'Still verify the URL is correct',
                'Look for HTTPS in the address bar'
            ];
        }
    }

    async handleTabUpdate(tabId, tab) {
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
            iconUrl: 'icons/icon-48.png',
            title: 'HTTPS Shield Installed',
            message: 'Your AI-powered HTTPS security assistant is ready!'
        });
    }
}

// Initialize the background service worker
new HTTPSShieldBackground();