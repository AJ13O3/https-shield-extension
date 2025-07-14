// HTTPS Shield Extension - Popup Script
// Manages extension popup interface and user settings

class HTTPSShieldPopup {
    constructor() {
        this.currentTab = null;
        this.settings = null;
        this.stats = null;
        this.init();
    }

    async init() {
        console.log('HTTPS Shield Popup initializing...');
        
        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.setup());
        } else {
            this.setup();
        }
    }

    async setup() {
        try {
            // Show loading
            this.showLoading(true);
            
            // Load current tab info
            await this.loadCurrentTab();
            
            // Load settings and stats
            await this.loadSettings();
            await this.loadStats();
            
            // Set up UI
            this.setupEventListeners();
            this.updateUI();
            
            // Hide loading
            this.showLoading(false);
            
            console.log('HTTPS Shield Popup ready');
        } catch (error) {
            console.error('Error setting up popup:', error);
            this.showError('Failed to load extension data');
        }
    }

    async loadCurrentTab() {
        // Get current active tab
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        this.currentTab = tabs[0];
        
        // Update URL display
        const urlElement = document.getElementById('current-url');
        if (this.currentTab?.url) {
            urlElement.textContent = this.currentTab.url;
            
            // Get risk assessment for current URL
            if (this.currentTab.url.startsWith('http://')) {
                await this.analyzeCurrentPage();
            } else {
                this.updateRiskDisplay({ riskScore: 0, riskLevel: 'low' });
            }
        } else {
            urlElement.textContent = 'No active tab';
        }
    }

    async analyzeCurrentPage() {
        try {
            const response = await chrome.runtime.sendMessage({
                type: 'ANALYZE_URL',
                url: this.currentTab.url
            });
            
            if (response.success) {
                this.updateRiskDisplay(response.data);
            }
        } catch (error) {
            console.error('Error analyzing current page:', error);
        }
    }

    updateRiskDisplay(riskData) {
        const scoreElement = document.getElementById('risk-score');
        const levelElement = document.getElementById('risk-level');
        
        scoreElement.textContent = riskData.riskScore || '--';
        levelElement.textContent = riskData.riskLevel || 'Unknown';
        levelElement.className = `risk-level ${riskData.riskLevel || ''}`;
    }

    async loadSettings() {
        try {
            const response = await chrome.runtime.sendMessage({
                type: 'GET_SETTINGS'
            });
            
            if (response.success) {
                this.settings = response.data;
            } else {
                // Use defaults
                this.settings = {
                    enabled: true,
                    riskThreshold: 50,
                    showNotifications: true
                };
            }
        } catch (error) {
            console.error('Error loading settings:', error);
            this.settings = {
                enabled: true,
                riskThreshold: 50,
                showNotifications: true
            };
        }
    }

    async loadStats() {
        try {
            // Get events from storage for today's stats
            const today = new Date().toDateString();
            const result = await chrome.storage.local.get(['events']);
            const events = result.events || [];
            
            // Filter events for today
            const todayEvents = events.filter(event => 
                new Date(event.timestamp).toDateString() === today
            );
            
            // Calculate stats
            this.stats = {
                sitesVisited: new Set(todayEvents
                    .filter(e => e.type === 'http_site_visited')
                    .map(e => e.url)).size,
                warningsShown: todayEvents
                    .filter(e => e.type === 'http_site_visited').length,
                httpsRedirects: todayEvents
                    .filter(e => e.type === 'user_action' && e.action === 'find_https_version').length
            };
        } catch (error) {
            console.error('Error loading stats:', error);
            this.stats = {
                sitesVisited: 0,
                warningsShown: 0,
                httpsRedirects: 0
            };
        }
    }

    setupEventListeners() {
        // Extension enabled toggle
        const enabledToggle = document.getElementById('extension-enabled');
        enabledToggle.checked = this.settings.enabled;
        enabledToggle.addEventListener('change', (e) => {
            this.updateSetting('enabled', e.target.checked);
        });

        // Notifications toggle
        const notificationsToggle = document.getElementById('notifications-enabled');
        notificationsToggle.checked = this.settings.showNotifications;
        notificationsToggle.addEventListener('change', (e) => {
            this.updateSetting('showNotifications', e.target.checked);
        });

        // Risk threshold slider
        const riskSlider = document.getElementById('risk-threshold');
        const thresholdValue = document.getElementById('threshold-value');
        riskSlider.value = this.settings.riskThreshold;
        thresholdValue.textContent = this.settings.riskThreshold;
        
        riskSlider.addEventListener('input', (e) => {
            const value = parseInt(e.target.value);
            thresholdValue.textContent = value;
            this.updateSetting('riskThreshold', value);
        });

        // View history button
        document.getElementById('view-history').addEventListener('click', () => {
            this.viewHistory();
        });

        // Clear data button
        document.getElementById('clear-data').addEventListener('click', () => {
            this.clearData();
        });
    }

    updateUI() {
        // Update stats display
        document.getElementById('sites-visited').textContent = this.stats.sitesVisited;
        document.getElementById('warnings-shown').textContent = this.stats.warningsShown;
        document.getElementById('https-redirects').textContent = this.stats.httpsRedirects;
    }

    async updateSetting(key, value) {
        try {
            this.settings[key] = value;
            
            const response = await chrome.runtime.sendMessage({
                type: 'UPDATE_SETTINGS',
                settings: this.settings
            });
            
            if (!response.success) {
                console.error('Failed to update settings');
            }
        } catch (error) {
            console.error('Error updating setting:', error);
        }
    }

    async viewHistory() {
        try {
            // Get all events
            const result = await chrome.storage.local.get(['events']);
            const events = result.events || [];
            
            // Create a simple history view
            const historyData = events
                .filter(e => e.type === 'http_site_visited')
                .slice(-10) // Last 10 events
                .map(e => ({
                    url: e.url,
                    timestamp: new Date(e.timestamp).toLocaleString(),
                    riskScore: e.riskScore
                }));
            
            // For now, just log to console (in Week 3 we'll create a proper history page)
            console.table(historyData);
            alert(`Recent history (${historyData.length} entries) logged to console`);
            
        } catch (error) {
            console.error('Error viewing history:', error);
            alert('Error loading history');
        }
    }

    async clearData() {
        if (confirm('Clear all stored data? This action cannot be undone.')) {
            try {
                await chrome.storage.local.clear();
                
                // Reset stats
                this.stats = {
                    sitesVisited: 0,
                    warningsShown: 0,
                    httpsRedirects: 0
                };
                
                this.updateUI();
                alert('Data cleared successfully');
                
            } catch (error) {
                console.error('Error clearing data:', error);
                alert('Error clearing data');
            }
        }
    }

    showLoading(show) {
        const loadingElement = document.getElementById('loading');
        loadingElement.style.display = show ? 'flex' : 'none';
    }

    showError(message) {
        // Simple error display - in production we'd have a proper error UI
        console.error(message);
        alert(`Error: ${message}`);
    }
}

// Initialize popup when DOM is ready
new HTTPSShieldPopup();