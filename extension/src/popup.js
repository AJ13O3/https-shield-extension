// HTTPS Shield Extension - Settings Dashboard
// Manages extension settings and statistics display

class SettingsManager {
    constructor() {
        this.settings = {
            riskThreshold: 50
        };
        this.stats = null;
        this.init();
    }

    async init() {
        console.log('HTTPS Shield Settings initializing...');
        
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
            
            // Load settings and stats
            await this.loadSettings();
            await this.loadDailyStats();
            
            // Set up UI
            this.setupEventListeners();
            this.updateUI();
            
            // Hide loading
            this.showLoading(false);
            
            console.log('HTTPS Shield Settings ready');
        } catch (error) {
            console.error('Error setting up settings:', error);
            this.showError('Failed to load extension data');
        }
    }

    async loadSettings() {
        try {
            const stored = await chrome.storage.local.get(['settings']);
            if (stored.settings) {
                this.settings = stored.settings;
            }
        } catch (error) {
            console.error('Error loading settings:', error);
        }
    }

    async loadDailyStats() {
        try {
            // Get today's date
            const today = new Date().toDateString();
            
            // Get daily stats from storage
            const stored = await chrome.storage.local.get(['dailyStats']);
            
            if (stored.dailyStats && stored.dailyStats.date === today) {
                this.stats = stored.dailyStats;
            } else {
                // Initialize new daily stats
                this.stats = {
                    date: today,
                    sitesScanned: 0,
                    warningsBlocked: 0,
                    httpsUpgrades: 0
                };
            }
            
            // Also get recent events to calculate real-time stats
            const eventsResult = await chrome.storage.local.get(['events']);
            const events = eventsResult.events || [];
            
            // Calculate today's stats from events
            const todayEvents = events.filter(event => 
                new Date(event.timestamp).toDateString() === today
            );
            
            this.stats = {
                date: today,
                sitesScanned: new Set(todayEvents
                    .filter(e => e.type === 'site_analyzed')
                    .map(e => e.url)).size,
                warningsBlocked: todayEvents
                    .filter(e => e.type === 'warning_shown').length,
                httpsUpgrades: todayEvents
                    .filter(e => e.type === 'https_upgrade').length
            };
            
            // Save updated stats
            await chrome.storage.local.set({ dailyStats: this.stats });
            
        } catch (error) {
            console.error('Error loading daily stats:', error);
            this.stats = {
                sitesScanned: 0,
                warningsBlocked: 0,
                httpsUpgrades: 0
            };
        }
    }

    setupEventListeners() {
        // Risk threshold slider
        const slider = document.getElementById('risk-threshold');
        const thresholdValue = document.getElementById('threshold-value');
        
        slider.value = this.settings.riskThreshold;
        thresholdValue.textContent = this.settings.riskThreshold;
        
        slider.addEventListener('input', (e) => {
            const value = parseInt(e.target.value);
            thresholdValue.textContent = value;
            this.updateThreshold(value);
        });

        // Quick links
        document.getElementById('view-history').addEventListener('click', () => {
            this.handleQuickLink('history');
        });

        document.getElementById('security-guide').addEventListener('click', () => {
            this.handleQuickLink('guide');
        });

        document.getElementById('advanced-settings').addEventListener('click', () => {
            this.handleQuickLink('settings');
        });

        document.getElementById('help-support').addEventListener('click', () => {
            this.handleQuickLink('support');
        });
    }

    updateUI() {
        // Update stats display
        document.getElementById('sites-scanned').textContent = this.stats.sitesScanned || 0;
        document.getElementById('warnings-blocked').textContent = this.stats.warningsBlocked || 0;
        document.getElementById('https-upgrades').textContent = this.stats.httpsUpgrades || 0;
        
        // Update threshold display
        const thresholdValue = document.getElementById('threshold-value');
        thresholdValue.textContent = this.settings.riskThreshold;
    }

    async updateThreshold(value) {
        this.settings.riskThreshold = value;
        await this.saveSettings();
        
        // Notify background script
        chrome.runtime.sendMessage({
            type: 'UPDATE_SETTINGS',
            settings: this.settings
        });
    }

    async saveSettings() {
        try {
            await chrome.storage.local.set({ settings: this.settings });
        } catch (error) {
            console.error('Error saving settings:', error);
        }
    }

    handleQuickLink(action) {
        switch (action) {
            case 'history':
                // Open history page
                chrome.tabs.create({
                    url: chrome.runtime.getURL('src/pages/history.html')
                });
                break;
                
            case 'guide':
                // Open security guide
                chrome.tabs.create({
                    url: 'https://www.google.com/chrome/security/'
                });
                break;
                
            case 'settings':
                // Open advanced settings page
                chrome.tabs.create({
                    url: chrome.runtime.getURL('src/pages/settings.html')
                });
                break;
                
            case 'support':
                // Open help/support page
                chrome.tabs.create({
                    url: 'https://github.com/your-repo/https-shield-extension/issues'
                });
                break;
        }
        
        // Close popup after opening link
        window.close();
    }

    showLoading(show) {
        const loadingElement = document.getElementById('loading');
        if (loadingElement) {
            loadingElement.style.display = show ? 'flex' : 'none';
        }
    }

    showError(message) {
        console.error(message);
        // Could show a toast notification in the future
    }
}

// Check if this popup is being shown as a warning notification
async function checkWarningMode() {
    try {
        // Check for active HTTP session
        const response = await chrome.runtime.sendMessage({
            action: 'getActiveHTTPSession'
        });
        
        if (response && response.session) {
            // Show warning popup instead
            showWarningPopup(response.session);
            return true;
        }
    } catch (error) {
        console.error('Error checking warning mode:', error);
    }
    return false;
}

// Show warning popup for active HTTP session
function showWarningPopup(session) {
    // Replace entire popup content with warning UI
    document.body.innerHTML = `
        <div class="popup-container popup-warning">
            <header class="popup-header">
                <div class="header-content">
                    <span class="header-icon">⚠️</span>
                    <h1 class="header-title">HTTPS Shield - Active Warning</h1>
                </div>
            </header>

            <section class="popup-card">
                <h3 class="card-title">You're on an Insecure Site</h3>
                <div class="risk-summary">
                    <div class="site-url">${session.url}</div>
                    <div class="risk-display">
                        <div class="risk-info">
                            <span class="risk-label">Risk Level:</span>
                            <span class="risk-value ${session.riskLevel.toLowerCase()}">${session.riskLevel} (${session.riskScore}/100)</span>
                        </div>
                        <div class="risk-progress">
                            <div class="risk-progress-fill ${session.riskLevel.toLowerCase()}" style="width: ${session.riskScore}%"></div>
                        </div>
                    </div>
                    
                    <div class="active-risks">
                        <h4 class="active-risks-title">
                            <span>⚠️</span>
                            <span>Active Risks:</span>
                        </h4>
                        <ul class="risks-list">
                            <li>Unencrypted connection</li>
                            <li>Data visible to attackers</li>
                            <li>No identity verification</li>
                        </ul>
                    </div>
                    
                    <div class="session-stats">
                        <div class="stat-item">
                            <span class="stat-label">Time on site:</span>
                            <span class="stat-value" id="session-time">0m 0s</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">Data sent:</span>
                            <span class="stat-value" id="data-sent">~0 KB</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">Forms detected:</span>
                            <span class="stat-value" id="forms-detected">0</span>
                        </div>
                    </div>
                </div>
            </section>

            <div class="action-buttons">
                <button class="btn btn-primary" id="view-analysis">
                    <span>🛡️</span>
                    <span>View Full Analysis</span>
                </button>
                <button class="btn btn-secondary" id="go-back">
                    <span>↩️</span>
                    <span>Go Back</span>
                </button>
            </div>
        </div>
    `;
    
    // Load styles
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = 'styles.css';
    document.head.appendChild(link);
    
    // Set up event listeners
    document.getElementById('view-analysis').addEventListener('click', () => {
        chrome.tabs.create({
            url: chrome.runtime.getURL(`src/pages/risk-assessment.html?target=${encodeURIComponent(session.url)}`)
        });
        window.close();
    });
    
    document.getElementById('go-back').addEventListener('click', () => {
        chrome.tabs.update({ url: 'chrome://newtab/' });
        window.close();
    });
    
    // Start session tracking
    const tracker = new HTTPSessionTracker(session);
    tracker.startTracking();
}

// HTTP Session Tracker for warning popup
class HTTPSessionTracker {
    constructor(session) {
        this.session = session;
        this.updateInterval = null;
    }

    startTracking() {
        // Initial update
        this.updateDisplay();
        
        // Update every second
        this.updateInterval = setInterval(() => {
            this.updateDisplay();
        }, 1000);
        
        // Clean up on window close
        window.addEventListener('beforeunload', () => {
            if (this.updateInterval) {
                clearInterval(this.updateInterval);
            }
        });
    }

    updateDisplay() {
        // Update session time
        const elapsed = Date.now() - this.session.startTime;
        const minutes = Math.floor(elapsed / 60000);
        const seconds = Math.floor((elapsed % 60000) / 1000);
        
        const timeElement = document.getElementById('session-time');
        if (timeElement) {
            timeElement.textContent = `${minutes}m ${seconds}s`;
        }
        
        // Update data sent (mock for now)
        const dataElement = document.getElementById('data-sent');
        if (dataElement) {
            const dataSent = Math.floor(elapsed / 1000) * 0.5; // Mock calculation
            dataElement.textContent = `~${dataSent.toFixed(1)} KB`;
        }
        
        // Update forms detected
        const formsElement = document.getElementById('forms-detected');
        if (formsElement && this.session.formsDetected) {
            formsElement.textContent = this.session.formsDetected.length;
        }
    }
}

// Initialize appropriate popup mode
async function initializePopup() {
    // Check if we should show warning popup
    const isWarning = await checkWarningMode();
    
    if (!isWarning) {
        // Show normal settings dashboard
        new SettingsManager();
    }
}

// Start initialization
initializePopup();