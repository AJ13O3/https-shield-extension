// Navigation Flow Manager
// Manages the complex navigation flows when intercepting HTTP requests

class NavigationManager {
    constructor() {
        // Track navigation states for each tab
        this.navigationStates = new Map();
        
        // Track pending risk assessments
        this.pendingAssessments = new Map();
        
        // User decisions cache (for session)
        this.userDecisions = new Map();
        
        this.setupListeners();
    }

    setupListeners() {
        // Clean up when tabs are closed
        chrome.tabs.onRemoved.addListener((tabId) => {
            this.cleanupTab(tabId);
        });

        // Monitor navigation completion
        chrome.webNavigation.onCompleted.addListener((details) => {
            if (details.frameId === 0) {
                this.handleNavigationComplete(details);
            }
        });

        // Monitor navigation errors
        chrome.webNavigation.onErrorOccurred.addListener((details) => {
            if (details.frameId === 0) {
                this.handleNavigationError(details);
            }
        });
    }

    // Start tracking a navigation flow
    startNavigation(tabId, originalUrl, interceptedAt) {
        const navigationState = {
            tabId,
            originalUrl,
            interceptedAt,
            status: 'intercepted',
            userDecision: null,
            riskAssessment: null,
            attempts: 0
        };
        
        this.navigationStates.set(tabId, navigationState);
        
        // Set timeout to clean up stale navigations
        setTimeout(() => {
            const state = this.navigationStates.get(tabId);
            if (state && state.status === 'intercepted') {
                this.cleanupTab(tabId);
            }
        }, 60000); // 1 minute timeout
        
        return navigationState;
    }

    // Update navigation state
    updateNavigation(tabId, updates) {
        const state = this.navigationStates.get(tabId);
        if (state) {
            Object.assign(state, updates);
            this.navigationStates.set(tabId, state);
        }
    }

    // Get navigation state
    getNavigation(tabId) {
        return this.navigationStates.get(tabId);
    }

    // Record user decision
    recordUserDecision(tabId, decision, url) {
        // Update navigation state
        this.updateNavigation(tabId, {
            userDecision: decision,
            status: 'decided'
        });
        
        // Cache decision for this session
        try {
            const domain = new URL(url).hostname;
            const decisions = this.userDecisions.get(domain) || [];
            decisions.push({
                decision,
                timestamp: Date.now(),
                tabId
            });
            this.userDecisions.set(domain, decisions);
        } catch (error) {
            console.error('Error recording user decision:', error);
        }
    }

    // Check if user has recently made a decision for this domain
    getRecentDecision(url) {
        try {
            const domain = new URL(url).hostname;
            const decisions = this.userDecisions.get(domain);
            
            if (!decisions || decisions.length === 0) {
                return null;
            }
            
            // Get decisions from last 30 minutes
            const recentDecisions = decisions.filter(
                d => Date.now() - d.timestamp < 30 * 60 * 1000
            );
            
            if (recentDecisions.length === 0) {
                return null;
            }
            
            // Return the most recent decision
            return recentDecisions[recentDecisions.length - 1];
            
        } catch (error) {
            console.error('Error getting recent decision:', error);
            return null;
        }
    }

    // Handle navigation completion
    handleNavigationComplete(details) {
        const state = this.navigationStates.get(details.tabId);
        if (state) {
            // Check if user proceeded to the HTTP site
            if (details.url.startsWith('http://') && 
                state.userDecision === 'proceed') {
                this.updateNavigation(details.tabId, {
                    status: 'completed',
                    finalUrl: details.url
                });
                
                // Log the event for analytics
                this.logNavigationEvent(details.tabId, 'proceeded_to_http');
            }
        }
    }

    // Handle navigation errors
    handleNavigationError(details) {
        const state = this.navigationStates.get(details.tabId);
        if (state) {
            this.updateNavigation(details.tabId, {
                status: 'error',
                error: details.error,
                errorUrl: details.url
            });
            
            // Check if this is a Chrome HTTPS-only warning
            if (this.isHttpsOnlyWarning(details)) {
                this.handleHttpsOnlyWarning(details.tabId, state);
            }
        }
    }

    // Check if error is from HTTPS-only mode
    isHttpsOnlyWarning(details) {
        const httpsOnlyErrors = [
            'net::ERR_SSL_PROTOCOL_ERROR',
            'net::ERR_CONNECTION_REFUSED',
            'net::ERR_CONNECTION_RESET'
        ];
        
        return details.url.startsWith('http://') && 
               httpsOnlyErrors.includes(details.error);
    }

    // Handle HTTPS-only warning detection
    handleHttpsOnlyWarning(tabId, state) {
        // Mark that we've seen an HTTPS-only warning
        chrome.storage.local.set({ httpsOnlyModeDetected: true });
        
        // Update navigation state
        this.updateNavigation(tabId, {
            httpsOnlyWarning: true,
            warningTime: Date.now()
        });
        
        // Log for analytics
        this.logNavigationEvent(tabId, 'https_only_warning_detected');
    }

    // Should intercept this navigation?
    shouldIntercept(url, tabId) {
        // Check if we have a recent decision for this domain
        const recentDecision = this.getRecentDecision(url);
        if (recentDecision && recentDecision.decision === 'proceed') {
            console.log('Allowing navigation due to recent user decision');
            return false;
        }
        
        // Check if this tab already has an active interception
        const state = this.navigationStates.get(tabId);
        if (state && state.status === 'intercepted') {
            // Avoid double interception
            return false;
        }
        
        return true;
    }

    // Clean up tab data
    cleanupTab(tabId) {
        this.navigationStates.delete(tabId);
        this.pendingAssessments.delete(tabId);
    }

    // Log navigation events for analytics
    async logNavigationEvent(tabId, eventType) {
        try {
            const state = this.navigationStates.get(tabId);
            const event = {
                type: 'navigation_event',
                eventType,
                tabId,
                timestamp: Date.now(),
                navigationData: state ? {
                    originalUrl: state.originalUrl,
                    userDecision: state.userDecision,
                    riskLevel: state.riskAssessment?.riskLevel
                } : null
            };
            
            // Send to background script for storage
            chrome.runtime.sendMessage({
                type: 'LOG_EVENT',
                event
            });
            
        } catch (error) {
            console.error('Error logging navigation event:', error);
        }
    }

    // Get navigation statistics
    getStatistics() {
        const stats = {
            activeNavigations: this.navigationStates.size,
            pendingAssessments: this.pendingAssessments.size,
            cachedDecisions: this.userDecisions.size,
            recentDecisions: []
        };
        
        // Get recent decisions
        for (const [domain, decisions] of this.userDecisions) {
            const recent = decisions.filter(
                d => Date.now() - d.timestamp < 60 * 60 * 1000 // Last hour
            );
            if (recent.length > 0) {
                stats.recentDecisions.push({
                    domain,
                    count: recent.length,
                    lastDecision: recent[recent.length - 1].decision
                });
            }
        }
        
        return stats;
    }
}

// Export singleton instance
const navigationManager = new NavigationManager();
export default navigationManager;