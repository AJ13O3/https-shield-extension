// HTTPS-Only Mode Detection Utility
// Detects if Chrome's HTTPS-only mode is enabled

class HttpsOnlyModeDetector {
    constructor() {
        this.detectionMethods = [
            this.checkNavigationPatterns.bind(this),
            this.checkErrorPatterns.bind(this),
            this.probeTestUrl.bind(this)
        ];
        this.isDetecting = false;
        this.detectionResult = null;
        this.callbacks = [];
    }

    // Main detection method
    async detect() {
        if (this.isDetecting) {
            return this.waitForDetection();
        }

        if (this.detectionResult !== null) {
            return this.detectionResult;
        }

        this.isDetecting = true;
        
        try {
            // Try multiple detection methods
            for (const method of this.detectionMethods) {
                try {
                    const result = await method();
                    if (result !== null) {
                        this.detectionResult = result;
                        this.saveDetectionResult(result);
                        this.notifyCallbacks(result);
                        return result;
                    }
                } catch (error) {
                    console.error('Detection method failed:', error);
                }
            }

            // Default to assuming it's enabled for safety
            this.detectionResult = true;
            this.saveDetectionResult(true);
            this.notifyCallbacks(true);
            return true;
            
        } finally {
            this.isDetecting = false;
        }
    }

    // Method 1: Check navigation patterns
    async checkNavigationPatterns() {
        return new Promise((resolve) => {
            let httpAttempts = 0;
            let httpsRedirects = 0;
            const startTime = Date.now();

            const listener = (details) => {
                if (details.frameId !== 0) return; // Main frame only

                const url = new URL(details.url);
                
                // Track HTTP navigation attempts
                if (url.protocol === 'http:') {
                    httpAttempts++;
                }

                // Check for automatic HTTPS upgrades
                if (details.transitionType === 'server_redirect' &&
                    details.transitionQualifiers.includes('from_address_bar')) {
                    httpsRedirects++;
                }

                // Make determination after observing some navigations
                if (Date.now() - startTime > 5000 || httpAttempts + httpsRedirects > 5) {
                    chrome.webNavigation.onCommitted.removeListener(listener);
                    
                    // If we see consistent HTTPS redirects, HTTPS-only mode is likely enabled
                    if (httpsRedirects > httpAttempts * 0.7) {
                        resolve(true);
                    } else {
                        resolve(null); // Inconclusive
                    }
                }
            };

            chrome.webNavigation.onCommitted.addListener(listener);

            // Timeout after 10 seconds
            setTimeout(() => {
                chrome.webNavigation.onCommitted.removeListener(listener);
                resolve(null);
            }, 10000);
        });
    }

    // Method 2: Check for specific error patterns
    async checkErrorPatterns() {
        return new Promise((resolve) => {
            const listener = (details) => {
                if (details.frameId !== 0) return;

                // HTTPS-only mode specific error patterns
                const httpsOnlyErrors = [
                    'net::ERR_SSL_PROTOCOL_ERROR',
                    'net::ERR_CONNECTION_REFUSED'
                ];

                if (httpsOnlyErrors.includes(details.error) &&
                    details.url.startsWith('http://')) {
                    chrome.webNavigation.onErrorOccurred.removeListener(listener);
                    resolve(true);
                }
            };

            chrome.webNavigation.onErrorOccurred.addListener(listener);

            // Timeout after 5 seconds
            setTimeout(() => {
                chrome.webNavigation.onErrorOccurred.removeListener(listener);
                resolve(null);
            }, 5000);
        });
    }

    // Method 3: Probe with a test URL
    async probeTestUrl() {
        try {
            // Create a hidden iframe to test HTTP navigation
            const testUrl = 'http://neverssl.com/'; // Known HTTP-only test site
            
            return new Promise((resolve) => {
                let frameId = null;
                
                const navigationListener = (details) => {
                    if (details.url.includes('neverssl.com')) {
                        // Check if navigation was blocked or redirected
                        if (details.url.startsWith('chrome-error://')) {
                            cleanup();
                            resolve(true); // HTTPS-only mode is enabled
                        }
                    }
                };

                const errorListener = (details) => {
                    if (details.url.includes('neverssl.com')) {
                        cleanup();
                        resolve(true); // HTTPS-only mode blocked the request
                    }
                };

                const completeListener = (details) => {
                    if (details.url.includes('neverssl.com') && 
                        details.url.startsWith('http://')) {
                        cleanup();
                        resolve(false); // HTTP loaded successfully, HTTPS-only mode is off
                    }
                };

                const cleanup = () => {
                    chrome.webNavigation.onCommitted.removeListener(navigationListener);
                    chrome.webNavigation.onErrorOccurred.removeListener(errorListener);
                    chrome.webNavigation.onCompleted.removeListener(completeListener);
                    
                    // Close the test tab if it was created
                    if (frameId) {
                        chrome.tabs.remove(frameId).catch(() => {});
                    }
                };

                // Set up listeners
                chrome.webNavigation.onCommitted.addListener(navigationListener);
                chrome.webNavigation.onErrorOccurred.addListener(errorListener);
                chrome.webNavigation.onCompleted.addListener(completeListener);

                // Create test tab
                chrome.tabs.create({
                    url: testUrl,
                    active: false
                }, (tab) => {
                    frameId = tab.id;
                });

                // Timeout after 3 seconds
                setTimeout(() => {
                    cleanup();
                    resolve(null);
                }, 3000);
            });
            
        } catch (error) {
            console.error('Probe test failed:', error);
            return null;
        }
    }

    // Save detection result to storage
    async saveDetectionResult(result) {
        try {
            await chrome.storage.local.set({
                httpsOnlyModeDetected: result,
                detectionTimestamp: Date.now()
            });
        } catch (error) {
            console.error('Failed to save detection result:', error);
        }
    }

    // Load previous detection result
    async loadPreviousResult() {
        try {
            const data = await chrome.storage.local.get([
                'httpsOnlyModeDetected',
                'detectionTimestamp'
            ]);
            
            // Use cached result if it's less than 24 hours old
            if (data.httpsOnlyModeDetected !== undefined &&
                data.detectionTimestamp &&
                Date.now() - data.detectionTimestamp < 24 * 60 * 60 * 1000) {
                this.detectionResult = data.httpsOnlyModeDetected;
                return this.detectionResult;
            }
        } catch (error) {
            console.error('Failed to load previous result:', error);
        }
        
        return null;
    }

    // Wait for ongoing detection
    waitForDetection() {
        return new Promise((resolve) => {
            this.callbacks.push(resolve);
        });
    }

    // Notify waiting callbacks
    notifyCallbacks(result) {
        this.callbacks.forEach(callback => callback(result));
        this.callbacks = [];
    }

    // Force re-detection
    async redetect() {
        this.detectionResult = null;
        return this.detect();
    }
}

// Export singleton instance
const httpsOnlyDetector = new HttpsOnlyModeDetector();
export default httpsOnlyDetector;