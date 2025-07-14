// Edge Case Handler
// Handles various edge cases and fallback scenarios for the pre-warning system

class EdgeCaseHandler {
    constructor() {
        // Special domains that should bypass interception
        this.bypassDomains = new Set([
            'localhost',
            '127.0.0.1',
            '[::1]'
        ]);
        
        // Patterns for local/private networks
        this.localNetworkPatterns = [
            /^192\.168\.\d+\.\d+$/,
            /^10\.\d+\.\d+\.\d+$/,
            /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/,
            /^fe80:/i,
            /^fc00:/i,
            /^fd00:/i,
            /\.local$/,
            /\.localhost$/,
            /\.internal$/,
            /\.lan$/
        ];
        
        // Known HTTP-only services that shouldn't trigger warnings
        this.httpOnlyServices = new Set([
            'captive.apple.com',
            'connectivitycheck.gstatic.com',
            'detectportal.firefox.com',
            'nmcheck.gnome.org'
        ]);
        
        // Special URL schemes to ignore
        this.ignoredSchemes = new Set([
            'chrome:',
            'chrome-extension:',
            'about:',
            'data:',
            'blob:',
            'file:',
            'ftp:'
        ]);
        
        // Rate limiting for repeated requests
        this.requestCounts = new Map();
        this.resetCountsInterval = setInterval(() => {
            this.requestCounts.clear();
        }, 60000); // Reset every minute
    }

    // Main method to check if request should be handled
    shouldHandleRequest(details) {
        try {
            const url = new URL(details.url);
            
            // Check various conditions
            const checks = [
                this.checkScheme(url),
                this.checkLocalAddress(url),
                this.checkHttpOnlyService(url),
                this.checkRateLimit(url, details.tabId),
                this.checkSpecialPorts(url),
                this.checkFileDownload(details),
                this.checkCaptivePortal(url)
            ];
            
            // Log reasons for bypassing
            const reasons = [];
            if (!this.checkScheme(url)) reasons.push('ignored scheme');
            if (this.checkLocalAddress(url)) reasons.push('local address');
            if (this.checkHttpOnlyService(url)) reasons.push('HTTP-only service');
            if (!this.checkRateLimit(url, details.tabId)) reasons.push('rate limited');
            if (this.checkSpecialPorts(url)) reasons.push('special port');
            if (this.checkFileDownload(details)) reasons.push('file download');
            if (this.checkCaptivePortal(url)) reasons.push('captive portal');
            
            if (reasons.length > 0) {
                console.log(`Bypassing interception for ${url.hostname}: ${reasons.join(', ')}`);
                return false;
            }
            
            return true;
            
        } catch (error) {
            console.error('Error in edge case handler:', error);
            // On error, allow interception for safety
            return true;
        }
    }

    // Check URL scheme
    checkScheme(url) {
        return !this.ignoredSchemes.has(url.protocol);
    }

    // Check if address is local/private
    checkLocalAddress(url) {
        const hostname = url.hostname;
        
        // Check explicit bypass list
        if (this.bypassDomains.has(hostname)) {
            return true;
        }
        
        // Check local network patterns
        for (const pattern of this.localNetworkPatterns) {
            if (pattern.test(hostname)) {
                return true;
            }
        }
        
        // Check for IPv6 local addresses
        if (hostname.startsWith('[') && hostname.endsWith(']')) {
            const ipv6 = hostname.slice(1, -1);
            if (ipv6.startsWith('fe80:') || 
                ipv6.startsWith('fc00:') || 
                ipv6.startsWith('fd00:') ||
                ipv6 === '::1') {
                return true;
            }
        }
        
        return false;
    }

    // Check if it's a known HTTP-only service
    checkHttpOnlyService(url) {
        return this.httpOnlyServices.has(url.hostname);
    }

    // Rate limiting to prevent spam
    checkRateLimit(url, tabId) {
        const key = `${tabId}:${url.hostname}`;
        const count = this.requestCounts.get(key) || 0;
        
        if (count >= 5) {
            console.warn(`Rate limit exceeded for ${url.hostname} in tab ${tabId}`);
            return false;
        }
        
        this.requestCounts.set(key, count + 1);
        return true;
    }

    // Check for special ports that might indicate development servers
    checkSpecialPorts(url) {
        const port = url.port;
        if (!port) return false;
        
        const devPorts = [
            '3000', '3001', '3002', '3003', // React, Node.js
            '4200', '4201', // Angular
            '5000', '5001', '5173', // Flask, Vite
            '8000', '8001', '8080', '8081', // Django, various
            '9000', '9001', '9090', // Various dev servers
            '19000', '19001', '19002' // Expo
        ];
        
        if (devPorts.includes(port)) {
            console.log(`Detected development server on port ${port}`);
            // Could show a different warning for dev servers
            return true;
        }
        
        return false;
    }

    // Check if this might be a file download
    checkFileDownload(details) {
        // Check for download-related headers in responseHeaders if available
        if (details.type === 'sub_frame' || details.type === 'object') {
            return true;
        }
        
        // Check common download patterns
        const url = details.url;
        const downloadExtensions = [
            '.zip', '.rar', '.7z', '.tar', '.gz',
            '.exe', '.msi', '.dmg', '.pkg', '.deb', '.rpm',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx',
            '.mp3', '.mp4', '.avi', '.mkv', '.mov',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp',
            '.iso', '.img', '.bin'
        ];
        
        const urlLower = url.toLowerCase();
        for (const ext of downloadExtensions) {
            if (urlLower.endsWith(ext)) {
                return true;
            }
        }
        
        return false;
    }

    // Check for captive portal detection
    checkCaptivePortal(url) {
        const captivePortalDomains = [
            'captive.apple.com',
            'connectivitycheck.gstatic.com',
            'detectportal.firefox.com',
            'nmcheck.gnome.org',
            'www.msftconnecttest.com',
            'clients3.google.com'
        ];
        
        return captivePortalDomains.includes(url.hostname);
    }

    // Handle fallback when interception fails
    async handleInterceptionFailure(tabId, url, error) {
        console.error(`Interception failed for ${url}:`, error);
        
        try {
            // Log the failure
            await chrome.runtime.sendMessage({
                type: 'LOG_EVENT',
                event: {
                    type: 'interception_failure',
                    tabId,
                    url,
                    error: error.message || String(error),
                    timestamp: Date.now()
                }
            });
            
            // Show notification to user
            chrome.notifications.create({
                type: 'basic',
                iconUrl: chrome.runtime.getURL('/icons/icon-48.png'),
                title: 'HTTPS Shield Notice',
                message: 'Unable to analyze security risk. Proceed with caution.',
                priority: 2
            });
            
            // Allow navigation to continue
            return { cancel: false };
            
        } catch (notificationError) {
            console.error('Failed to show notification:', notificationError);
            return { cancel: false };
        }
    }

    // Handle when risk assessment page fails to load
    handleAssessmentPageError(tabId, targetUrl) {
        console.error('Risk assessment page failed to load');
        
        // Create a simple fallback warning
        const fallbackHtml = `
            <html>
            <head>
                <title>Security Warning</title>
                <style>
                    body { 
                        font-family: Arial, sans-serif; 
                        max-width: 600px; 
                        margin: 50px auto; 
                        padding: 20px;
                        text-align: center;
                    }
                    h1 { color: #d32f2f; }
                    .warning { 
                        background: #fff3e0; 
                        border: 2px solid #ff9800; 
                        padding: 20px; 
                        margin: 20px 0;
                        border-radius: 8px;
                    }
                    .actions { margin-top: 30px; }
                    button { 
                        padding: 10px 20px; 
                        margin: 0 10px; 
                        border: none;
                        border-radius: 4px;
                        cursor: pointer;
                        font-size: 16px;
                    }
                    .safe { background: #4caf50; color: white; }
                    .danger { background: #f44336; color: white; }
                </style>
            </head>
            <body>
                <h1>⚠️ Security Warning</h1>
                <div class="warning">
                    <p><strong>You are about to visit an insecure HTTP website:</strong></p>
                    <p style="word-break: break-all;">${targetUrl}</p>
                    <p>Your connection will not be encrypted.</p>
                </div>
                <div class="actions">
                    <button class="safe" onclick="history.back()">Go Back</button>
                    <button class="danger" onclick="location.href='${targetUrl}'">Continue Anyway</button>
                </div>
            </body>
            </html>
        `;
        
        // Create data URL for fallback page
        const dataUrl = 'data:text/html;charset=utf-8,' + encodeURIComponent(fallbackHtml);
        
        // Navigate to fallback warning
        chrome.tabs.update(tabId, { url: dataUrl });
    }

    // Clean up resources
    cleanup() {
        if (this.resetCountsInterval) {
            clearInterval(this.resetCountsInterval);
        }
        this.requestCounts.clear();
    }
}

// Export singleton instance
const edgeCaseHandler = new EdgeCaseHandler();
export default edgeCaseHandler;