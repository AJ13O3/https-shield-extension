// Detection configuration and thresholds
export const DETECTION_CONFIG = {
    // Performance settings
    performance: {
        debounceDelay: 100,
        throttleLimit: 250,
        maxMutationsPerBatch: 50,
        maxDetectionRunTime: 50, // milliseconds
        maxMemoryUsage: 10 * 1024 * 1024 // 10MB
    },

    // Detection thresholds
    thresholds: {
        minConfidence: 0.6,
        highSeverityThreshold: 4,
        criticalSeverityThreshold: 5
    },

    // Warning patterns for Chrome
    chromePatterns: {
        // Address bar indicators
        notSecure: [
            '[data-value="Not secure"]',
            '.location-icon[data-tooltip*="Not secure"]',
            '#security-state-icon[data-tooltip*="Not secure"]'
        ],

        // HTTPS-only mode warnings
        httpsOnlyMode: [
            '.https-only-mode-warning',
            '[id*="https-only"]',
            '.interstitial-wrapper[id*="https-only"]'
        ],

        // Certificate error pages
        certificateErrors: [
            '#security-error-page',
            '.ssl-error-container',
            '.interstitial-wrapper[class*="ssl"]',
            '.error-page[class*="cert"]'
        ],

        // Privacy error pages
        privacyErrors: [
            '.privacy-error-page',
            '.interstitial-wrapper[class*="privacy"]',
            '#privacy-error-page'
        ]
    },

    // Error code patterns
    errorCodes: {
        certificate: [
            'ERR_CERT_AUTHORITY_INVALID',
            'ERR_CERT_COMMON_NAME_INVALID',
            'ERR_CERT_DATE_INVALID',
            'ERR_CERT_INVALID',
            'ERR_CERT_REVOKED',
            'ERR_CERT_WEAK_SIGNATURE_ALGORITHM',
            'ERR_SSL_PROTOCOL_ERROR',
            'ERR_SSL_VERSION_OR_CIPHER_MISMATCH'
        ],
        connection: [
            'ERR_CONNECTION_REFUSED',
            'ERR_CONNECTION_TIMED_OUT',
            'ERR_SSL_PROTOCOL_ERROR'
        ]
    },

    // Form security indicators
    formSecurity: {
        sensitiveInputTypes: [
            'password',
            'email',
            'tel',
            'credit-card',
            'social-security'
        ],
        sensitiveFieldNames: [
            'password', 'passwd', 'pwd',
            'email', 'mail',
            'phone', 'tel', 'mobile',
            'ssn', 'social',
            'card', 'credit', 'cvv', 'cvc',
            'account', 'login', 'username'
        ]
    },

    // Mixed content patterns
    mixedContent: {
        insecureResourceTypes: [
            'script[src^="http:"]',
            'img[src^="http:"]',
            'link[href^="http:"]',
            'iframe[src^="http:"]',
            'video[src^="http:"]',
            'audio[src^="http:"]'
        ]
    },

    // Exclusions and allowlists
    exclusions: {
        // Domains to skip detection
        skipDomains: [
            'localhost',
            '127.0.0.1',
            '*.local'
        ],
        
        // Elements to ignore
        skipElements: [
            '#https-shield-overlay',
            '#https-shield-warning-banner',
            '.https-shield-*'
        ]
    }
};