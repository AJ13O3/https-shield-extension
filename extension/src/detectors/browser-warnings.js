// Chrome-specific warning detection
import { DETECTION_CONFIG } from '../config/detection-config.js';
import { WarningClassifier } from '../utils/warning-classifier.js';

export class BrowserWarningDetector {
    constructor() {
        this.detectors = this.initializeDetectors();
        this.cache = new Map();
        this.lastCheckTime = 0;
    }

    initializeDetectors() {
        return [
            {
                name: 'chrome-not-secure',
                priority: 'high',
                check: () => this.checkNotSecureIndicator(),
                patterns: DETECTION_CONFIG.chromePatterns.notSecure
            },
            {
                name: 'https-only-mode',
                priority: 'high',
                check: () => this.checkHttpsOnlyMode(),
                patterns: DETECTION_CONFIG.chromePatterns.httpsOnlyMode
            },
            {
                name: 'certificate-error-page',
                priority: 'critical',
                check: () => this.checkCertificateErrorPage(),
                patterns: DETECTION_CONFIG.chromePatterns.certificateErrors
            },
            {
                name: 'privacy-error-page',
                priority: 'high',
                check: () => this.checkPrivacyErrorPage(),
                patterns: DETECTION_CONFIG.chromePatterns.privacyErrors
            }
        ];
    }

    async runDetection() {
        const startTime = performance.now();
        const results = [];

        for (const detector of this.detectors) {
            try {
                const result = await this.runSingleDetection(detector);
                if (result.detected) {
                    results.push(result);
                }
            } catch (error) {
                console.warn(`Detection error in ${detector.name}:`, error);
            }

            // Performance check
            if (performance.now() - startTime > DETECTION_CONFIG.performance.maxDetectionRunTime) {
                console.warn('Detection timeout reached, stopping early');
                break;
            }
        }

        this.lastCheckTime = Date.now();
        return results;
    }

    async runSingleDetection(detector) {
        const cacheKey = `${detector.name}-${window.location.href}`;
        
        // Check cache first (valid for 5 seconds)
        if (this.cache.has(cacheKey)) {
            const cached = this.cache.get(cacheKey);
            if (Date.now() - cached.timestamp < 5000) {
                return cached.result;
            }
        }

        const detected = await detector.check();
        const context = this.buildDetectionContext(detector, detected);
        
        const result = {
            detectorName: detector.name,
            detected: detected.found,
            element: detected.element,
            confidence: detected.confidence || 0.8,
            context,
            classification: WarningClassifier.classifyWarning(detector.name, context),
            timestamp: Date.now()
        };

        // Cache result
        this.cache.set(cacheKey, {
            result,
            timestamp: Date.now()
        });

        return result;
    }

    checkNotSecureIndicator() {
        // Check address bar "Not secure" indicator
        for (const pattern of DETECTION_CONFIG.chromePatterns.notSecure) {
            const element = document.querySelector(pattern);
            if (element) {
                return {
                    found: true,
                    element,
                    confidence: 0.95,
                    method: 'dom-selector'
                };
            }
        }

        // Fallback: Check if current page is HTTP
        if (window.location.protocol === 'http:') {
            return {
                found: true,
                element: null,
                confidence: 0.9,
                method: 'protocol-check'
            };
        }

        return { found: false };
    }

    checkHttpsOnlyMode() {
        // Check for HTTPS-only mode warning page
        for (const pattern of DETECTION_CONFIG.chromePatterns.httpsOnlyMode) {
            const element = document.querySelector(pattern);
            if (element) {
                return {
                    found: true,
                    element,
                    confidence: 0.98,
                    method: 'dom-selector'
                };
            }
        }

        // Check page title and content for HTTPS-only indicators
        const title = document.title.toLowerCase();
        const bodyText = document.body ? document.body.textContent.toLowerCase() : '';
        
        const httpsOnlyIndicators = [
            'https-only mode',
            'upgrade to https',
            'secure connection required',
            'connection not secure'
        ];

        for (const indicator of httpsOnlyIndicators) {
            if (title.includes(indicator) || bodyText.includes(indicator)) {
                return {
                    found: true,
                    element: document.body,
                    confidence: 0.85,
                    method: 'content-analysis'
                };
            }
        }

        return { found: false };
    }

    checkCertificateErrorPage() {
        // Check for certificate error page elements
        for (const pattern of DETECTION_CONFIG.chromePatterns.certificateErrors) {
            const element = document.querySelector(pattern);
            if (element) {
                return {
                    found: true,
                    element,
                    confidence: 0.98,
                    method: 'dom-selector'
                };
            }
        }

        // Check for certificate error codes in page content
        const pageContent = document.documentElement.innerHTML;
        for (const errorCode of DETECTION_CONFIG.errorCodes.certificate) {
            if (pageContent.includes(errorCode)) {
                return {
                    found: true,
                    element: document.body,
                    confidence: 0.95,
                    method: 'error-code',
                    errorCode
                };
            }
        }

        // Check page title for certificate errors
        const title = document.title.toLowerCase();
        const certErrorIndicators = [
            'privacy error',
            'security error',
            'certificate error',
            'ssl error',
            'connection not private'
        ];

        for (const indicator of certErrorIndicators) {
            if (title.includes(indicator)) {
                return {
                    found: true,
                    element: document.head,
                    confidence: 0.85,
                    method: 'title-analysis'
                };
            }
        }

        return { found: false };
    }

    checkPrivacyErrorPage() {
        // Check for privacy error page elements
        for (const pattern of DETECTION_CONFIG.chromePatterns.privacyErrors) {
            const element = document.querySelector(pattern);
            if (element) {
                return {
                    found: true,
                    element,
                    confidence: 0.95,
                    method: 'dom-selector'
                };
            }
        }

        // Check for privacy-related error content
        const bodyText = document.body ? document.body.textContent.toLowerCase() : '';
        const privacyIndicators = [
            'your connection is not private',
            'attackers might be trying',
            'certificate is not trusted',
            'proceed to'
        ];

        for (const indicator of privacyIndicators) {
            if (bodyText.includes(indicator)) {
                return {
                    found: true,
                    element: document.body,
                    confidence: 0.8,
                    method: 'content-analysis'
                };
            }
        }

        return { found: false };
    }

    buildDetectionContext(detector, detectionResult) {
        return {
            url: window.location.href,
            protocol: window.location.protocol,
            hostname: window.location.hostname,
            hasPasswordFields: this.hasPasswordFields(),
            hasFormsWithSensitiveData: this.hasFormsWithSensitiveData(),
            domElementFound: !!detectionResult.element,
            detectionMethod: detectionResult.method,
            pageTitle: document.title,
            userAgent: navigator.userAgent
        };
    }

    hasPasswordFields() {
        return document.querySelectorAll('input[type="password"]').length > 0;
    }

    hasFormsWithSensitiveData() {
        const forms = document.querySelectorAll('form');
        
        for (const form of forms) {
            const inputs = form.querySelectorAll('input');
            
            for (const input of inputs) {
                const type = input.type.toLowerCase();
                const name = input.name.toLowerCase();
                
                if (DETECTION_CONFIG.formSecurity.sensitiveInputTypes.includes(type)) {
                    return true;
                }
                
                for (const fieldName of DETECTION_CONFIG.formSecurity.sensitiveFieldNames) {
                    if (name.includes(fieldName)) {
                        return true;
                    }
                }
            }
        }
        
        return false;
    }

    clearCache() {
        this.cache.clear();
    }

    getMetrics() {
        return {
            detectorCount: this.detectors.length,
            cacheSize: this.cache.size,
            lastCheckTime: this.lastCheckTime
        };
    }
}