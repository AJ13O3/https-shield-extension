// HTTPS Shield Extension - Enhanced Content Script
// Comprehensive security detection system with modular architecture

// Utility: Debounce function
function debounce(func, wait, immediate = false) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            timeout = null;
            if (!immediate) func.apply(this, args);
        };
        const callNow = immediate && !timeout;
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
        if (callNow) func.apply(this, args);
    };
}

// Utility: Throttle function
function throttle(func, limit) {
    let inThrottle;
    return function(...args) {
        if (!inThrottle) {
            func.apply(this, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// Configuration
const DETECTION_CONFIG = {
    performance: {
        debounceDelay: 100,
        throttleLimit: 250,
        maxMutationsPerBatch: 50,
        maxDetectionRunTime: 50
    },
    thresholds: {
        minConfidence: 0.6,
        highSeverityThreshold: 4,
        criticalSeverityThreshold: 5
    },
    chromePatterns: {
        notSecure: [
            '[data-value="Not secure"]',
            '.location-icon[data-tooltip*="Not secure"]'
        ],
        httpsOnlyMode: [
            '.https-only-mode-warning',
            '[id*="https-only"]'
        ],
        certificateErrors: [
            '#security-error-page',
            '.ssl-error-container'
        ]
    },
    errorCodes: {
        certificate: [
            'ERR_CERT_AUTHORITY_INVALID',
            'ERR_CERT_COMMON_NAME_INVALID',
            'ERR_CERT_DATE_INVALID'
        ]
    },
    formSecurity: {
        sensitiveInputTypes: ['password', 'email', 'tel'],
        sensitiveFieldNames: ['password', 'email', 'phone', 'card', 'ssn']
    },
    exclusions: {
        skipDomains: ['localhost', '127.0.0.1']
    }
};

// Warning Classifier
class WarningClassifier {
    static SEVERITY_LEVELS = {
        CRITICAL: 5,
        HIGH: 4,
        MEDIUM: 3,
        LOW: 2,
        INFO: 1
    };

    static WARNING_TYPES = {
        CERTIFICATE_ERROR: 'certificate_error',
        HTTP_SITE: 'http_site',
        MIXED_CONTENT: 'mixed_content',
        INSECURE_FORM: 'insecure_form'
    };

    static classifyWarning(detectorName, context = {}) {
        return {
            type: this.getWarningType(detectorName),
            severity: this.getSeverity(detectorName, context),
            confidence: this.getConfidence(detectorName, context),
            impact: this.getImpact(detectorName),
            recommendation: this.getRecommendation(detectorName)
        };
    }

    static getWarningType(detectorName) {
        if (detectorName.includes('certificate')) return this.WARNING_TYPES.CERTIFICATE_ERROR;
        if (detectorName.includes('form')) return this.WARNING_TYPES.INSECURE_FORM;
        if (detectorName.includes('mixed')) return this.WARNING_TYPES.MIXED_CONTENT;
        if (detectorName.includes('not-secure')) return this.WARNING_TYPES.HTTP_SITE;
        return this.WARNING_TYPES.HTTP_SITE;
    }

    static getSeverity(detectorName, context) {
        if (detectorName.includes('certificate')) return this.SEVERITY_LEVELS.CRITICAL;
        if (detectorName.includes('password') && context.hasPasswordField) return this.SEVERITY_LEVELS.HIGH;
        if (detectorName.includes('not-secure')) return this.SEVERITY_LEVELS.MEDIUM;
        return this.SEVERITY_LEVELS.LOW;
    }

    static getConfidence(detectorName, context) {
        if (context.domElementFound) return 0.95;
        if (context.urlBased) return 0.75;
        return 0.8;
    }

    static getImpact(detectorName) {
        const impacts = {
            'certificate': 'Certificate security error - potential man-in-the-middle attack',
            'not-secure': 'Unencrypted connection - data transmitted in plain text',
            'form': 'Form data transmitted without encryption',
            'mixed': 'Mixed content - some resources loaded over HTTP'
        };
        
        for (const [key, impact] of Object.entries(impacts)) {
            if (detectorName.includes(key)) return impact;
        }
        
        return 'Security issue detected';
    }

    static getRecommendation(detectorName) {
        if (detectorName.includes('certificate')) return 'Do not proceed - verify site legitimacy';
        if (detectorName.includes('form')) return 'Avoid entering sensitive information';
        if (detectorName.includes('not-secure')) return 'Look for HTTPS version of site';
        return 'Exercise caution when proceeding';
    }
}

// Enhanced DOM Observer
class DOMObserver {
    constructor(callback, options = {}) {
        this.callback = callback;
        this.options = {
            debounceDelay: options.debounceDelay || 100,
            throttleLimit: options.throttleLimit || 250,
            ...options
        };
        
        this.observer = null;
        this.isObserving = false;
        this.debouncedCallback = debounce(this.processCallback.bind(this), this.options.debounceDelay);
    }

    start(target = document.body) {
        if (this.isObserving) this.stop();

        this.observer = new MutationObserver((mutations) => {
            this.debouncedCallback(mutations);
        });

        this.observer.observe(target, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ['src', 'href', 'action', 'type']
        });

        this.isObserving = true;
        console.log('Enhanced DOM Observer started');
    }

    stop() {
        if (this.observer) {
            this.observer.disconnect();
            this.observer = null;
        }
        this.isObserving = false;
    }

    processCallback(mutations) {
        const relevantMutations = mutations.filter(mutation => this.isMutationRelevant(mutation));
        if (relevantMutations.length > 0) {
            this.callback(relevantMutations, { timestamp: Date.now() });
        }
    }

    isMutationRelevant(mutation) {
        if (mutation.target && mutation.target.id && mutation.target.id.startsWith('https-shield')) {
            return false;
        }

        if (mutation.type === 'childList') {
            for (const node of mutation.addedNodes) {
                if (node.nodeType === Node.ELEMENT_NODE) {
                    const tagName = node.tagName ? node.tagName.toLowerCase() : '';
                    if (['form', 'input', 'script', 'iframe', 'img'].includes(tagName)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    getMetrics() {
        return { isObserving: this.isObserving };
    }
}

// Browser Warning Detector
class BrowserWarningDetector {
    constructor() {
        this.cache = new Map();
    }

    async runDetection() {
        const results = [];

        // Check for "Not secure" indicator
        const notSecureResult = this.checkNotSecureIndicator();
        if (notSecureResult.detected) {
            results.push({
                detectorName: 'chrome-not-secure',
                detected: true,
                confidence: notSecureResult.confidence,
                context: this.buildContext(),
                classification: WarningClassifier.classifyWarning('chrome-not-secure', this.buildContext())
            });
        }

        // Check for certificate errors
        const certErrorResult = this.checkCertificateErrors();
        if (certErrorResult.detected) {
            results.push({
                detectorName: 'certificate-error',
                detected: true,
                confidence: certErrorResult.confidence,
                context: this.buildContext(),
                classification: WarningClassifier.classifyWarning('certificate-error', this.buildContext())
            });
        }

        return results;
    }

    checkNotSecureIndicator() {
        // Check DOM elements
        for (const pattern of DETECTION_CONFIG.chromePatterns.notSecure) {
            if (document.querySelector(pattern)) {
                return { detected: true, confidence: 0.95 };
            }
        }

        // Check protocol
        if (window.location.protocol === 'http:') {
            return { detected: true, confidence: 0.9 };
        }

        return { detected: false };
    }

    checkCertificateErrors() {
        // Check DOM elements
        for (const pattern of DETECTION_CONFIG.chromePatterns.certificateErrors) {
            if (document.querySelector(pattern)) {
                return { detected: true, confidence: 0.98 };
            }
        }

        // Check for error codes
        const pageContent = document.documentElement.innerHTML;
        for (const errorCode of DETECTION_CONFIG.errorCodes.certificate) {
            if (pageContent.includes(errorCode)) {
                return { detected: true, confidence: 0.95 };
            }
        }

        // Check page title
        const title = document.title.toLowerCase();
        if (title.includes('privacy error') || title.includes('security error')) {
            return { detected: true, confidence: 0.85 };
        }

        return { detected: false };
    }

    buildContext() {
        return {
            url: window.location.href,
            protocol: window.location.protocol,
            hasPasswordFields: document.querySelectorAll('input[type="password"]').length > 0,
            hasFormsWithSensitiveData: this.hasFormsWithSensitiveData(),
            domElementFound: true
        };
    }

    hasFormsWithSensitiveData() {
        const forms = document.querySelectorAll('form');
        for (const form of forms) {
            const inputs = form.querySelectorAll('input');
            for (const input of inputs) {
                const type = input.type.toLowerCase();
                const name = (input.name || '').toLowerCase();
                
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

    getMetrics() {
        return { cacheSize: this.cache.size };
    }
}

// Form Security Detector
class FormSecurityDetector {
    async runDetection() {
        const results = [];

        // Check for insecure form submission
        const insecureFormsResult = this.checkInsecureFormSubmission();
        if (insecureFormsResult.detected) {
            results.push({
                detectorName: 'insecure-form-submission',
                detected: true,
                details: insecureFormsResult.details,
                context: this.buildFormContext(),
                classification: WarningClassifier.classifyWarning('insecure-form-submission', this.buildFormContext())
            });
        }

        // Check for password fields on HTTP
        if (window.location.protocol === 'http:') {
            const passwordFields = document.querySelectorAll('input[type="password"]');
            if (passwordFields.length > 0) {
                results.push({
                    detectorName: 'password-field-http',
                    detected: true,
                    details: { passwordFieldsCount: passwordFields.length },
                    context: this.buildFormContext(),
                    classification: WarningClassifier.classifyWarning('password-field-http', this.buildFormContext())
                });
            }
        }

        return results;
    }

    checkInsecureFormSubmission() {
        const insecureForms = [];
        const forms = document.querySelectorAll('form');

        for (const form of forms) {
            const action = form.getAttribute('action') || window.location.href;
            const hasSensitiveFields = this.formHasSensitiveFields(form);
            
            if (action.startsWith('http://') && hasSensitiveFields) {
                insecureForms.push({ form, action });
            }
        }

        return {
            detected: insecureForms.length > 0,
            details: { formsCount: insecureForms.length }
        };
    }

    formHasSensitiveFields(form) {
        const inputs = form.querySelectorAll('input, textarea');
        for (const input of inputs) {
            const type = input.type.toLowerCase();
            const name = (input.name || '').toLowerCase();
            
            if (DETECTION_CONFIG.formSecurity.sensitiveInputTypes.includes(type)) {
                return true;
            }
            
            for (const fieldName of DETECTION_CONFIG.formSecurity.sensitiveFieldNames) {
                if (name.includes(fieldName)) {
                    return true;
                }
            }
        }
        return false;
    }

    buildFormContext() {
        return {
            url: window.location.href,
            protocol: window.location.protocol,
            hasPasswordField: document.querySelectorAll('input[type="password"]').length > 0,
            hasFormsWithSensitiveData: true
        };
    }

    getMetrics() {
        return { formsAnalyzed: document.querySelectorAll('form').length };
    }
}

// Mixed Content Detector
class MixedContentDetector {
    async runDetection() {
        if (window.location.protocol !== 'https:') {
            return [];
        }

        const results = [];

        // Check for mixed content scripts
        const scripts = document.querySelectorAll('script[src]');
        const insecureScripts = Array.from(scripts).filter(script => 
            script.getAttribute('src').startsWith('http://')
        );

        if (insecureScripts.length > 0) {
            results.push({
                detectorName: 'mixed-content-scripts',
                detected: true,
                details: { scriptsCount: insecureScripts.length },
                context: this.buildMixedContentContext(),
                classification: WarningClassifier.classifyWarning('mixed-content-scripts', this.buildMixedContentContext())
            });
        }

        // Check for mixed content images
        const images = document.querySelectorAll('img[src]');
        const insecureImages = Array.from(images).filter(img => 
            img.getAttribute('src').startsWith('http://')
        );

        if (insecureImages.length > 0) {
            results.push({
                detectorName: 'mixed-content-images',
                detected: true,
                details: { imagesCount: insecureImages.length },
                context: this.buildMixedContentContext(),
                classification: WarningClassifier.classifyWarning('mixed-content-images', this.buildMixedContentContext())
            });
        }

        return results;
    }

    buildMixedContentContext() {
        return {
            url: window.location.href,
            protocol: window.location.protocol,
            hasMixedContent: true
        };
    }

    getMetrics() {
        return { 
            totalScripts: document.querySelectorAll('script').length,
            totalImages: document.querySelectorAll('img').length
        };
    }
}

// Main Content Script Class
class HTTPSShieldContentEnhanced {
    constructor() {
        this.isInitialized = false;
        this.detectors = new Map();
        this.domObserver = null;
        this.detectionResults = new Map();
        this.lastDetectionTime = 0;
        this.performanceMetrics = {
            detectionsRun: 0,
            averageDetectionTime: 0,
            totalDetectionTime: 0
        };
        this.init();
    }

    async init() {
        if (this.isInitialized) return;
        
        console.log('HTTPS Shield Enhanced Content Script initializing on:', window.location.href);
        
        this.initializeDetectors();
        
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
            this.handleMessage(message, sender, sendResponse);
            return true;
        });

        this.setupEnhancedMutationObserver();
        await this.runComprehensiveDetection();
        
        this.isInitialized = true;
        console.log('HTTPS Shield Enhanced Content Script initialized');
    }

    initializeDetectors() {
        this.detectors.set('browser-warnings', new BrowserWarningDetector());
        this.detectors.set('form-security', new FormSecurityDetector());
        this.detectors.set('mixed-content', new MixedContentDetector());
        
        console.log('Initialized', this.detectors.size, 'enhanced detector modules');
    }

    async runComprehensiveDetection() {
        const startTime = performance.now();
        
        if (this.shouldSkipDetection()) {
            console.log('Skipping detection on excluded domain');
            return;
        }

        console.log('Running comprehensive security detection...');

        const allResults = [];
        const detectionPromises = Array.from(this.detectors.entries()).map(async ([name, detector]) => {
            try {
                const results = await detector.runDetection();
                return { detectorName: name, results };
            } catch (error) {
                console.warn(`Detection error in ${name}:`, error);
                return { detectorName: name, results: [] };
            }
        });

        const detectionResults = await Promise.all(detectionPromises);

        for (const { detectorName, results } of detectionResults) {
            if (results && results.length > 0) {
                console.log(`${detectorName} detected ${results.length} security issues`);
                allResults.push(...results);
                this.detectionResults.set(detectorName, results);
            }
        }

        const detectionTime = performance.now() - startTime;
        this.updatePerformanceMetrics(detectionTime);

        if (allResults.length > 0) {
            await this.handleDetectionResults(allResults);
        }

        // Legacy compatibility for HTTP sites
        if (window.location.href.startsWith('http://')) {
            await this.handleHTTPSite(window.location.href);
        }

        console.log(`Detection completed in ${detectionTime.toFixed(2)}ms, found ${allResults.length} issues`);
    }

    shouldSkipDetection() {
        const hostname = window.location.hostname;
        return DETECTION_CONFIG.exclusions.skipDomains.includes(hostname);
    }

    updatePerformanceMetrics(detectionTime) {
        this.performanceMetrics.detectionsRun++;
        this.performanceMetrics.totalDetectionTime += detectionTime;
        this.performanceMetrics.averageDetectionTime = 
            this.performanceMetrics.totalDetectionTime / this.performanceMetrics.detectionsRun;
    }

    async handleDetectionResults(allResults) {
        console.log('Processing detection results:', allResults.length, 'issues found');
        
        const classifiedResults = this.classifyAndPrioritizeResults(allResults);
        
        chrome.runtime.sendMessage({
            type: 'LOG_EVENT',
            event: {
                type: 'comprehensive_security_detection',
                results: classifiedResults,
                url: window.location.href,
                detectionTime: this.performanceMetrics.averageDetectionTime,
                issueCount: allResults.length
            }
        });

        const highestSeverity = this.getHighestSeverity(classifiedResults);
        
        if (highestSeverity >= WarningClassifier.SEVERITY_LEVELS.HIGH) {
            this.showCriticalWarningUI(classifiedResults);
        } else if (highestSeverity >= WarningClassifier.SEVERITY_LEVELS.MEDIUM) {
            this.showWarningUI(classifiedResults);
        } else {
            this.showInfoUI(classifiedResults);
        }
    }

    classifyAndPrioritizeResults(results) {
        return results
            .map(result => ({
                ...result,
                priorityScore: this.calculatePriorityScore(result)
            }))
            .sort((a, b) => b.priorityScore - a.priorityScore);
    }

    calculatePriorityScore(result) {
        let score = 0;
        
        if (result.classification) {
            score += result.classification.severity * 20;
            score += result.classification.confidence * 10;
        }
        
        const priorityMap = { 'critical': 100, 'high': 80, 'medium': 60, 'low': 40 };
        score += priorityMap[result.priority] || 0;
        
        if (result.context) {
            if (result.context.hasPasswordField) score += 30;
            if (result.context.hasFormsWithSensitiveData) score += 20;
            if (result.context.protocol === 'http') score += 25;
        }
        
        return Math.min(score, 200);
    }

    getHighestSeverity(results) {
        return Math.max(...results.map(r => 
            r.classification ? r.classification.severity : 1
        ), 0);
    }

    async handleHTTPSite(url) {
        try {
            const response = await chrome.runtime.sendMessage({
                type: 'ANALYZE_URL',
                url: url
            });

            if (response.success) {
                this.showRiskAssessment(response.data);
                
                chrome.runtime.sendMessage({
                    type: 'LOG_EVENT',
                    event: {
                        type: 'http_site_visited',
                        url: url,
                        riskScore: response.data.riskScore,
                        riskLevel: response.data.riskLevel
                    }
                });
            }
        } catch (error) {
            console.error('Error analyzing URL:', error);
        }
    }

    showCriticalWarningUI(results) {
        this.createEnhancedWarningOverlay(results, 'critical');
    }

    showWarningUI(results) {
        this.createEnhancedWarningOverlay(results, 'warning');
    }

    showInfoUI(results) {
        this.createEnhancedWarningOverlay(results, 'info');
    }

    createEnhancedWarningOverlay(results, severity) {
        this.removeExistingOverlays();

        const overlay = document.createElement('div');
        overlay.id = 'https-shield-enhanced-overlay';
        overlay.className = `shield-overlay severity-${severity}`;
        
        const topResults = results.slice(0, 3);
        const severityConfig = this.getSeverityConfig(severity);
        
        overlay.innerHTML = `
            <div class="shield-overlay-content">
                <div class="shield-header ${severity}">
                    <span class="shield-icon">${severityConfig.icon}</span>
                    <span class="shield-title">HTTPS Shield</span>
                    <span class="severity-badge">${severityConfig.label}</span>
                    <button class="shield-close">×</button>
                </div>
                <div class="shield-body">
                    <div class="detection-summary">
                        <h4>${severityConfig.title}</h4>
                        <p>${results.length} security issue${results.length > 1 ? 's' : ''} detected</p>
                    </div>
                    <div class="issues-list">
                        ${topResults.map(result => this.createIssueItem(result)).join('')}
                        ${results.length > 3 ? `<div class="more-issues">... and ${results.length - 3} more issues</div>` : ''}
                    </div>
                    <div class="shield-actions">
                        <button class="btn-primary">Dismiss</button>
                        <button class="btn-secondary">Learn More</button>
                    </div>
                </div>
            </div>
        `;

        this.addEnhancedOverlayStyles();
        document.body.appendChild(overlay);

        overlay.querySelector('.shield-close').onclick = () => overlay.remove();
        overlay.querySelector('.btn-primary').onclick = () => overlay.remove();

        if (severity === 'info') {
            setTimeout(() => {
                if (overlay.parentNode) overlay.remove();
            }, 10000);
        }
    }

    createIssueItem(result) {
        const severityClass = result.classification ? 
            `severity-${result.classification.severity}` : 'severity-unknown';
        
        return `
            <div class="issue-item ${severityClass}">
                <div class="issue-type">${this.getIssueTypeDisplay(result.detectorName)}</div>
                <div class="issue-description">${this.getIssueDescription(result)}</div>
            </div>
        `;
    }

    getIssueTypeDisplay(detectorName) {
        const displayNames = {
            'browser-warnings': 'Browser Warning',
            'form-security': 'Form Security',
            'mixed-content': 'Mixed Content'
        };
        
        return displayNames[detectorName] || detectorName.replace('-', ' ');
    }

    getIssueDescription(result) {
        if (result.classification && result.classification.impact) {
            return result.classification.impact;
        }
        return 'Security issue detected';
    }

    getSeverityConfig(severity) {
        const configs = {
            critical: { icon: '🛑', label: 'CRITICAL', title: 'Critical Security Issues' },
            warning: { icon: '⚠️', label: 'WARNING', title: 'Security Warnings' },
            info: { icon: '🛡️', label: 'INFO', title: 'Security Information' }
        };
        
        return configs[severity] || configs.info;
    }

    removeExistingOverlays() {
        const existing = document.querySelectorAll('#https-shield-enhanced-overlay, #https-shield-overlay');
        existing.forEach(el => el.remove());
    }

    showRiskAssessment(analysis) {
        // Legacy risk assessment display
        console.log('Risk assessment:', analysis);
    }

    addEnhancedOverlayStyles() {
        if (document.getElementById('https-shield-enhanced-styles')) return;

        const styles = document.createElement('style');
        styles.id = 'https-shield-enhanced-styles';
        styles.textContent = `
            #https-shield-enhanced-overlay {
                position: fixed; top: 20px; right: 20px; width: 350px;
                background: white; border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.2);
                z-index: 10000; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                font-size: 14px; max-height: 80vh; overflow-y: auto;
            }
            .shield-header { padding: 16px 20px; border-radius: 12px 12px 0 0; color: white;
                display: flex; align-items: center; gap: 12px; }
            .shield-header.critical { background: linear-gradient(135deg, #e74c3c, #c0392b); }
            .shield-header.warning { background: linear-gradient(135deg, #f39c12, #e67e22); }
            .shield-header.info { background: linear-gradient(135deg, #3498db, #2980b9); }
            .shield-icon { font-size: 20px; }
            .shield-title { font-weight: 600; flex: 1; }
            .severity-badge { background: rgba(255,255,255,0.3); padding: 4px 8px;
                border-radius: 12px; font-size: 11px; font-weight: bold; }
            .shield-close { background: none; border: none; color: white; font-size: 20px;
                cursor: pointer; padding: 4px; border-radius: 50%; width: 32px; height: 32px; }
            .shield-body { padding: 20px; }
            .detection-summary h4 { margin: 0 0 8px 0; font-size: 16px; color: #333; }
            .detection-summary p { margin: 0 0 16px 0; color: #666; }
            .issue-item { padding: 12px; margin-bottom: 8px; border-radius: 8px;
                border-left: 4px solid #ddd; background: #f8f9fa; }
            .issue-item.severity-5 { border-left-color: #e74c3c; background: #fdf2f2; }
            .issue-item.severity-4 { border-left-color: #f39c12; background: #fef9f3; }
            .issue-item.severity-3 { border-left-color: #f1c40f; background: #fefef3; }
            .issue-type { font-weight: 600; color: #333; margin-bottom: 4px; }
            .issue-description { color: #666; font-size: 13px; }
            .shield-actions { display: flex; gap: 8px; margin-top: 16px; }
            .shield-actions button { flex: 1; padding: 10px 16px; border: none;
                border-radius: 6px; font-size: 13px; cursor: pointer; }
            .btn-primary { background: #667eea; color: white; }
            .btn-secondary { background: #e9ecef; color: #495057; }
            .more-issues { padding: 8px; text-align: center; color: #666; font-style: italic; }
        `;

        document.head.appendChild(styles);
    }

    setupEnhancedMutationObserver() {
        this.domObserver = new DOMObserver(
            (mutations) => this.handleDOMChanges(mutations),
            {
                debounceDelay: DETECTION_CONFIG.performance.debounceDelay,
                throttleLimit: DETECTION_CONFIG.performance.throttleLimit
            }
        );

        this.domObserver.start();
    }

    async handleDOMChanges(mutations) {
        const now = Date.now();
        if (now - this.lastDetectionTime < DETECTION_CONFIG.performance.throttleLimit) {
            return;
        }

        this.lastDetectionTime = now;

        if (this.hasSignificantChanges(mutations)) {
            console.log('Significant DOM changes detected, re-running detection');
            await this.runComprehensiveDetection();
        }
    }

    hasSignificantChanges(mutations) {
        for (const mutation of mutations) {
            if (mutation.type === 'childList') {
                for (const node of mutation.addedNodes) {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        const tagName = node.tagName ? node.tagName.toLowerCase() : '';
                        if (['form', 'input', 'script', 'iframe'].includes(tagName)) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    async handleMessage(message, sender, sendResponse) {
        try {
            switch (message.type) {
                case 'HTTP_SITE_DETECTED':
                    await this.handleHTTPSite(message.url);
                    sendResponse({ success: true });
                    break;
                    
                case 'RUN_COMPREHENSIVE_DETECTION':
                    await this.runComprehensiveDetection();
                    sendResponse({ success: true });
                    break;
                    
                case 'GET_DETECTION_METRICS':
                    sendResponse({
                        success: true,
                        metrics: this.performanceMetrics
                    });
                    break;
                    
                default:
                    sendResponse({ success: false, error: 'Unknown message type' });
            }
        } catch (error) {
            console.error('Error handling message:', error);
            sendResponse({ success: false, error: error.message });
        }
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        new HTTPSShieldContentEnhanced();
    });
} else {
    new HTTPSShieldContentEnhanced();
}