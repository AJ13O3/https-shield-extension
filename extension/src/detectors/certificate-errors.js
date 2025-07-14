// Certificate and SSL/TLS error detection
import { DETECTION_CONFIG } from '../config/detection-config.js';
import { WarningClassifier } from '../utils/warning-classifier.js';

export class CertificateErrorDetector {
    constructor() {
        this.detectors = this.initializeDetectors();
        this.errorPatterns = this.initializeErrorPatterns();
    }

    initializeDetectors() {
        return [
            {
                name: 'certificate-expired',
                priority: 'critical',
                check: () => this.checkCertificateExpired()
            },
            {
                name: 'certificate-invalid',
                priority: 'critical',
                check: () => this.checkCertificateInvalid()
            },
            {
                name: 'certificate-authority-invalid',
                priority: 'critical',
                check: () => this.checkCertificateAuthorityInvalid()
            },
            {
                name: 'ssl-protocol-error',
                priority: 'high',
                check: () => this.checkSSLProtocolError()
            },
            {
                name: 'weak-cipher',
                priority: 'medium',
                check: () => this.checkWeakCipher()
            }
        ];
    }

    initializeErrorPatterns() {
        return {
            expired: [
                'ERR_CERT_DATE_INVALID',
                'certificate has expired',
                'certificate is not valid',
                'expired on'
            ],
            invalid: [
                'ERR_CERT_INVALID',
                'ERR_CERT_COMMON_NAME_INVALID',
                'certificate is invalid',
                'certificate name mismatch'
            ],
            authority: [
                'ERR_CERT_AUTHORITY_INVALID',
                'certificate authority is invalid',
                'untrusted certificate',
                'self-signed certificate'
            ],
            revoked: [
                'ERR_CERT_REVOKED',
                'certificate has been revoked',
                'certificate revocation'
            ],
            weak: [
                'ERR_CERT_WEAK_SIGNATURE_ALGORITHM',
                'weak signature algorithm',
                'insecure cipher',
                'deprecated ssl'
            ],
            protocol: [
                'ERR_SSL_PROTOCOL_ERROR',
                'ERR_SSL_VERSION_OR_CIPHER_MISMATCH',
                'ssl protocol error',
                'tls handshake failed'
            ]
        };
    }

    async runDetection() {
        const results = [];

        for (const detector of this.detectors) {
            try {
                const result = await detector.check();
                if (result.detected) {
                    const classification = WarningClassifier.classifyWarning(
                        detector.name, 
                        result.context
                    );

                    results.push({
                        detectorName: detector.name,
                        priority: detector.priority,
                        detected: true,
                        details: result.details,
                        element: result.element,
                        context: result.context,
                        classification,
                        timestamp: Date.now()
                    });
                }
            } catch (error) {
                console.warn(`Certificate detection error in ${detector.name}:`, error);
            }
        }

        return results;
    }

    checkCertificateExpired() {
        const context = this.analyzePageContent();
        
        // Check for expired certificate indicators
        for (const pattern of this.errorPatterns.expired) {
            if (context.pageContent.includes(pattern.toLowerCase()) ||
                context.pageTitle.includes(pattern.toLowerCase())) {
                
                return {
                    detected: true,
                    details: {
                        errorType: 'certificate_expired',
                        pattern: pattern,
                        evidence: this.extractErrorDetails(pattern, context.pageContent)
                    },
                    element: this.findErrorElement(),
                    context: {
                        ...context,
                        errorCode: this.extractErrorCode(context.pageContent),
                        certificateInfo: this.extractCertificateInfo(context.pageContent)
                    }
                };
            }
        }

        return { detected: false };
    }

    checkCertificateInvalid() {
        const context = this.analyzePageContent();
        
        // Check for invalid certificate indicators
        for (const pattern of this.errorPatterns.invalid) {
            if (context.pageContent.includes(pattern.toLowerCase())) {
                
                return {
                    detected: true,
                    details: {
                        errorType: 'certificate_invalid',
                        pattern: pattern,
                        evidence: this.extractErrorDetails(pattern, context.pageContent)
                    },
                    element: this.findErrorElement(),
                    context: {
                        ...context,
                        expectedHostname: window.location.hostname,
                        actualHostname: this.extractActualHostname(context.pageContent)
                    }
                };
            }
        }

        return { detected: false };
    }

    checkCertificateAuthorityInvalid() {
        const context = this.analyzePageContent();
        
        // Check for certificate authority issues
        for (const pattern of this.errorPatterns.authority) {
            if (context.pageContent.includes(pattern.toLowerCase())) {
                
                return {
                    detected: true,
                    details: {
                        errorType: 'certificate_authority_invalid',
                        pattern: pattern,
                        evidence: this.extractErrorDetails(pattern, context.pageContent)
                    },
                    element: this.findErrorElement(),
                    context: {
                        ...context,
                        isSelfSigned: this.checkSelfSignedIndicators(context.pageContent),
                        authorityInfo: this.extractAuthorityInfo(context.pageContent)
                    }
                };
            }
        }

        return { detected: false };
    }

    checkSSLProtocolError() {
        const context = this.analyzePageContent();
        
        // Check for SSL/TLS protocol errors
        for (const pattern of this.errorPatterns.protocol) {
            if (context.pageContent.includes(pattern.toLowerCase())) {
                
                return {
                    detected: true,
                    details: {
                        errorType: 'ssl_protocol_error',
                        pattern: pattern,
                        evidence: this.extractErrorDetails(pattern, context.pageContent)
                    },
                    element: this.findErrorElement(),
                    context: {
                        ...context,
                        supportedProtocols: this.extractSupportedProtocols(context.pageContent),
                        cipherInfo: this.extractCipherInfo(context.pageContent)
                    }
                };
            }
        }

        return { detected: false };
    }

    checkWeakCipher() {
        const context = this.analyzePageContent();
        
        // Check for weak signature algorithm warnings
        for (const pattern of this.errorPatterns.weak) {
            if (context.pageContent.includes(pattern.toLowerCase())) {
                
                return {
                    detected: true,
                    details: {
                        errorType: 'weak_cipher',
                        pattern: pattern,
                        evidence: this.extractErrorDetails(pattern, context.pageContent)
                    },
                    element: this.findErrorElement(),
                    context: {
                        ...context,
                        weakAlgorithm: this.extractWeakAlgorithm(context.pageContent)
                    }
                };
            }
        }

        return { detected: false };
    }

    analyzePageContent() {
        return {
            pageContent: document.documentElement.innerHTML.toLowerCase(),
            pageTitle: document.title.toLowerCase(),
            url: window.location.href,
            protocol: window.location.protocol,
            hostname: window.location.hostname,
            hasErrorPage: this.hasErrorPageStructure()
        };
    }

    hasErrorPageStructure() {
        // Check for common error page elements
        const errorPageSelectors = [
            '.ssl-error-container',
            '#security-error-page',
            '.interstitial-wrapper',
            '.error-page'
        ];

        return errorPageSelectors.some(selector => 
            document.querySelector(selector) !== null
        );
    }

    findErrorElement() {
        // Try to find the specific error element
        const errorSelectors = [
            '.ssl-error-container',
            '#security-error-page',
            '.error-code',
            '.error-message',
            '.interstitial-wrapper'
        ];

        for (const selector of errorSelectors) {
            const element = document.querySelector(selector);
            if (element) {
                return element;
            }
        }

        return document.body;
    }

    extractErrorCode(content) {
        // Extract Chrome error codes
        const errorCodeMatch = content.match(/ERR_[A-Z_]+/);
        return errorCodeMatch ? errorCodeMatch[0] : null;
    }

    extractErrorDetails(pattern, content) {
        // Extract relevant text around the error pattern
        const index = content.indexOf(pattern.toLowerCase());
        if (index === -1) return null;

        const start = Math.max(0, index - 100);
        const end = Math.min(content.length, index + 200);
        
        return content.substring(start, end).trim();
    }

    extractCertificateInfo(content) {
        // Extract certificate validity dates and issuer info
        const info = {};

        // Look for expiration dates
        const dateMatch = content.match(/expired on ([^.]+)/i);
        if (dateMatch) {
            info.expiredOn = dateMatch[1];
        }

        // Look for issuer information
        const issuerMatch = content.match(/issued by ([^.]+)/i);
        if (issuerMatch) {
            info.issuer = issuerMatch[1];
        }

        return Object.keys(info).length > 0 ? info : null;
    }

    extractActualHostname(content) {
        // Extract the actual hostname from certificate mismatch errors
        const hostnameMatch = content.match(/certificate is valid for ([^,\s]+)/i);
        return hostnameMatch ? hostnameMatch[1] : null;
    }

    checkSelfSignedIndicators(content) {
        const selfSignedIndicators = [
            'self-signed',
            'self signed',
            'not issued by a trusted'
        ];

        return selfSignedIndicators.some(indicator => 
            content.includes(indicator.toLowerCase())
        );
    }

    extractAuthorityInfo(content) {
        // Extract certificate authority information
        const authorityMatch = content.match(/certificate authority[^.]*([^.]+)/i);
        return authorityMatch ? authorityMatch[1].trim() : null;
    }

    extractSupportedProtocols(content) {
        // Extract supported SSL/TLS protocols from error messages
        const protocolMatch = content.match(/(ssl|tls) (\d+\.?\d*)/gi);
        return protocolMatch || [];
    }

    extractCipherInfo(content) {
        // Extract cipher suite information
        const cipherMatch = content.match(/cipher[^.]*([^.]+)/i);
        return cipherMatch ? cipherMatch[1].trim() : null;
    }

    extractWeakAlgorithm(content) {
        // Extract information about weak signature algorithms
        const algorithmMatch = content.match(/(sha-?1|md5|rc4|des)[^a-z]*/gi);
        return algorithmMatch ? algorithmMatch[0] : null;
    }

    getMetrics() {
        return {
            detectorCount: this.detectors.length,
            errorPatternCount: Object.values(this.errorPatterns).flat().length
        };
    }
}