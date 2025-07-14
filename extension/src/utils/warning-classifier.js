// Warning classification and severity analysis
export class WarningClassifier {
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
        INSECURE_FORM: 'insecure_form',
        HTTPS_ONLY_MODE: 'https_only_mode',
        PRIVACY_ERROR: 'privacy_error',
        SECURITY_WARNING: 'security_warning'
    };

    static classifyWarning(detectorName, context = {}) {
        const classification = {
            type: this.getWarningType(detectorName),
            severity: this.getSeverity(detectorName, context),
            confidence: this.getConfidence(detectorName, context),
            impact: this.getImpact(detectorName),
            recommendation: this.getRecommendation(detectorName)
        };

        return classification;
    }

    static getWarningType(detectorName) {
        const typeMap = {
            'chrome-not-secure': this.WARNING_TYPES.HTTP_SITE,
            'ssl-error-page': this.WARNING_TYPES.CERTIFICATE_ERROR,
            'mixed-content': this.WARNING_TYPES.MIXED_CONTENT,
            'insecure-form': this.WARNING_TYPES.INSECURE_FORM,
            'https-only-mode': this.WARNING_TYPES.HTTPS_ONLY_MODE,
            'certificate-expired': this.WARNING_TYPES.CERTIFICATE_ERROR,
            'certificate-invalid': this.WARNING_TYPES.CERTIFICATE_ERROR,
            'privacy-error': this.WARNING_TYPES.PRIVACY_ERROR
        };

        return typeMap[detectorName] || this.WARNING_TYPES.SECURITY_WARNING;
    }

    static getSeverity(detectorName, context) {
        // Certificate errors are always critical
        if (detectorName.includes('certificate') || detectorName.includes('ssl-error')) {
            return this.SEVERITY_LEVELS.CRITICAL;
        }

        // HTTPS-only mode warnings are high severity
        if (detectorName.includes('https-only')) {
            return this.SEVERITY_LEVELS.HIGH;
        }

        // Forms with sensitive data are high severity
        if (detectorName.includes('insecure-form') && context.hasPasswordField) {
            return this.SEVERITY_LEVELS.HIGH;
        }

        // HTTP sites are medium to high based on content
        if (detectorName.includes('not-secure')) {
            return context.hasFormsWithSensitiveData ? 
                this.SEVERITY_LEVELS.HIGH : this.SEVERITY_LEVELS.MEDIUM;
        }

        // Mixed content is medium severity
        if (detectorName.includes('mixed-content')) {
            return this.SEVERITY_LEVELS.MEDIUM;
        }

        return this.SEVERITY_LEVELS.LOW;
    }

    static getConfidence(detectorName, context) {
        // DOM-based detections have high confidence
        if (context.domElementFound) {
            return 0.95;
        }

        // URL-based detections have medium confidence
        if (context.urlBased) {
            return 0.75;
        }

        // Pattern-based detections vary
        if (context.patternMatch) {
            return 0.85;
        }

        return 0.6;
    }

    static getImpact(detectorName) {
        const impactMap = {
            'ssl-error-page': 'Complete security bypass - all data transmitted in clear text',
            'certificate-expired': 'Potential man-in-the-middle attacks',
            'mixed-content': 'Partial security compromise - some resources unencrypted',
            'insecure-form': 'Form data transmitted without encryption',
            'chrome-not-secure': 'No encryption - data visible to attackers',
            'https-only-mode': 'Browser blocking insecure connection'
        };

        return impactMap[detectorName] || 'Security risk detected';
    }

    static getRecommendation(detectorName) {
        const recommendationMap = {
            'ssl-error-page': 'Do not proceed - find HTTPS version of site',
            'certificate-expired': 'Verify site legitimacy before proceeding',
            'mixed-content': 'Check for HTTPS version of all resources',
            'insecure-form': 'Avoid entering sensitive information',
            'chrome-not-secure': 'Look for HTTPS version or avoid site',
            'https-only-mode': 'Use HTTPS version if available'
        };

        return recommendationMap[detectorName] || 'Exercise caution when proceeding';
    }
}