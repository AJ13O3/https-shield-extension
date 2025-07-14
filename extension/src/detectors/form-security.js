// Form security analysis and insecure form detection
import { DETECTION_CONFIG } from '../config/detection-config.js';
import { WarningClassifier } from '../utils/warning-classifier.js';

export class FormSecurityDetector {
    constructor() {
        this.detectors = this.initializeDetectors();
        this.formCache = new WeakMap();
        this.observedForms = new Set();
    }

    initializeDetectors() {
        return [
            {
                name: 'insecure-form-submission',
                priority: 'high',
                check: () => this.checkInsecureFormSubmission()
            },
            {
                name: 'password-field-http',
                priority: 'critical',
                check: () => this.checkPasswordFieldOnHTTP()
            },
            {
                name: 'sensitive-data-http',
                priority: 'high',
                check: () => this.checkSensitiveDataOnHTTP()
            },
            {
                name: 'form-mixed-content',
                priority: 'medium',
                check: () => this.checkFormMixedContent()
            },
            {
                name: 'autocomplete-sensitive',
                priority: 'low',
                check: () => this.checkSensitiveAutocomplete()
            }
        ];
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
                        forms: result.forms,
                        context: result.context,
                        classification,
                        timestamp: Date.now()
                    });
                }
            } catch (error) {
                console.warn(`Form security detection error in ${detector.name}:`, error);
            }
        }

        return results;
    }

    checkInsecureFormSubmission() {
        const insecureForms = [];
        const forms = document.querySelectorAll('form');

        for (const form of forms) {
            const analysis = this.analyzeForm(form);
            
            // Check if form submits to HTTP endpoint
            if (analysis.submitsToHTTP && analysis.hasSensitiveFields) {
                insecureForms.push({
                    element: form,
                    action: analysis.action,
                    method: analysis.method,
                    sensitiveFields: analysis.sensitiveFields,
                    riskLevel: this.calculateFormRiskLevel(analysis)
                });
            }
        }

        if (insecureForms.length > 0) {
            return {
                detected: true,
                details: {
                    formsCount: insecureForms.length,
                    totalSensitiveFields: insecureForms.reduce(
                        (sum, form) => sum + form.sensitiveFields.length, 0
                    )
                },
                forms: insecureForms,
                context: this.buildFormContext(insecureForms)
            };
        }

        return { detected: false };
    }

    checkPasswordFieldOnHTTP() {
        if (window.location.protocol !== 'http:') {
            return { detected: false };
        }

        const passwordFields = document.querySelectorAll('input[type="password"]');
        
        if (passwordFields.length > 0) {
            const formsWithPasswords = [];
            
            passwordFields.forEach(field => {
                const form = field.closest('form');
                const formData = {
                    element: field,
                    form: form,
                    name: field.name || field.id,
                    isVisible: this.isElementVisible(field),
                    hasAutocomplete: field.hasAttribute('autocomplete'),
                    autocompleteValue: field.getAttribute('autocomplete')
                };
                
                formsWithPasswords.push(formData);
            });

            return {
                detected: true,
                details: {
                    passwordFieldsCount: passwordFields.length,
                    protocol: window.location.protocol,
                    visibleFields: formsWithPasswords.filter(f => f.isVisible).length
                },
                forms: formsWithPasswords,
                context: {
                    url: window.location.href,
                    hasPasswordField: true,
                    protocol: 'http'
                }
            };
        }

        return { detected: false };
    }

    checkSensitiveDataOnHTTP() {
        if (window.location.protocol !== 'http:') {
            return { detected: false };
        }

        const sensitiveFields = this.findSensitiveFields();
        
        if (sensitiveFields.length > 0) {
            return {
                detected: true,
                details: {
                    sensitiveFieldsCount: sensitiveFields.length,
                    fieldTypes: [...new Set(sensitiveFields.map(f => f.type))]
                },
                forms: sensitiveFields,
                context: {
                    url: window.location.href,
                    hasSensitiveFields: true,
                    protocol: 'http'
                }
            };
        }

        return { detected: false };
    }

    checkFormMixedContent() {
        if (window.location.protocol !== 'https:') {
            return { detected: false };
        }

        const mixedContentForms = [];
        const forms = document.querySelectorAll('form');

        for (const form of forms) {
            const action = form.getAttribute('action');
            
            if (action && action.startsWith('http://')) {
                const analysis = this.analyzeForm(form);
                
                mixedContentForms.push({
                    element: form,
                    action: action,
                    method: analysis.method,
                    hasSensitiveFields: analysis.hasSensitiveFields,
                    sensitiveFields: analysis.sensitiveFields
                });
            }
        }

        if (mixedContentForms.length > 0) {
            return {
                detected: true,
                details: {
                    mixedFormsCount: mixedContentForms.length,
                    formsWithSensitiveData: mixedContentForms.filter(f => f.hasSensitiveFields).length
                },
                forms: mixedContentForms,
                context: {
                    url: window.location.href,
                    protocol: 'https',
                    hasMixedContent: true
                }
            };
        }

        return { detected: false };
    }

    checkSensitiveAutocomplete() {
        const sensitiveAutocompleteFields = [];
        const inputs = document.querySelectorAll('input[autocomplete]');

        for (const input of inputs) {
            const autocomplete = input.getAttribute('autocomplete').toLowerCase();
            
            // Check for sensitive autocomplete values that should be disabled
            const sensitiveBut Enabled = [
                'current-password',
                'new-password',
                'cc-number',
                'cc-exp',
                'cc-csc'
            ];

            if (sensitiveButEnabled.includes(autocomplete) && 
                window.location.protocol === 'http:') {
                
                sensitiveAutocompleteFields.push({
                    element: input,
                    autocompleteValue: autocomplete,
                    type: input.type,
                    name: input.name || input.id,
                    isVisible: this.isElementVisible(input)
                });
            }
        }

        if (sensitiveAutocompleteFields.length > 0) {
            return {
                detected: true,
                details: {
                    fieldsCount: sensitiveAutocompleteFields.length,
                    autocompleteTypes: [...new Set(sensitiveAutocompleteFields.map(f => f.autocompleteValue))]
                },
                forms: sensitiveAutocompleteFields,
                context: {
                    url: window.location.href,
                    hasAutocompleteIssue: true
                }
            };
        }

        return { detected: false };
    }

    analyzeForm(form) {
        // Use cache if available
        if (this.formCache.has(form)) {
            return this.formCache.get(form);
        }

        const action = form.getAttribute('action') || window.location.href;
        const method = (form.getAttribute('method') || 'GET').toUpperCase();
        
        const analysis = {
            action: action,
            method: method,
            submitsToHTTP: action.startsWith('http://'),
            submitsToExternal: this.isExternalSubmission(action),
            hasSensitiveFields: false,
            sensitiveFields: [],
            fieldCount: 0
        };

        // Analyze form fields
        const inputs = form.querySelectorAll('input, textarea, select');
        analysis.fieldCount = inputs.length;

        for (const input of inputs) {
            if (this.isSensitiveField(input)) {
                analysis.hasSensitiveFields = true;
                analysis.sensitiveFields.push({
                    element: input,
                    type: input.type,
                    name: input.name || input.id,
                    sensitiveReason: this.getSensitiveReason(input)
                });
            }
        }

        // Cache the analysis
        this.formCache.set(form, analysis);
        return analysis;
    }

    findSensitiveFields() {
        const sensitiveFields = [];
        const inputs = document.querySelectorAll('input, textarea');

        for (const input of inputs) {
            if (this.isSensitiveField(input)) {
                sensitiveFields.push({
                    element: input,
                    type: input.type,
                    name: input.name || input.id,
                    form: input.closest('form'),
                    sensitiveReason: this.getSensitiveReason(input),
                    isVisible: this.isElementVisible(input)
                });
            }
        }

        return sensitiveFields;
    }

    isSensitiveField(input) {
        const type = input.type.toLowerCase();
        const name = (input.name || input.id || '').toLowerCase();
        const placeholder = (input.placeholder || '').toLowerCase();
        const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();

        // Check input type
        if (DETECTION_CONFIG.formSecurity.sensitiveInputTypes.includes(type)) {
            return true;
        }

        // Check field name/id
        for (const fieldName of DETECTION_CONFIG.formSecurity.sensitiveFieldNames) {
            if (name.includes(fieldName) || placeholder.includes(fieldName)) {
                return true;
            }
        }

        // Check autocomplete attribute
        const sensitiveAutocomplete = [
            'current-password', 'new-password', 'cc-number', 
            'cc-exp', 'cc-csc', 'cc-name', 'email', 'tel'
        ];
        
        if (sensitiveAutocomplete.includes(autocomplete)) {
            return true;
        }

        return false;
    }

    getSensitiveReason(input) {
        const type = input.type.toLowerCase();
        const name = (input.name || input.id || '').toLowerCase();
        const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();

        if (type === 'password') return 'password_field';
        if (type === 'email') return 'email_field';
        if (autocomplete.includes('password')) return 'password_autocomplete';
        if (autocomplete.includes('cc-')) return 'credit_card_autocomplete';
        if (name.includes('card') || name.includes('credit')) return 'credit_card_field';
        if (name.includes('ssn') || name.includes('social')) return 'ssn_field';
        
        return 'sensitive_field_name';
    }

    isElementVisible(element) {
        const style = window.getComputedStyle(element);
        return style.display !== 'none' && 
               style.visibility !== 'hidden' && 
               style.opacity !== '0' &&
               element.offsetWidth > 0 && 
               element.offsetHeight > 0;
    }

    isExternalSubmission(action) {
        try {
            const actionUrl = new URL(action, window.location.href);
            return actionUrl.hostname !== window.location.hostname;
        } catch {
            return false;
        }
    }

    calculateFormRiskLevel(analysis) {
        let risk = 0;
        
        if (analysis.submitsToHTTP) risk += 40;
        if (analysis.hasSensitiveFields) risk += 30;
        if (analysis.method === 'GET') risk += 20; // GET with sensitive data
        if (analysis.submitsToExternal) risk += 10;
        
        risk += analysis.sensitiveFields.length * 5;
        
        return Math.min(risk, 100);
    }

    buildFormContext(forms) {
        return {
            url: window.location.href,
            protocol: window.location.protocol,
            formsCount: forms.length,
            hasPasswordField: forms.some(f => 
                f.sensitiveFields && f.sensitiveFields.some(field => 
                    field.type === 'password'
                )
            ),
            hasFormsWithSensitiveData: forms.length > 0,
            totalSensitiveFields: forms.reduce(
                (sum, form) => sum + (form.sensitiveFields ? form.sensitiveFields.length : 0), 0
            )
        };
    }

    setupFormMonitoring() {
        // Monitor for dynamically added forms
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        const forms = node.tagName === 'FORM' ? 
                            [node] : node.querySelectorAll('form');
                        
                        forms.forEach(form => {
                            if (!this.observedForms.has(form)) {
                                this.observedForms.add(form);
                                this.analyzeForm(form);
                            }
                        });
                    }
                });
            });
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    getMetrics() {
        return {
            detectorCount: this.detectors.length,
            cachedFormsCount: this.formCache.size || 0,
            observedFormsCount: this.observedForms.size
        };
    }
}