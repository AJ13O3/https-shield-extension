// Enhanced DOM monitoring with performance optimizations
import { debounce, throttle } from './debounce.js';

export class DOMObserver {
    constructor(callback, options = {}) {
        this.callback = callback;
        this.options = {
            debounceDelay: options.debounceDelay || 100,
            throttleLimit: options.throttleLimit || 250,
            maxMutations: options.maxMutations || 50,
            ...options
        };
        
        this.observer = null;
        this.isObserving = false;
        this.mutationCount = 0;
        this.lastProcessTime = 0;
        
        // Create debounced and throttled versions of callback
        this.debouncedCallback = debounce(this.processCallback.bind(this), this.options.debounceDelay);
        this.throttledCallback = throttle(this.processCallback.bind(this), this.options.throttleLimit);
    }

    start(target = document.body) {
        if (this.isObserving) {
            this.stop();
        }

        this.observer = new MutationObserver((mutations) => {
            this.handleMutations(mutations);
        });

        const config = {
            childList: true,
            subtree: true,
            attributes: this.options.watchAttributes || false,
            attributeFilter: this.options.attributeFilter,
            characterData: this.options.watchTextChanges || false
        };

        this.observer.observe(target, config);
        this.isObserving = true;
        console.log('DOM Observer started');
    }

    stop() {
        if (this.observer) {
            this.observer.disconnect();
            this.observer = null;
        }
        this.isObserving = false;
        this.mutationCount = 0;
        console.log('DOM Observer stopped');
    }

    handleMutations(mutations) {
        this.mutationCount += mutations.length;
        
        // Performance protection - limit processing frequency
        const now = Date.now();
        if (now - this.lastProcessTime < 50) {
            this.throttledCallback(mutations);
        } else {
            this.debouncedCallback(mutations);
        }
    }

    processCallback(mutations) {
        const now = Date.now();
        this.lastProcessTime = now;
        
        // Filter relevant mutations
        const relevantMutations = this.filterMutations(mutations);
        
        if (relevantMutations.length > 0) {
            this.callback(relevantMutations, {
                totalMutations: this.mutationCount,
                timestamp: now
            });
        }
        
        // Reset counter periodically
        if (this.mutationCount > this.options.maxMutations) {
            this.mutationCount = 0;
        }
    }

    filterMutations(mutations) {
        const relevant = [];
        
        for (const mutation of mutations) {
            if (this.isMutationRelevant(mutation)) {
                relevant.push(mutation);
            }
        }
        
        return relevant;
    }

    isMutationRelevant(mutation) {
        // Skip mutations from our own extension
        if (mutation.target && mutation.target.id && 
            mutation.target.id.startsWith('https-shield')) {
            return false;
        }

        // Check for added nodes that might contain warnings
        if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
            for (const node of mutation.addedNodes) {
                if (node.nodeType === Node.ELEMENT_NODE) {
                    // Check if node might contain security warnings
                    if (this.elementMightContainWarning(node)) {
                        return true;
                    }
                }
            }
        }

        // Check for attribute changes that might indicate security state
        if (mutation.type === 'attributes') {
            const attrName = mutation.attributeName;
            if (['class', 'data-security', 'aria-label'].includes(attrName)) {
                return true;
            }
        }

        return false;
    }

    elementMightContainWarning(element) {
        // Check element properties that might indicate warnings
        const tagName = element.tagName ? element.tagName.toLowerCase() : '';
        const className = element.className || '';
        const id = element.id || '';
        
        // Common warning indicators
        const warningIndicators = [
            'security', 'warning', 'error', 'ssl', 'certificate',
            'insecure', 'not-secure', 'mixed-content', 'https',
            'privacy', 'connection', 'unsafe'
        ];
        
        const textContent = element.textContent ? element.textContent.toLowerCase() : '';
        
        // Check for warning-related content
        for (const indicator of warningIndicators) {
            if (className.includes(indicator) || 
                id.includes(indicator) || 
                textContent.includes(indicator)) {
                return true;
            }
        }
        
        // Check for form elements (potential security risk)
        if (['form', 'input', 'textarea'].includes(tagName)) {
            return true;
        }
        
        // Check for iframe (potential security context)
        if (tagName === 'iframe') {
            return true;
        }
        
        return false;
    }

    // Get performance metrics
    getMetrics() {
        return {
            isObserving: this.isObserving,
            totalMutations: this.mutationCount,
            lastProcessTime: this.lastProcessTime
        };
    }
}