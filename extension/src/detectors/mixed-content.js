// Enhanced mixed content detection
import { DETECTION_CONFIG } from '../config/detection-config.js';
import { WarningClassifier } from '../utils/warning-classifier.js';

export class MixedContentDetector {
    constructor() {
        this.detectors = this.initializeDetectors();
        this.resourceCache = new Map();
        this.observedResources = new Set();
    }

    initializeDetectors() {
        return [
            {
                name: 'mixed-content-scripts',
                priority: 'critical',
                check: () => this.checkMixedContentScripts()
            },
            {
                name: 'mixed-content-stylesheets',
                priority: 'high',
                check: () => this.checkMixedContentStylesheets()
            },
            {
                name: 'mixed-content-images',
                priority: 'medium',
                check: () => this.checkMixedContentImages()
            },
            {
                name: 'mixed-content-iframes',
                priority: 'high',
                check: () => this.checkMixedContentIframes()
            },
            {
                name: 'mixed-content-media',
                priority: 'medium',
                check: () => this.checkMixedContentMedia()
            },
            {
                name: 'mixed-content-xhr',
                priority: 'high',
                check: () => this.checkMixedContentXHR()
            }
        ];
    }

    async runDetection() {
        // Only run on HTTPS pages
        if (window.location.protocol !== 'https:') {
            return [];
        }

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
                        resources: result.resources,
                        context: result.context,
                        classification,
                        timestamp: Date.now()
                    });
                }
            } catch (error) {
                console.warn(`Mixed content detection error in ${detector.name}:`, error);
            }
        }

        return results;
    }

    checkMixedContentScripts() {
        const insecureScripts = [];
        const scripts = document.querySelectorAll('script[src]');

        for (const script of scripts) {
            const src = script.getAttribute('src');
            if (src && src.startsWith('http://')) {
                insecureScripts.push({
                    element: script,
                    src: src,
                    type: 'script',
                    isAsync: script.hasAttribute('async'),
                    isDefer: script.hasAttribute('defer'),
                    isInline: false,
                    riskLevel: this.calculateScriptRiskLevel(script, src)
                });
            }
        }

        // Check for inline scripts that might load HTTP resources
        const inlineScripts = document.querySelectorAll('script:not([src])');
        for (const script of inlineScripts) {
            const content = script.textContent || script.innerHTML;
            const httpUrls = this.extractHTTPUrls(content);
            
            if (httpUrls.length > 0) {
                insecureScripts.push({
                    element: script,
                    content: content.substring(0, 200) + '...',
                    type: 'inline-script',
                    httpUrls: httpUrls,
                    isInline: true,
                    riskLevel: 80 // High risk for inline scripts with HTTP
                });
            }
        }

        if (insecureScripts.length > 0) {
            return {
                detected: true,
                details: {
                    scriptsCount: insecureScripts.length,
                    externalScripts: insecureScripts.filter(s => !s.isInline).length,
                    inlineScripts: insecureScripts.filter(s => s.isInline).length,
                    averageRiskLevel: this.calculateAverageRisk(insecureScripts)
                },
                resources: insecureScripts,
                context: this.buildMixedContentContext('scripts', insecureScripts)
            };
        }

        return { detected: false };
    }

    checkMixedContentStylesheets() {
        const insecureStylesheets = [];
        
        // Check external stylesheets
        const links = document.querySelectorAll('link[rel="stylesheet"][href]');
        for (const link of links) {
            const href = link.getAttribute('href');
            if (href && href.startsWith('http://')) {
                insecureStylesheets.push({
                    element: link,
                    href: href,
                    type: 'stylesheet',
                    media: link.getAttribute('media') || 'all',
                    riskLevel: 60 // Medium-high risk
                });
            }
        }

        // Check style elements with @import rules
        const styles = document.querySelectorAll('style');
        for (const style of styles) {
            const content = style.textContent || style.innerHTML;
            const importMatches = content.match(/@import\s+url\(['"]?http:\/\/[^'")\s]+['"]?\)/gi);
            
            if (importMatches) {
                insecureStylesheets.push({
                    element: style,
                    type: 'inline-style',
                    imports: importMatches,
                    riskLevel: 50
                });
            }
        }

        if (insecureStylesheets.length > 0) {
            return {
                detected: true,
                details: {
                    stylesheetsCount: insecureStylesheets.length,
                    externalStylesheets: insecureStylesheets.filter(s => s.type === 'stylesheet').length,
                    inlineStyles: insecureStylesheets.filter(s => s.type === 'inline-style').length
                },
                resources: insecureStylesheets,
                context: this.buildMixedContentContext('stylesheets', insecureStylesheets)
            };
        }

        return { detected: false };
    }

    checkMixedContentImages() {
        const insecureImages = [];
        const images = document.querySelectorAll('img[src]');

        for (const img of images) {
            const src = img.getAttribute('src');
            if (src && src.startsWith('http://')) {
                insecureImages.push({
                    element: img,
                    src: src,
                    type: 'image',
                    alt: img.getAttribute('alt'),
                    isVisible: this.isElementVisible(img),
                    dimensions: this.getElementDimensions(img),
                    riskLevel: 30 // Lower risk for images
                });
            }
        }

        // Check CSS background images
        const elementsWithBackgrounds = document.querySelectorAll('*');
        for (const element of elementsWithBackgrounds) {
            const style = window.getComputedStyle(element);
            const backgroundImage = style.backgroundImage;
            
            if (backgroundImage && backgroundImage.includes('http://')) {
                const httpUrls = this.extractHTTPUrls(backgroundImage);
                if (httpUrls.length > 0) {
                    insecureImages.push({
                        element: element,
                        type: 'background-image',
                        backgroundUrls: httpUrls,
                        riskLevel: 25
                    });
                }
            }
        }

        if (insecureImages.length > 0) {
            return {
                detected: true,
                details: {
                    imagesCount: insecureImages.length,
                    visibleImages: insecureImages.filter(img => img.isVisible).length,
                    backgroundImages: insecureImages.filter(img => img.type === 'background-image').length
                },
                resources: insecureImages,
                context: this.buildMixedContentContext('images', insecureImages)
            };
        }

        return { detected: false };
    }

    checkMixedContentIframes() {
        const insecureIframes = [];
        const iframes = document.querySelectorAll('iframe[src]');

        for (const iframe of iframes) {
            const src = iframe.getAttribute('src');
            if (src && src.startsWith('http://')) {
                insecureIframes.push({
                    element: iframe,
                    src: src,
                    type: 'iframe',
                    sandbox: iframe.getAttribute('sandbox'),
                    isVisible: this.isElementVisible(iframe),
                    dimensions: this.getElementDimensions(iframe),
                    riskLevel: this.calculateIframeRiskLevel(iframe, src)
                });
            }
        }

        if (insecureIframes.length > 0) {
            return {
                detected: true,
                details: {
                    iframesCount: insecureIframes.length,
                    sandboxedIframes: insecureIframes.filter(f => f.sandbox).length,
                    visibleIframes: insecureIframes.filter(f => f.isVisible).length
                },
                resources: insecureIframes,
                context: this.buildMixedContentContext('iframes', insecureIframes)
            };
        }

        return { detected: false };
    }

    checkMixedContentMedia() {
        const insecureMedia = [];
        
        // Check video elements
        const videos = document.querySelectorAll('video[src], video source[src]');
        for (const video of videos) {
            const src = video.getAttribute('src');
            if (src && src.startsWith('http://')) {
                insecureMedia.push({
                    element: video,
                    src: src,
                    type: 'video',
                    controls: video.hasAttribute('controls'),
                    autoplay: video.hasAttribute('autoplay'),
                    riskLevel: 40
                });
            }
        }

        // Check audio elements
        const audios = document.querySelectorAll('audio[src], audio source[src]');
        for (const audio of audios) {
            const src = audio.getAttribute('src');
            if (src && src.startsWith('http://')) {
                insecureMedia.push({
                    element: audio,
                    src: src,
                    type: 'audio',
                    controls: audio.hasAttribute('controls'),
                    autoplay: audio.hasAttribute('autoplay'),
                    riskLevel: 30
                });
            }
        }

        if (insecureMedia.length > 0) {
            return {
                detected: true,
                details: {
                    mediaCount: insecureMedia.length,
                    videos: insecureMedia.filter(m => m.type === 'video').length,
                    audios: insecureMedia.filter(m => m.type === 'audio').length,
                    autoplayMedia: insecureMedia.filter(m => m.autoplay).length
                },
                resources: insecureMedia,
                context: this.buildMixedContentContext('media', insecureMedia)
            };
        }

        return { detected: false };
    }

    checkMixedContentXHR() {
        // This is limited by content script permissions, but we can check for indicators
        const indicators = [];
        
        // Check for fetch/XHR patterns in inline scripts
        const scripts = document.querySelectorAll('script:not([src])');
        for (const script of scripts) {
            const content = script.textContent || script.innerHTML;
            
            // Look for HTTP URLs in fetch/XHR calls
            const fetchMatches = content.match(/fetch\s*\(\s*['"`]http:\/\/[^'"`]+['"`]/gi);
            const xhrMatches = content.match(/\.open\s*\(\s*['"`](?:GET|POST)['"`]\s*,\s*['"`]http:\/\/[^'"`]+['"`]/gi);
            
            if (fetchMatches || xhrMatches) {
                indicators.push({
                    element: script,
                    type: 'xhr-indication',
                    fetchCalls: fetchMatches || [],
                    xhrCalls: xhrMatches || [],
                    riskLevel: 70
                });
            }
        }

        if (indicators.length > 0) {
            return {
                detected: true,
                details: {
                    indicationsCount: indicators.length,
                    fetchCalls: indicators.reduce((sum, i) => sum + i.fetchCalls.length, 0),
                    xhrCalls: indicators.reduce((sum, i) => sum + i.xhrCalls.length, 0)
                },
                resources: indicators,
                context: this.buildMixedContentContext('xhr', indicators)
            };
        }

        return { detected: false };
    }

    extractHTTPUrls(content) {
        const httpUrlRegex = /http:\/\/[^\s'"()]+/gi;
        return content.match(httpUrlRegex) || [];
    }

    calculateScriptRiskLevel(script, src) {
        let risk = 70; // Base risk for mixed content script
        
        // Higher risk for certain domains/patterns
        if (src.includes('analytics') || src.includes('tracking')) {
            risk += 10;
        }
        
        if (src.includes('ads') || src.includes('advertisement')) {
            risk += 15;
        }
        
        // Lower risk if async/defer
        if (script.hasAttribute('async') || script.hasAttribute('defer')) {
            risk -= 5;
        }
        
        return Math.min(risk, 100);
    }

    calculateIframeRiskLevel(iframe, src) {
        let risk = 60; // Base risk for mixed content iframe
        
        // Higher risk for no sandbox
        if (!iframe.hasAttribute('sandbox')) {
            risk += 20;
        }
        
        // Higher risk for certain content types
        if (src.includes('payment') || src.includes('login')) {
            risk += 25;
        }
        
        return Math.min(risk, 100);
    }

    calculateAverageRisk(resources) {
        if (resources.length === 0) return 0;
        
        const totalRisk = resources.reduce((sum, resource) => sum + resource.riskLevel, 0);
        return Math.round(totalRisk / resources.length);
    }

    isElementVisible(element) {
        const rect = element.getBoundingClientRect();
        const style = window.getComputedStyle(element);
        
        return rect.width > 0 && 
               rect.height > 0 && 
               style.display !== 'none' && 
               style.visibility !== 'hidden';
    }

    getElementDimensions(element) {
        const rect = element.getBoundingClientRect();
        return {
            width: rect.width,
            height: rect.height
        };
    }

    buildMixedContentContext(resourceType, resources) {
        return {
            url: window.location.href,
            protocol: window.location.protocol,
            resourceType: resourceType,
            resourceCount: resources.length,
            hasMixedContent: true,
            averageRiskLevel: this.calculateAverageRisk(resources),
            visibleResources: resources.filter(r => r.isVisible !== false).length
        };
    }

    setupDynamicMonitoring() {
        // Monitor for dynamically added content
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        this.checkNewElement(node);
                    }
                });
            });
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    checkNewElement(element) {
        // Quick check for mixed content in new elements
        const tagName = element.tagName ? element.tagName.toLowerCase() : '';
        
        if (['script', 'img', 'iframe', 'link', 'video', 'audio'].includes(tagName)) {
            const src = element.getAttribute('src') || element.getAttribute('href');
            if (src && src.startsWith('http://')) {
                console.warn('Mixed content detected in dynamically added element:', element);
                // Could trigger re-detection here
            }
        }
    }

    getMetrics() {
        return {
            detectorCount: this.detectors.length,
            resourceCacheSize: this.resourceCache.size,
            observedResourcesCount: this.observedResources.size
        };
    }
}