// Get URL parameters
const urlParams = new URLSearchParams(window.location.search);
let targetUrl = urlParams.get('target');
const tabId = urlParams.get('tabId');
const intercepted = urlParams.get('intercepted');

// Initialize API client (will be loaded dynamically)
let apiClient = null;

// Chat widget instance
let chatWidget = null;

// Store risk assessment data globally for chat widget
window.riskAssessment = null;

// Handle intercepted URLs from declarativeNetRequest
if (intercepted === 'true' && targetUrl) {
    // The URL might be encoded from the regex substitution
    try {
        // If it's a full URL, use it directly
        if (targetUrl.startsWith('http://')) {
            targetUrl = targetUrl;
        } else {
            // Otherwise, try to decode it
            targetUrl = decodeURIComponent(targetUrl);
        }
    } catch (e) {
        console.error('Error decoding URL:', e);
    }
}

// Display the target URL
document.getElementById('targetUrl').textContent = targetUrl || 'Unknown URL';

// Initialize page
document.addEventListener('DOMContentLoaded', async function() {
    // Load API client dynamically
    try {
        const apiClientModule = await import(chrome.runtime.getURL('src/services/api-client.js'));
        const HTTPSShieldAPIClient = apiClientModule.default || apiClientModule.HTTPSShieldAPIClient;
        apiClient = new HTTPSShieldAPIClient();
        
        // Wait for API client to initialize
        await apiClient.initialize();
        
        // Start risk analysis
        analyzeRisk();
    } catch (error) {
        console.error('Failed to load API client:', error);
        displayAPIError('Failed to initialize security analysis system');
    }
    
    // Set up button handlers
    document.getElementById('goBackBtn').addEventListener('click', goBack);
    document.getElementById('viewDetailsBtn').addEventListener('click', toggleDetails);
    document.getElementById('proceedBtn').addEventListener('click', proceedToSite);
    document.getElementById('learnMoreLink').addEventListener('click', learnMore);
    
    // Modal handlers
    document.getElementById('closeModal').addEventListener('click', closeModal);
    document.getElementById('detailsModal').addEventListener('click', function(e) {
        if (e.target === this) closeModal();
    });
    
    // Initialize chat widget after a short delay to ensure DOM is ready
    setTimeout(initializeChatWidget, 1000);
});

async function analyzeRisk() {
    try {
        console.log('Starting risk analysis for:', targetUrl);
        
        if (apiClient) {
            // Use API client to analyze the URL
            const riskData = await apiClient.analyzeUrlRisk(targetUrl);
            
            if (riskData) {
                displayRiskResults(riskData);
            } else {
                displayAPIError('Security analysis returned no data');
            }
        } else {
            displayAPIError('Security analysis system not available');
        }
    } catch (error) {
        console.error('Risk analysis error:', error);
        
        // Determine specific error message based on error type
        let errorMessage = 'Security analysis failed';
        if (error.message.includes('timeout')) {
            errorMessage = 'Security analysis timed out - please try again';
        } else if (error.message.includes('403')) {
            errorMessage = 'Security analysis authentication failed';
        } else if (error.message.includes('500')) {
            errorMessage = 'Security analysis service is temporarily unavailable';
        } else if (error.message.includes('network')) {
            errorMessage = 'Network error during security analysis';
        }
        
        displayAPIError(errorMessage);
    }
}


function displayRiskResults(riskData) {
    // Check if required elements exist
    const loadingEl = document.getElementById('riskLoading');
    const resultsEl = document.getElementById('riskResults');
    const riskValueEl = document.getElementById('riskValue');
    const riskFillEl = document.getElementById('riskFill');
    const riskDetailsEl = document.getElementById('riskDetails');
    
    if (!loadingEl || !resultsEl || !riskValueEl || !riskFillEl || !riskDetailsEl) {
        console.error('Required DOM elements not found');
        return;
    }
    
    // Hide loading, show results
    loadingEl.style.display = 'none';
    resultsEl.style.display = 'block';
    
    // Get risk data from API response
    const riskScore = Math.round(riskData.riskScore || 75);
    const riskLevel = riskData.riskLevel || 'HIGH';
    const riskClass = riskLevel.toLowerCase();
    
    // Create tooltip text
    const tooltipText = `Risk score: ${riskScore}/100. Based on AI threat analysis, domain reputation, and security checks.`;
    
    // Update risk display with tooltip
    riskValueEl.textContent = `${riskLevel} (${riskScore}/100)`;
    riskValueEl.className = `risk-value ${riskClass}`;
    riskValueEl.setAttribute('data-tooltip', tooltipText);
    
    // Update risk bar
    riskFillEl.style.width = `${riskScore}%`;
    riskFillEl.className = `risk-fill ${riskClass}`;
    
    // Display risk score details only - no hardcoded recommendations
    const detailsHtml = `
        <div class="risk-score-details">
            <p><strong>Risk Score:</strong> ${riskScore}/100</p>
            <p><strong>Domain:</strong> ${riskData.domain || 'Unknown'}</p>
            <p><strong>Protocol:</strong> ${riskData.protocol || 'Unknown'}</p>
        </div>
    `;
    riskDetailsEl.innerHTML = detailsHtml;
    
    // Debug log to check the actual Lambda response structure
    console.log('Full Lambda response data:', riskData);
    
    // Store threat assessment data globally for modal view
    if (riskData.threat_assessment) {
        window.threatAssessmentData = riskData.threat_assessment;
    }
    
    // Add data source indicator
    const sourceIndicator = riskData.source === 'mock' ? ' (Offline Mode)' : '';
    document.getElementById('riskValue').title = `Risk Level: ${riskLevel}${sourceIndicator}`;
    
    // Generate unique assessment ID from timestamp and URL hash
    const assessmentId = `assess_${Date.now()}_${btoa(targetUrl).slice(0, 8)}`;
    
    // Store complete risk data globally for chat widget
    window.riskAssessment = {
        ...riskData,
        assessmentId: assessmentId
    };
    
    // Update chat widget if initialized
    if (chatWidget) {
        chatWidget.riskContext = {
            url: targetUrl,
            riskScore: riskScore,
            riskLevel: riskLevel,
            domain: riskData.domain,
            protocol: riskData.protocol,
            errorCode: riskData.errorCode,
            threats: riskData.threat_assessment || {},
            threat_assessment: riskData.threat_assessment || {},
            analysis: riskData.analysis || {},
            assessmentId: assessmentId,
            timestamp: riskData.timestamp || new Date().toISOString()
        };
    }
}

function formatThreatAssessment(threatData) {
    if (!threatData) return '<p>No threat assessment data available.</p>';
    
    let html = '<div class="threat-assessment">';
    
    // Display raw threat data
    if (threatData.final_risk_score !== undefined) {
        html += `<p><strong>Final Risk Score:</strong> ${threatData.final_risk_score}</p>`;
    }
    
    if (threatData.individual_scores) {
        html += '<h4>Individual Scores:</h4><ul>';
        for (const [source, score] of Object.entries(threatData.individual_scores)) {
            html += `<li><strong>${source}:</strong> ${score}</li>`;
        }
        html += '</ul>';
    }
    
    html += '</div>';
    return html;
}

function formatAdvancedAnalysis(analysis) {
    if (!analysis) return '<p>No detailed analysis available.</p>';
    
    let html = '<div class="advanced-analysis">';
    
    // Protocol Analysis
    if (analysis.protocol_analysis) {
        html += '<div class="analysis-section">';
        html += '<h4>Protocol Analysis</h4>';
        html += `<p><strong>Protocol:</strong> ${analysis.protocol_analysis.protocol?.toUpperCase() || 'Unknown'}</p>`;
        html += `<p><strong>Secure:</strong> ${analysis.protocol_analysis.secure ? 'Yes' : 'No'}</p>`;
        if (analysis.protocol_analysis.risk_factors?.length > 0) {
            html += '<ul>';
            analysis.protocol_analysis.risk_factors.forEach(factor => {
                html += `<li>${factor}</li>`;
            });
            html += '</ul>';
        }
        html += '</div>';
    }
    
    // Domain Analysis
    if (analysis.domain_analysis) {
        html += '<div class="analysis-section">';
        html += '<h4>Domain Analysis</h4>';
        html += `<p><strong>Domain:</strong> ${analysis.domain_analysis.domain || 'Unknown'}</p>`;
        html += `<p><strong>Length:</strong> ${analysis.domain_analysis.length || 'Unknown'} characters</p>`;
        if (analysis.domain_analysis.subdomain_count !== undefined) {
            html += `<p><strong>Subdomains:</strong> ${analysis.domain_analysis.subdomain_count}</p>`;
        }
        if (analysis.domain_analysis.risk_indicators?.length > 0) {
            html += '<p><strong>Risk Indicators:</strong></p><ul>';
            analysis.domain_analysis.risk_indicators.forEach(indicator => {
                html += `<li>${indicator}</li>`;
            });
            html += '</ul>';
        }
        html += '</div>';
    }
    
    // Error Analysis
    if (analysis.error_analysis && analysis.error_analysis.error_code) {
        html += '<div class="analysis-section">';
        html += '<h4>Error Analysis</h4>';
        html += `<p><strong>Error Code:</strong> ${analysis.error_analysis.error_code}</p>`;
        html += `<p><strong>Severity:</strong> ${analysis.error_analysis.severity}</p>`;
        if (analysis.error_analysis.description) {
            html += `<p><strong>Description:</strong> ${analysis.error_analysis.description}</p>`;
        }
        if (analysis.error_analysis.risk_factors?.length > 0) {
            html += '<p><strong>Risk Factors:</strong></p><ul>';
            analysis.error_analysis.risk_factors.forEach(factor => {
                html += `<li>${factor}</li>`;
            });
            html += '</ul>';
        }
        html += '</div>';
    }
    
    // URL Structure Analysis
    if (analysis.url_structure) {
        html += '<div class="analysis-section">';
        html += '<h4>URL Structure Analysis</h4>';
        html += `<p><strong>URL Length:</strong> ${analysis.url_structure.length || 'Unknown'} characters</p>`;
        if (analysis.url_structure.risk_indicators?.length > 0) {
            html += '<p><strong>Risk Indicators:</strong></p><ul>';
            analysis.url_structure.risk_indicators.forEach(indicator => {
                html += `<li>${indicator}</li>`;
            });
            html += '</ul>';
        }
        html += '</div>';
    }
    
    html += '</div>';
    return html;
}

function displayRiskError() {
    displayAPIError('Unable to complete security analysis');
}

function displayAPIError(message) {
    // Hide loading, show error
    document.getElementById('riskLoading').style.display = 'none';
    document.getElementById('riskResults').style.display = 'none';
    
    // Create error display
    const errorHtml = `
        <div class="api-error-container">
            <div class="error-icon">⚠️</div>
            <div class="error-content">
                <h3>Security Analysis Unavailable</h3>
                <p class="error-message">${message}</p>
                <p class="error-explanation">
                    HTTPS Shield requires AI-powered security analysis to protect you from potential threats. 
                    Without this analysis, we cannot safely assess the security risks of this HTTP site.
                </p>
                <div class="error-actions">
                    <button id="retryAnalysis" class="retry-btn">Retry Analysis</button>
                    <button id="proceedWithoutAnalysis" class="proceed-unsafe-btn">Proceed Without Analysis (Not Recommended)</button>
                </div>
            </div>
        </div>
    `;
    
    // Replace the risk loading section with error display
    document.getElementById('riskLoading').innerHTML = errorHtml;
    document.getElementById('riskLoading').style.display = 'block';
    
    // Add event listeners for error action buttons
    document.getElementById('retryAnalysis').addEventListener('click', () => {
        // Reset to loading state and retry
        document.getElementById('riskLoading').innerHTML = `
            <div class="loading-spinner"></div>
            <div class="loading-text">Analyzing security risks...</div>
        `;
        analyzeRisk();
    });
    
    document.getElementById('proceedWithoutAnalysis').addEventListener('click', () => {
        // Show warning and proceed
        if (confirm('Are you sure you want to proceed without security analysis?\\n\\nThis HTTP site may pose security risks that have not been assessed.')) {
            proceedToSite();
        }
    });
}

function formatAdvancedDetails(details) {
    let html = '<div class="advanced-info">';
    
    if (details.domainInfo) {
        html += `
            <div class="detail-section">
                <h4>Domain Information</h4>
                <p>Age: ${details.domainInfo.age || 'Unknown'}</p>
                <p>Registrar: ${details.domainInfo.registrar || 'Unknown'}</p>
                <p>SSL Support: ${details.domainInfo.sslSupport || 'Not available'}</p>
            </div>
        `;
    }
    
    if (details.securityIssues) {
        html += `
            <div class="detail-section">
                <h4>Security Issues</h4>
                <ul>
                    ${details.securityIssues.map(issue => `<li>${issue}</li>`).join('')}
                </ul>
            </div>
        `;
    }
    
    if (details.reputation) {
        html += `
            <div class="detail-section">
                <h4>Reputation Data</h4>
                <p>Trust Score: ${details.reputation.trustScore || 'N/A'}</p>
                <p>Reports: ${details.reputation.reports || 'None'}</p>
            </div>
        `;
    }
    
    html += '</div>';
    return html;
}

function goBack() {
    // Try to go back in history, or close the tab
    if (window.history.length > 1) {
        window.history.back();
    } else {
        chrome.runtime.sendMessage({
            action: 'closeTab',
            tabId: tabId
        });
    }
}

function toggleDetails() {
    const modal = document.getElementById('detailsModal');
    modal.classList.add('active');
    
    // Format and display detailed risk information in modal
    if (window.threatAssessmentData) {
        displayDetailedRisks(window.threatAssessmentData);
    } else if (window.riskAssessment && window.riskAssessment.threat_assessment) {
        displayDetailedRisks(window.riskAssessment.threat_assessment);
    } else {
        // Show a message if no detailed data is available
        document.getElementById('modalBody').innerHTML = '<p>No detailed risk information available.</p>';
    }
}

function closeModal() {
    const modal = document.getElementById('detailsModal');
    modal.classList.remove('active');
}

function displayDetailedRisks(threatAssessment) {
    const container = document.getElementById('modalBody');
    if (!container || !threatAssessment) return;
    
    const { full_responses = {}, individual_scores = {}, final_risk_score } = threatAssessment;
    
    let html = '<div class="risk-accordion">';
    
    // Overall Risk Summary
    html += `
        <div class="accordion-item">
            <h4 class="accordion-header">
                <span class="accordion-icon">▼</span>
                Overall Risk Assessment
                <span class="risk-badge ${getRiskClass(final_risk_score)}">${final_risk_score?.toFixed(1) || 'N/A'}/100</span>
            </h4>
            <div class="accordion-content" style="display: block;">
                <p><strong>Combined Risk Score:</strong> ${final_risk_score?.toFixed(2) || 'N/A'}/100</p>
                <p><strong>Risk Level:</strong> ${window.riskAssessment?.riskLevel || 'Unknown'}</p>
                <p><strong>Assessment Method:</strong> Threat-weighted aggregation</p>
                <div class="individual-scores">
                    <h5>Individual Service Scores:</h5>
                    <ul>
                        ${Object.entries(individual_scores).map(([service, score]) => 
                            `<li><strong>${formatServiceName(service)}:</strong> ${typeof score === 'number' ? score.toFixed(2) : score}</li>`
                        ).join('')}
                    </ul>
                </div>
            </div>
        </div>
    `;
    
    // URLBERT Analysis
    if (full_responses.urlbert) {
        const urlbert = full_responses.urlbert;
        html += `
            <div class="accordion-item">
                <h4 class="accordion-header">
                    <span class="accordion-icon">▶</span>
                    AI URL Analysis (URLBERT)
                    <span class="risk-badge ${urlbert.classification === 'malicious' ? 'critical' : 'low'}">${urlbert.classification || 'Unknown'}</span>
                </h4>
                <div class="accordion-content">
                    <p><strong>Classification:</strong> ${urlbert.classification || 'Unknown'}</p>
                    <p><strong>Confidence:</strong> ${urlbert.confidence ? (urlbert.confidence * 100).toFixed(1) + '%' : 'N/A'}</p>
                    <p><strong>Model Score:</strong> ${urlbert.risk_score?.toFixed(2) || 'N/A'}/100</p>
                </div>
            </div>
        `;
    }
    
    // Google Safe Browsing
    if (full_responses.google_safebrowsing) {
        const gsb = full_responses.google_safebrowsing;
        const threats = gsb.threats || [];
        html += `
            <div class="accordion-item">
                <h4 class="accordion-header">
                    <span class="accordion-icon">▶</span>
                    Google Safe Browsing
                    <span class="risk-badge ${threats.length > 0 ? 'critical' : 'low'}">${threats.length > 0 ? 'Threats Found' : 'Clear'}</span>
                </h4>
                <div class="accordion-content">
                    ${threats.length > 0 ? `
                        <div class="threat-list">
                            <h5>Detected Threats:</h5>
                            <ul>
                                ${threats.map(threat => `
                                    <li class="threat-item">
                                        <strong>${threat.type || 'Unknown Threat'}</strong>
                                        ${threat.platform ? `<br>Platform: ${threat.platform}` : ''}
                                        ${threat.threatEntryType ? `<br>Entry Type: ${threat.threatEntryType}` : ''}
                                    </li>
                                `).join('')}
                            </ul>
                        </div>
                    ` : '<p class="all-clear">✅ No threats detected by Google Safe Browsing</p>'}
                </div>
            </div>
        `;
    }
    
    // VirusTotal
    if (full_responses.virustotal) {
        const vt = full_responses.virustotal;
        console.log('VirusTotal data:', vt);
        const fullResponse = vt.full_response || vt || {};
        const positives = fullResponse.positives || vt.positives || 0;
        const total = fullResponse.total || vt.total || 0;
        html += `
            <div class="accordion-item">
                <h4 class="accordion-header">
                    <span class="accordion-icon">▶</span>
                    VirusTotal Security Scan
                    <span class="risk-badge ${positives > 0 ? 'high' : 'low'}">${positives}/${total} detections</span>
                </h4>
                <div class="accordion-content">
                    <p><strong>Scan Date:</strong> ${fullResponse.scan_date || vt.scan_date || 'N/A'}</p>
                    <p><strong>Detections:</strong> ${positives} out of ${total} engines</p>
                    <p><strong>Detection Ratio:</strong> ${total > 0 ? ((positives / total) * 100).toFixed(1) + '%' : '0.0%'}</p>
                    ${fullResponse.permalink || vt.permalink ? `<p><a href="${fullResponse.permalink || vt.permalink}" target="_blank" rel="noopener">View full report →</a></p>` : ''}
                </div>
            </div>
        `;
    }
    
    // WHOIS Domain Information
    if (full_responses.whois) {
        const whois = full_responses.whois;
        html += `
            <div class="accordion-item">
                <h4 class="accordion-header">
                    <span class="accordion-icon">▶</span>
                    Domain Information (WHOIS)
                    <span class="risk-badge medium">Score: ${(whois.risk_score * 100).toFixed(0)}/100</span>
                </h4>
                <div class="accordion-content">
                    <p><strong>Domain Age:</strong> ${whois.domain_age_days ? whois.domain_age_days + ' days' : 'Unknown'}</p>
                    <p><strong>Registrar:</strong> ${whois.registrar || 'Unknown'}</p>
                    <p><strong>Creation Date:</strong> ${whois.creation_date || 'Unknown'}</p>
                    <p><strong>Expiration Date:</strong> ${whois.expiration_date || 'Unknown'}</p>
                    <p><strong>Privacy Protected:</strong> ${whois.is_privacy_protected ? 'Yes' : 'No'}</p>
                    <p><strong>Risk Signals:</strong></p>
                    <ul>
                        ${whois.domain_age_days < 30 ? '<li>⚠️ Very new domain (less than 30 days old)</li>' : ''}
                        ${whois.is_privacy_protected ? '<li>⚠️ WHOIS privacy enabled</li>' : ''}
                        ${whois.risk_score > 0.7 ? '<li>⚠️ High risk domain characteristics</li>' : ''}
                    </ul>
                </div>
            </div>
        `;
    }
    
    html += '</div>';
    container.innerHTML = html;
    
    // Add event listeners for accordion headers after DOM is updated
    setTimeout(() => {
        const accordionHeaders = container.querySelectorAll('.accordion-header');
        accordionHeaders.forEach(header => {
            header.style.cursor = 'pointer';
            header.addEventListener('click', function() {
                toggleAccordion(this);
            });
        });
    }, 0);
}

function formatServiceName(service) {
    const names = {
        'urlbert': 'URLBERT AI',
        'google_safebrowsing': 'Google Safe Browsing',
        'virustotal': 'VirusTotal',
        'whois': 'WHOIS Domain Info'
    };
    return names[service] || service;
}

function getRiskClass(score) {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    return 'low';
}

function toggleAccordion(header) {
    const content = header.nextElementSibling;
    const icon = header.querySelector('.accordion-icon');
    const isCurrentlyOpen = content.style.display === 'block';
    
    // Close all accordions first
    const allAccordions = document.querySelectorAll('.accordion-header');
    allAccordions.forEach(accordionHeader => {
        const accordionContent = accordionHeader.nextElementSibling;
        const accordionIcon = accordionHeader.querySelector('.accordion-icon');
        if (accordionContent && accordionIcon) {
            accordionContent.style.display = 'none';
            accordionIcon.textContent = '▶';
        }
    });
    
    // If the clicked accordion was closed, open it
    if (!isCurrentlyOpen) {
        content.style.display = 'block';
        icon.textContent = '▼';
    }
}

// Make toggleAccordion available globally for onclick handlers
window.toggleAccordion = toggleAccordion;

async function proceedToSite() {
    if (!targetUrl) return;
    
    const proceedBtn = document.getElementById('proceedBtn');
    const originalText = proceedBtn.innerHTML;
    
    // Show loading state
    proceedBtn.disabled = true;
    proceedBtn.textContent = 'Setting up secure bypass...';
    proceedBtn.style.opacity = '0.7';
    
    let retries = 0;
    const maxRetries = 3;
    
    const attemptBypass = async () => {
        try {
            console.log(`Requesting bypass for: ${targetUrl} (attempt ${retries + 1})`);
            
            const response = await chrome.runtime.sendMessage({
                action: 'allowHttpOnce',
                url: targetUrl,
                tabId: tabId ? parseInt(tabId) : null
            });
            
            if (response && response.success) {
                console.log('Bypass rule created successfully:', response);
                
                // Update UI to show navigation is starting
                proceedBtn.textContent = 'Navigating to site...';
                
                // Wait a bit for rule to be fully processed, then navigate
                setTimeout(() => {
                    try {
                        // Use location.replace for better navigation in extension context
                        window.location.replace(targetUrl);
                    } catch (navError) {
                        console.error('Navigation error:', navError);
                        // Fallback: try using chrome.tabs.update if available
                        if (tabId) {
                            chrome.runtime.sendMessage({
                                action: 'navigateTab',
                                tabId: parseInt(tabId),
                                url: targetUrl
                            });
                        } else {
                            // Last resort: simple location assignment
                            window.location.href = targetUrl;
                        }
                    }
                }, 500); // Increased delay to ensure rule is fully active
                
            } else {
                throw new Error(response?.error || 'Bypass request failed');
            }
        } catch (error) {
            console.error('Bypass attempt failed:', error);
            if (retries < maxRetries) {
                retries++;
                proceedBtn.textContent = `Retrying... (${retries}/${maxRetries})`;
                setTimeout(attemptBypass, 1000); // Increased retry delay
            } else {
                // All retries failed, restore button
                proceedBtn.disabled = false;
                proceedBtn.innerHTML = originalText;
                proceedBtn.style.opacity = '1';
                
                // Show more helpful error message
                const errorMsg = error.message || 'Unknown error occurred';
                alert(`Unable to proceed to the site: ${errorMsg}\n\nPlease try again or contact support if the problem persists.`);
            }
        }
    };
    
    // Start the bypass attempt
    await attemptBypass();
}

function learnMore(e) {
    e.preventDefault();
    chrome.tabs.create({
        url: 'https://www.ncsc.gov.uk/collection/top-tips-for-staying-secure-online'
    });
}

/**
 * Initialize the chat widget with current risk context
 */
function initializeChatWidget() {
    try {
        console.log('Initializing chat widget...');
        
        // Check if chat components are available
        if (typeof ChatWidget === 'undefined' || typeof ChatService === 'undefined') {
            console.warn('Chat components not loaded, retrying in 2 seconds...');
            setTimeout(initializeChatWidget, 2000);
            return;
        }
        
        const container = document.getElementById('chatWidgetContainer');
        if (!container) {
            console.error('Chat widget container not found');
            return;
        }
        
        // Prepare risk context with complete data - NO FALLBACKS
        const riskContext = {
            url: targetUrl,
            riskScore: window.riskAssessment?.riskScore,
            riskLevel: window.riskAssessment?.riskLevel,
            domain: window.riskAssessment?.domain,
            protocol: window.riskAssessment?.protocol,
            errorCode: window.riskAssessment?.errorCode,
            threats: window.riskAssessment?.threat_assessment || {},
            threat_assessment: window.riskAssessment?.threat_assessment || {},
            analysis: window.riskAssessment?.analysis || {},
            assessmentId: window.riskAssessment?.assessmentId,
            timestamp: window.riskAssessment?.timestamp || new Date().toISOString(),
            sessionId: `risk_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
        };
        
        // Initialize chat widget
        chatWidget = new ChatWidget(container, riskContext);
        
        console.log('Chat widget initialized successfully');
        
    } catch (error) {
        console.error('Failed to initialize chat widget:', error);
    }
}