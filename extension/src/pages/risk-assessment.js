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
    // Hide loading, show results
    document.getElementById('riskLoading').style.display = 'none';
    document.getElementById('riskResults').style.display = 'block';
    
    // Get risk data from API response
    const riskScore = riskData.riskScore || 75;
    const riskLevel = riskData.riskLevel || 'HIGH';
    const riskClass = riskLevel.toLowerCase();
    
    // Update risk display
    const riskValue = document.getElementById('riskValue');
    riskValue.textContent = riskLevel;
    riskValue.className = `risk-value ${riskClass}`;
    
    // Update risk bar
    const riskFill = document.getElementById('riskFill');
    riskFill.style.width = `${riskScore}%`;
    riskFill.className = `risk-fill ${riskClass}`;
    
    // Display recommendations instead of generic details
    const recommendations = riskData.recommendations || [
        'No encryption for data transmission',
        'Potential for man-in-the-middle attacks',
        'Cannot verify site authenticity'
    ];
    
    const detailsHtml = '<ul>' + 
        recommendations.map(rec => `<li>${rec}</li>`).join('') +
        '</ul>';
    document.getElementById('riskDetails').innerHTML = detailsHtml;
    
    // Store detailed analysis info for advanced view
    if (riskData.analysis) {
        document.getElementById('detailedRiskInfo').innerHTML = formatAdvancedAnalysis(riskData.analysis);
    }
    
    // Add data source indicator
    const sourceIndicator = riskData.source === 'mock' ? ' (Offline Mode)' : '';
    document.getElementById('riskValue').title = `Risk Level: ${riskLevel}${sourceIndicator}`;
    
    // Store risk data globally for chat widget
    window.riskAssessment = riskData;
    
    // Update chat widget if initialized
    if (chatWidget) {
        chatWidget.riskContext = {
            url: targetUrl,
            riskScore: riskScore,
            riskLevel: riskLevel,
            threats: riskData.threat_assessment || {},
            analysis: riskData.analysis || {},
            timestamp: new Date().toISOString()
        };
    }
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
    const details = document.getElementById('advancedDetails');
    const button = document.getElementById('viewDetailsBtn');
    
    if (details.style.display === 'none') {
        details.style.display = 'block';
        button.textContent = 'Hide Detailed Risks';
    } else {
        details.style.display = 'none';
        button.textContent = 'View Detailed Risks';
    }
}

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
        url: 'https://www.eff.org/https-everywhere/how-https-everywhere-works'
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
        
        // Prepare risk context
        const riskContext = {
            url: targetUrl,
            riskScore: window.riskAssessment?.riskScore || 50,
            riskLevel: window.riskAssessment?.riskLevel || 'MEDIUM',
            threats: window.riskAssessment?.threat_assessment || {},
            analysis: window.riskAssessment?.analysis || {},
            timestamp: new Date().toISOString(),
            sessionId: `risk_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
        };
        
        // Initialize chat widget
        chatWidget = new ChatWidget(container, riskContext);
        
        console.log('Chat widget initialized successfully');
        
    } catch (error) {
        console.error('Failed to initialize chat widget:', error);
    }
}