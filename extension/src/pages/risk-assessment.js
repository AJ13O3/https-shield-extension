// Get URL parameters
const urlParams = new URLSearchParams(window.location.search);
let targetUrl = urlParams.get('target');
const tabId = urlParams.get('tabId');
const intercepted = urlParams.get('intercepted');

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
document.addEventListener('DOMContentLoaded', function() {
    // Start risk analysis
    analyzeRisk();
    
    // Set up button handlers
    document.getElementById('goBackBtn').addEventListener('click', goBack);
    document.getElementById('viewDetailsBtn').addEventListener('click', toggleDetails);
    document.getElementById('proceedBtn').addEventListener('click', proceedToSite);
    document.getElementById('learnMoreLink').addEventListener('click', learnMore);
});

async function analyzeRisk() {
    try {
        // Send message to background script to analyze the URL
        const response = await chrome.runtime.sendMessage({
            action: 'analyzeRisk',
            url: targetUrl
        });
        
        if (response && response.success) {
            displayRiskResults(response.data);
        } else {
            displayRiskError();
        }
    } catch (error) {
        console.error('Risk analysis error:', error);
        displayRiskError();
    }
}

function displayRiskResults(riskData) {
    // Hide loading, show results
    document.getElementById('riskLoading').style.display = 'none';
    document.getElementById('riskResults').style.display = 'block';
    
    // Determine risk level
    const riskScore = riskData.riskScore || 75; // Default high risk for HTTP
    let riskLevel, riskClass;
    
    if (riskScore >= 80) {
        riskLevel = 'CRITICAL';
        riskClass = 'critical';
    } else if (riskScore >= 60) {
        riskLevel = 'HIGH';
        riskClass = 'high';
    } else if (riskScore >= 40) {
        riskLevel = 'MEDIUM';
        riskClass = 'medium';
    } else {
        riskLevel = 'LOW';
        riskClass = 'low';
    }
    
    // Update risk display
    const riskValue = document.getElementById('riskValue');
    riskValue.textContent = riskLevel;
    riskValue.className = `risk-value ${riskClass}`;
    
    // Update risk bar
    const riskFill = document.getElementById('riskFill');
    riskFill.style.width = `${riskScore}%`;
    riskFill.className = `risk-fill ${riskClass}`;
    
    // Display risk details
    const riskDetails = riskData.details || [
        'No encryption for data transmission',
        'Potential for man-in-the-middle attacks',
        'Cannot verify site authenticity'
    ];
    
    const detailsHtml = '<ul>' + 
        riskDetails.map(detail => `<li>${detail}</li>`).join('') +
        '</ul>';
    document.getElementById('riskDetails').innerHTML = detailsHtml;
    
    // Store detailed info for advanced view
    if (riskData.advancedDetails) {
        document.getElementById('detailedRiskInfo').innerHTML = formatAdvancedDetails(riskData.advancedDetails);
    }
}

function displayRiskError() {
    document.getElementById('riskLoading').innerHTML = `
        <div class="error-message">
            <p>Unable to complete risk analysis</p>
            <p class="error-detail">Proceeding without risk assessment</p>
        </div>
    `;
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