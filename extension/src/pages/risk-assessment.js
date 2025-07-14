// Get URL parameters
const urlParams = new URLSearchParams(window.location.search);
const targetUrl = urlParams.get('target');
const tabId = urlParams.get('tabId');

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

function proceedToSite() {
    if (!targetUrl) return;
    
    // Add this domain to the session bypass list
    chrome.runtime.sendMessage({
        action: 'addHttpBypass',
        url: targetUrl,
        tabId: tabId
    }, function(response) {
        if (response && response.success) {
            // Navigate to the original HTTP URL
            window.location.href = targetUrl;
        } else {
            console.error('Failed to add bypass');
            // Try to navigate anyway
            window.location.href = targetUrl;
        }
    });
}

function learnMore(e) {
    e.preventDefault();
    chrome.tabs.create({
        url: 'https://www.eff.org/https-everywhere/how-https-everywhere-works'
    });
}