// Welcome page JavaScript

function testExtension() {
    // Open a test HTTP site in a new tab
    chrome.tabs.create({ url: 'http://example.com' });
}

function viewSettings() {
    // Open the extension popup
    // Note: chrome.action.openPopup() can only be called in response to a user gesture
    // and only works from the extension's popup or background script
    // Instead, we'll open the options page or show a message
    chrome.runtime.openOptionsPage();
}

// Set up event listeners when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Add click handlers to buttons
    const testBtn = document.getElementById('testBtn');
    const settingsBtn = document.getElementById('settingsBtn');
    
    if (testBtn) {
        testBtn.addEventListener('click', function(e) {
            e.preventDefault();
            testExtension();
        });
    }
    
    if (settingsBtn) {
        settingsBtn.addEventListener('click', function(e) {
            e.preventDefault();
            viewSettings();
        });
    }
    
    // Optional: Close this tab after a delay
    setTimeout(() => {
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('autoclose') === 'true') {
            window.close();
        }
    }, 10000);
});