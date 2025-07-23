/**
 * API Key Configuration Script
 * 
 * This script helps you securely configure API keys for the HTTPS Shield extension.
 * Run this in the browser console on the extension's popup page.
 * 
 * IMPORTANT: Never commit API keys to version control!
 */

// Configuration function
async function configureAPIKeys() {
  console.log('🔐 HTTPS Shield API Key Configuration');
  console.log('====================================');
  
  // Get current configuration
  const existingConfig = await chrome.storage.sync.get(['apiConfig']);
  
  console.log('Current API Configuration:', existingConfig.apiConfig?.apiKey ? 'Configured ✅' : 'Not configured ❌');
  
  // Single API Key for both Risk Assessment and Chat endpoints
  const apiKey = prompt('Enter your API Key (from AWS API Gateway 7razok9dpj):\n\nThis key will be used for both /analyze-url and /chat endpoints.');
  
  if (apiKey && apiKey.trim()) {
    await chrome.storage.sync.set({
      apiConfig: {
        baseUrl: 'https://7razok9dpj.execute-api.eu-west-2.amazonaws.com/prod',
        apiKey: apiKey.trim()
      }
    });
    console.log('✅ API key configured for both endpoints');
    console.log('   📊 Risk Assessment: /analyze-url');
    console.log('   💬 Chat Assistant: /chat');
  } else {
    console.log('⚠️ API key configuration skipped');
    return false;
  }
  
  // Verify configuration
  const newConfig = await chrome.storage.sync.get(['apiConfig']);
  console.log('\n🎉 Configuration Complete!');
  console.log('API Key:', newConfig.apiConfig?.apiKey ? 'Configured ✅' : 'Not configured ❌');
  console.log('Base URL:', newConfig.apiConfig?.baseUrl || 'Not set');
  console.log('\nYou can now use the extension with full API functionality.');
  
  return true;
}

// Auto-run if in browser console
if (typeof chrome !== 'undefined' && chrome.storage) {
  console.log('🚀 Run configureAPIKeys() to set up your API keys');
} else {
  console.log('❌ This script must be run in a Chrome extension context');
}

// Export for manual use
window.configureAPIKeys = configureAPIKeys;