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
  const existingConfig = await chrome.storage.sync.get(['apiConfig', 'chatApiConfig']);
  
  console.log('Current Risk Assessment API:', existingConfig.apiConfig?.apiKey ? 'Configured ✅' : 'Not configured ❌');
  console.log('Current Chat API:', existingConfig.chatApiConfig?.apiKey ? 'Configured ✅' : 'Not configured ❌');
  
  // Risk Assessment API Key
  const riskApiKey = prompt('Enter your Risk Assessment API Key (from AWS API Gateway 7razok9dpj):');
  if (riskApiKey && riskApiKey.trim()) {
    await chrome.storage.sync.set({
      apiConfig: {
        baseUrl: 'https://7razok9dpj.execute-api.eu-west-2.amazonaws.com/prod',
        apiKey: riskApiKey.trim()
      }
    });
    console.log('✅ Risk Assessment API key configured');
  } else {
    console.log('⚠️ Risk Assessment API key skipped');
  }
  
  // Chat API Key
  const chatApiKey = prompt('Enter your Chat API Key (from AWS API Gateway 8i76flzg45):');
  if (chatApiKey && chatApiKey.trim()) {
    await chrome.storage.sync.set({
      chatApiConfig: {
        endpoint: 'https://8i76flzg45.execute-api.eu-west-2.amazonaws.com/prod/chat',
        apiKey: chatApiKey.trim()
      }
    });
    console.log('✅ Chat API key configured');
  } else {
    console.log('⚠️ Chat API key skipped');
  }
  
  // Verify configuration
  const newConfig = await chrome.storage.sync.get(['apiConfig', 'chatApiConfig']);
  console.log('\n🎉 Configuration Complete!');
  console.log('Risk Assessment API:', newConfig.apiConfig?.apiKey ? 'Configured ✅' : 'Not configured ❌');
  console.log('Chat API:', newConfig.chatApiConfig?.apiKey ? 'Configured ✅' : 'Not configured ❌');
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