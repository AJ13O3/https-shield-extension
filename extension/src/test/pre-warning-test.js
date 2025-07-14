// Pre-warning Interception System Test
// Tests the complete flow of intercepting HTTP requests before Chrome's HTTPS-only warning

class PreWarningTest {
    constructor() {
        this.testResults = [];
        this.currentTest = null;
    }

    // Run all tests
    async runAllTests() {
        console.log('Starting pre-warning interception tests...');
        
        const tests = [
            this.testBasicInterception.bind(this),
            this.testLocalAddressBypass.bind(this),
            this.testUserDecisionFlow.bind(this),
            this.testHttpsOnlyDetection.bind(this),
            this.testRateLimiting.bind(this),
            this.testNavigationFlow.bind(this),
            this.testErrorHandling.bind(this)
        ];
        
        for (const test of tests) {
            try {
                await test();
            } catch (error) {
                this.recordResult(false, `Test error: ${error.message}`);
            }
        }
        
        this.printResults();
        return this.testResults;
    }

    // Test 1: Basic HTTP interception
    async testBasicInterception() {
        this.startTest('Basic HTTP Interception');
        
        // Simulate HTTP request
        const testUrl = 'http://example.com';
        const mockDetails = {
            url: testUrl,
            type: 'main_frame',
            tabId: 12345,
            frameId: 0
        };
        
        // Send message to background script
        const response = await chrome.runtime.sendMessage({
            type: 'TEST_INTERCEPTION',
            details: mockDetails
        });
        
        // Verify redirection to risk assessment page
        const expectedRedirect = response.redirectUrl?.includes('risk-assessment.html');
        this.recordResult(expectedRedirect, 'HTTP request redirected to risk assessment');
    }

    // Test 2: Local address bypass
    async testLocalAddressBypass() {
        this.startTest('Local Address Bypass');
        
        const localUrls = [
            'http://localhost:3000',
            'http://127.0.0.1:8080',
            'http://192.168.1.100',
            'http://myapp.local'
        ];
        
        for (const url of localUrls) {
            const mockDetails = {
                url,
                type: 'main_frame',
                tabId: 12346,
                frameId: 0
            };
            
            const response = await chrome.runtime.sendMessage({
                type: 'TEST_INTERCEPTION',
                details: mockDetails
            });
            
            const bypassed = !response.redirectUrl;
            this.recordResult(bypassed, `Local address ${url} bypassed`);
        }
    }

    // Test 3: User decision flow
    async testUserDecisionFlow() {
        this.startTest('User Decision Flow');
        
        const testUrl = 'http://test.example.com';
        const tabId = 12347;
        
        // Step 1: Initial interception
        await chrome.runtime.sendMessage({
            type: 'TEST_INTERCEPTION',
            details: {
                url: testUrl,
                type: 'main_frame',
                tabId,
                frameId: 0
            }
        });
        
        // Step 2: User decides to proceed
        const proceedResponse = await chrome.runtime.sendMessage({
            action: 'addHttpBypass',
            url: testUrl,
            tabId
        });
        
        this.recordResult(proceedResponse.success, 'User proceed decision recorded');
        
        // Step 3: Verify subsequent request is not intercepted
        const secondResponse = await chrome.runtime.sendMessage({
            type: 'TEST_INTERCEPTION',
            details: {
                url: testUrl,
                type: 'main_frame',
                tabId,
                frameId: 0
            }
        });
        
        const notIntercepted = !secondResponse.redirectUrl;
        this.recordResult(notIntercepted, 'Subsequent request bypassed after user decision');
    }

    // Test 4: HTTPS-only mode detection
    async testHttpsOnlyDetection() {
        this.startTest('HTTPS-Only Mode Detection');
        
        const detectionResponse = await chrome.runtime.sendMessage({
            action: 'checkHttpsOnlyMode'
        });
        
        this.recordResult(
            detectionResponse.success,
            `HTTPS-only mode detection: ${detectionResponse.enabled ? 'Enabled' : 'Disabled'}`
        );
    }

    // Test 5: Rate limiting
    async testRateLimiting() {
        this.startTest('Rate Limiting');
        
        const testUrl = 'http://ratelimit.example.com';
        const tabId = 12348;
        let interceptCount = 0;
        
        // Send multiple requests rapidly
        for (let i = 0; i < 10; i++) {
            const response = await chrome.runtime.sendMessage({
                type: 'TEST_INTERCEPTION',
                details: {
                    url: testUrl,
                    type: 'main_frame',
                    tabId,
                    frameId: 0
                }
            });
            
            if (response.redirectUrl) {
                interceptCount++;
            }
        }
        
        // Should be rate limited after 5 requests
        const rateLimited = interceptCount <= 5;
        this.recordResult(rateLimited, `Rate limiting working: ${interceptCount}/10 intercepted`);
    }

    // Test 6: Navigation flow tracking
    async testNavigationFlow() {
        this.startTest('Navigation Flow Tracking');
        
        const testUrl = 'http://navigation.example.com';
        const tabId = 12349;
        
        // Start navigation
        const startResponse = await chrome.runtime.sendMessage({
            type: 'START_NAVIGATION',
            tabId,
            url: testUrl
        });
        
        this.recordResult(startResponse.success, 'Navigation tracking started');
        
        // Get navigation state
        const stateResponse = await chrome.runtime.sendMessage({
            type: 'GET_NAVIGATION_STATE',
            tabId
        });
        
        const hasState = stateResponse.state && stateResponse.state.originalUrl === testUrl;
        this.recordResult(hasState, 'Navigation state properly tracked');
    }

    // Test 7: Error handling
    async testErrorHandling() {
        this.startTest('Error Handling');
        
        // Test with invalid URL
        try {
            const response = await chrome.runtime.sendMessage({
                type: 'TEST_INTERCEPTION',
                details: {
                    url: 'not-a-valid-url',
                    type: 'main_frame',
                    tabId: 12350,
                    frameId: 0
                }
            });
            
            // Should handle gracefully
            this.recordResult(true, 'Invalid URL handled gracefully');
        } catch (error) {
            this.recordResult(false, 'Error not handled properly');
        }
        
        // Test risk assessment failure
        const riskResponse = await chrome.runtime.sendMessage({
            action: 'analyzeRisk',
            url: 'http://[invalid]'
        });
        
        const hasGracefulError = riskResponse.success || 
                                (riskResponse.data && riskResponse.data.riskScore);
        this.recordResult(hasGracefulError, 'Risk assessment error handled');
    }

    // Helper methods
    startTest(testName) {
        this.currentTest = testName;
        console.log(`\nRunning test: ${testName}`);
    }

    recordResult(passed, message) {
        const result = {
            test: this.currentTest,
            passed,
            message,
            timestamp: new Date().toISOString()
        };
        
        this.testResults.push(result);
        console.log(`  ${passed ? '✓' : '✗'} ${message}`);
    }

    printResults() {
        console.log('\n=== Test Results Summary ===');
        const passed = this.testResults.filter(r => r.passed).length;
        const total = this.testResults.length;
        
        console.log(`Total: ${total} | Passed: ${passed} | Failed: ${total - passed}`);
        console.log(`Success Rate: ${((passed / total) * 100).toFixed(1)}%`);
        
        if (passed < total) {
            console.log('\nFailed tests:');
            this.testResults
                .filter(r => !r.passed)
                .forEach(r => console.log(`  - ${r.test}: ${r.message}`));
        }
    }
}

// Export test runner
const preWarningTest = new PreWarningTest();

// Add test command to extension
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'RUN_PRE_WARNING_TESTS') {
        preWarningTest.runAllTests().then(results => {
            sendResponse({ success: true, results });
        });
        return true;
    }
});