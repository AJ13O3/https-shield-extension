#!/usr/bin/env python3
"""
Test script for Lambda function
Run this locally to test the Lambda handler before deployment
"""

import json
from lambda_function import lambda_handler

def test_valid_request():
    """Test with valid request"""
    print("Testing valid request...")
    
    test_event = {
        'body': json.dumps({
            'url': 'http://suspicious-site.com',
            'errorCode': 'ERR_CERT_DATE_INVALID'
        }),
        'requestContext': {
            'requestTime': '2024-01-15T12:00:00Z'
        }
    }
    
    response = lambda_handler(test_event, {})
    print(f"Status Code: {response['statusCode']}")
    print(f"Response Body: {json.dumps(json.loads(response['body']), indent=2)}")
    print("-" * 50)

def test_invalid_json():
    """Test with invalid JSON"""
    print("Testing invalid JSON...")
    
    test_event = {
        'body': 'invalid json',
    }
    
    response = lambda_handler(test_event, {})
    print(f"Status Code: {response['statusCode']}")
    print(f"Response Body: {response['body']}")
    print("-" * 50)

def test_empty_request():
    """Test with empty request"""
    print("Testing empty request...")
    
    test_event = {
        'body': json.dumps({})
    }
    
    response = lambda_handler(test_event, {})
    print(f"Status Code: {response['statusCode']}")
    print(f"Response Body: {json.dumps(json.loads(response['body']), indent=2)}")
    print("-" * 50)

def test_multiple_requests():
    """Test multiple requests to see random risk scores"""
    print("Testing multiple requests for different risk scores...")
    
    urls = [
        'http://example1.com',
        'http://example2.com',
        'http://example3.com'
    ]
    
    for url in urls:
        test_event = {
            'body': json.dumps({
                'url': url,
                'errorCode': 'ERR_CERT_AUTHORITY_INVALID'
            })
        }
        
        response = lambda_handler(test_event, {})
        body = json.loads(response['body'])
        print(f"URL: {url} - Risk: {body['riskLevel']} ({body['riskScore']}/100)")
    
    print("-" * 50)

if __name__ == "__main__":
    print("=" * 50)
    print("Lambda Function Test Suite")
    print("=" * 50)
    
    test_valid_request()
    test_invalid_json()
    test_empty_request()
    test_multiple_requests()
    
    print("All tests completed!")