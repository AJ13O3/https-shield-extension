"""
HTTPS Shield URL Risk Assessment Lambda Function

This Lambda function analyzes URLs for security risks and provides recommendations.
It integrates with DynamoDB for caching and external APIs for enhanced analysis.

Author: HTTPS Shield Extension Team
Version: 1.0.0
"""

import json
import os
import re
import hashlib
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse
from typing import Dict, Any, Optional, List
import boto3
from botocore.exceptions import ClientError
from decimal import Decimal

# Import logger configuration
from logger_config import setup_logger, log_lambda_event, log_performance_metric, log_error, log_api_request

# Configure logging
logger = setup_logger(__name__)

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb')
table_name = os.environ.get('DYNAMODB_TABLE_NAME', 'https-shield-risk-assessments')

# Cache for DynamoDB table reference
_dynamodb_table = None

def get_dynamodb_table():
    """Get DynamoDB table instance with caching"""
    global _dynamodb_table
    if _dynamodb_table is None:
        _dynamodb_table = dynamodb.Table(table_name)
    return _dynamodb_table

class DecimalEncoder(json.JSONEncoder):
    """Custom JSON encoder for DynamoDB Decimal objects"""
    def default(self, obj):
        if isinstance(obj, Decimal):
            # Convert Decimal to int if it's a whole number, otherwise float
            if obj % 1 == 0:
                return int(obj)
            else:
                return float(obj)
        return super(DecimalEncoder, self).default(obj)

def lambda_handler(event, context):
    """
    Main Lambda handler for HTTPS risk assessment
    
    Expected input:
    {
        "url": "http://example.com",
        "errorCode": "ERR_CERT_DATE_INVALID",
        "userAgent": "Mozilla/5.0...",
        "timestamp": "2024-01-15T10:30:00Z"
    }
    
    Returns:
    {
        "statusCode": 200,
        "body": {
            "url": "http://example.com",
            "riskScore": 75,
            "riskLevel": "HIGH",
            "analysis": {...},
            "recommendations": [...],
            "timestamp": "2024-01-15T10:30:00Z"
        }
    }
    """
    start_time = time.time()
    
    try:
        # Log Lambda invocation
        log_lambda_event(logger, event, context)
        
        # Parse request
        if 'body' in event:
            body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
        else:
            body = event
            
        url = body.get('url', '')
        error_code = body.get('errorCode', '')
        user_agent = body.get('userAgent', '')
        
        # Input validation
        if not url:
            logger.warning("Request rejected: URL is required")
            return error_response(400, 'URL is required')
            
        if not url.startswith(('http://', 'https://')):
            logger.warning(f"Request rejected: Invalid URL format: {url}")
            return error_response(400, 'Invalid URL format')
        
        logger.info(f"Starting risk analysis for URL: {url}")
        
        # Generate cache key
        cache_key = generate_cache_key(url, error_code)
        
        # Check cache first
        cache_start = time.time()
        cached_result = get_cached_assessment(cache_key)
        log_performance_metric(logger, 'cache_lookup', (time.time() - cache_start) * 1000)
        
        if cached_result:
            logger.info(f"Cache hit for URL: {url}")
            log_performance_metric(logger, 'total_request', (time.time() - start_time) * 1000, cache_hit=True)
            return success_response(cached_result)
        
        # Perform risk assessment
        assessment_start = time.time()
        assessment = perform_risk_assessment(url, error_code, user_agent)
        log_performance_metric(logger, 'risk_assessment', (time.time() - assessment_start) * 1000)
        
        # Cache the result
        cache_write_start = time.time()
        cache_assessment(cache_key, assessment)
        log_performance_metric(logger, 'cache_write', (time.time() - cache_write_start) * 1000)
        
        # Log final metrics
        total_duration = (time.time() - start_time) * 1000
        log_performance_metric(logger, 'total_request', total_duration, cache_hit=False)
        
        logger.info(f"Risk assessment complete: {assessment['riskLevel']} ({assessment['riskScore']}/100)")
        return success_response(assessment)
        
    except json.JSONDecodeError as e:
        log_error(logger, e, {'event': event})
        return error_response(400, 'Invalid request body')
        
    except Exception as e:
        log_error(logger, e, {'event': event, 'url': url if 'url' in locals() else 'unknown'})
        return error_response(500, 'Internal server error')

def perform_risk_assessment(url: str, error_code: str, user_agent: str) -> Dict[str, Any]:
    """
    Perform comprehensive risk assessment for a URL
    
    Args:
        url: The URL to analyze
        error_code: Browser error code (if any)
        user_agent: User agent string
        
    Returns:
        Dictionary containing risk assessment results
    """
    parsed_url = urlparse(url)
    
    # Initialize assessment
    assessment = {
        'url': url,
        'domain': parsed_url.netloc,
        'protocol': parsed_url.scheme,
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'analysis': {
            'domain_analysis': analyze_domain(parsed_url.netloc),
            'protocol_analysis': analyze_protocol(parsed_url.scheme),
            'error_analysis': analyze_error_code(error_code),
            'url_structure': analyze_url_structure(url)
        }
    }
    
    # Calculate risk score
    risk_score = calculate_risk_score(assessment['analysis'])
    assessment['riskScore'] = risk_score
    assessment['riskLevel'] = get_risk_level(risk_score)
    assessment['recommendations'] = get_recommendations(assessment['riskLevel'], assessment['analysis'])
    
    return assessment

def analyze_domain(domain: str) -> Dict[str, Any]:
    """Analyze domain for security indicators"""
    analysis = {
        'length': len(domain),
        'subdomain_count': len(domain.split('.')) - 2,
        'suspicious_patterns': [],
        'risk_indicators': []
    }
    
    # Check for suspicious patterns
    suspicious_patterns = [
        r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
        r'[a-zA-Z0-9-]+\.tk$',  # Suspicious TLDs
        r'[a-zA-Z0-9-]+\.ml$',
        r'[a-zA-Z0-9-]+\.ga$',
        r'[a-zA-Z0-9-]+\.cf$',
        r'.*-[0-9]+\..*',  # Numbered subdomains
        r'.*[0-9]{4,}.*',  # Long number sequences
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, domain):
            analysis['suspicious_patterns'].append(pattern)
    
    # Domain length analysis
    if len(domain) > 50:
        analysis['risk_indicators'].append('Very long domain name')
    elif len(domain) > 30:
        analysis['risk_indicators'].append('Long domain name')
    
    # Subdomain analysis
    if analysis['subdomain_count'] > 3:
        analysis['risk_indicators'].append('Multiple subdomains')
    
    return analysis

def analyze_protocol(protocol: str) -> Dict[str, Any]:
    """Analyze protocol for security"""
    analysis = {
        'protocol': protocol,
        'secure': protocol == 'https',
        'risk_level': 'LOW' if protocol == 'https' else 'HIGH'
    }
    
    if protocol == 'http':
        analysis['risk_factors'] = [
            'No encryption for data transmission',
            'Susceptible to man-in-the-middle attacks',
            'Cannot verify server authenticity'
        ]
    else:
        analysis['risk_factors'] = []
    
    return analysis

def analyze_error_code(error_code: str) -> Dict[str, Any]:
    """Analyze browser error codes"""
    error_analysis = {
        'error_code': error_code,
        'severity': 'UNKNOWN',
        'description': 'Unknown error',
        'risk_factors': []
    }
    
    error_mappings = {
        'ERR_CERT_DATE_INVALID': {
            'severity': 'HIGH',
            'description': 'Certificate has expired or is not yet valid',
            'risk_factors': ['Expired or invalid certificate', 'Potential phishing site']
        },
        'ERR_CERT_AUTHORITY_INVALID': {
            'severity': 'HIGH',
            'description': 'Certificate not issued by trusted authority',
            'risk_factors': ['Untrusted certificate authority', 'Possible man-in-the-middle attack']
        },
        'ERR_CERT_COMMON_NAME_INVALID': {
            'severity': 'HIGH',
            'description': 'Certificate hostname mismatch',
            'risk_factors': ['Certificate hostname mismatch', 'Potential spoofing attempt']
        },
        'ERR_SSL_PROTOCOL_ERROR': {
            'severity': 'MEDIUM',
            'description': 'SSL/TLS protocol error',
            'risk_factors': ['SSL/TLS configuration issues', 'Potential downgrade attack']
        },
        'ERR_INSECURE_RESPONSE': {
            'severity': 'MEDIUM',
            'description': 'Mixed content detected',
            'risk_factors': ['Mixed HTTP/HTTPS content', 'Partial encryption']
        }
    }
    
    if error_code in error_mappings:
        error_analysis.update(error_mappings[error_code])
    
    return error_analysis

def analyze_url_structure(url: str) -> Dict[str, Any]:
    """Analyze URL structure for suspicious patterns"""
    analysis = {
        'length': len(url),
        'suspicious_patterns': [],
        'risk_indicators': []
    }
    
    # Check for suspicious URL patterns
    suspicious_patterns = [
        r'bit\.ly|tinyurl|t\.co',  # URL shorteners
        r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
        r'[a-zA-Z0-9-]+\.tk|\.ml|\.ga|\.cf',  # Suspicious TLDs
        r'[a-zA-Z0-9-]*phishing[a-zA-Z0-9-]*',  # Phishing keywords
        r'[a-zA-Z0-9-]*secure[a-zA-Z0-9-]*',  # Fake security keywords
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            analysis['suspicious_patterns'].append(pattern)
    
    # URL length analysis
    if len(url) > 200:
        analysis['risk_indicators'].append('Very long URL')
    elif len(url) > 100:
        analysis['risk_indicators'].append('Long URL')
    
    return analysis

def calculate_risk_score(analysis: Dict[str, Any]) -> int:
    """Calculate overall risk score from analysis results"""
    base_score = 0
    
    # Protocol analysis (40% weight)
    if analysis['protocol_analysis']['protocol'] == 'http':
        base_score += 40
    
    # Error code analysis (30% weight)
    error_severity = analysis['error_analysis']['severity']
    if error_severity == 'HIGH':
        base_score += 30
    elif error_severity == 'MEDIUM':
        base_score += 20
    elif error_severity == 'LOW':
        base_score += 10
    
    # Domain analysis (20% weight)
    domain_risks = len(analysis['domain_analysis']['risk_indicators'])
    base_score += min(domain_risks * 5, 20)
    
    # URL structure analysis (10% weight)
    url_risks = len(analysis['url_structure']['risk_indicators'])
    base_score += min(url_risks * 3, 10)
    
    # Suspicious patterns bonus
    suspicious_patterns = (
        len(analysis['domain_analysis']['suspicious_patterns']) +
        len(analysis['url_structure']['suspicious_patterns'])
    )
    base_score += min(suspicious_patterns * 5, 15)
    
    return min(base_score, 100)

def get_risk_level(score: int) -> str:
    """Convert numeric score to risk level"""
    if score >= 80:
        return 'CRITICAL'
    elif score >= 60:
        return 'HIGH'
    elif score >= 40:
        return 'MEDIUM'
    else:
        return 'LOW'

def get_recommendations(risk_level: str, analysis: Dict[str, Any]) -> List[str]:
    """Generate contextual recommendations based on risk level and analysis"""
    recommendations = []
    
    # Base recommendations by risk level
    base_recommendations = {
        'CRITICAL': [
            'Do not proceed to this site',
            'This site poses significant security risks',
            'Consider reporting this site if it appears to be fraudulent'
        ],
        'HIGH': [
            'Exercise extreme caution',
            'Do not enter sensitive information',
            'Consider finding an alternative secure site'
        ],
        'MEDIUM': [
            'Proceed with caution',
            'Verify the site is legitimate',
            'Avoid entering sensitive data'
        ],
        'LOW': [
            'Site appears relatively safe',
            'Still verify the URL is correct',
            'Look for HTTPS when possible'
        ]
    }
    
    recommendations.extend(base_recommendations.get(risk_level, []))
    
    # Add specific recommendations based on analysis
    if analysis['protocol_analysis']['protocol'] == 'http':
        recommendations.append('This site uses HTTP instead of HTTPS - your data is not encrypted')
    
    if analysis['error_analysis']['error_code']:
        recommendations.append(f"Browser detected: {analysis['error_analysis']['description']}")
    
    if analysis['domain_analysis']['suspicious_patterns']:
        recommendations.append('Domain contains suspicious patterns')
    
    return recommendations

def generate_cache_key(url: str, error_code: str) -> str:
    """Generate cache key for DynamoDB storage"""
    combined = f"{url}|{error_code}"
    return hashlib.sha256(combined.encode()).hexdigest()

def get_cached_assessment(cache_key: str) -> Optional[Dict[str, Any]]:
    """Retrieve cached assessment from DynamoDB"""
    try:
        table = get_dynamodb_table()
        response = table.get_item(Key={'assessment_id': cache_key})
        
        if 'Item' in response:
            item = response['Item']
            # Check if cache is still valid (1 hour TTL)
            cached_time = datetime.fromisoformat(item['timestamp'].replace('Z', '+00:00'))
            if datetime.utcnow().replace(tzinfo=cached_time.tzinfo) - cached_time < timedelta(hours=1):
                logger.info(f"Cache hit for key: {cache_key[:16]}...")
                return item['assessment']
            else:
                logger.info(f"Cache expired for key: {cache_key[:16]}...")
        else:
            logger.info(f"Cache miss for key: {cache_key[:16]}...")
        
        return None
    except ClientError as e:
        log_error(logger, e, {'operation': 'cache_get', 'cache_key': cache_key[:16]})
        return None
    except Exception as e:
        log_error(logger, e, {'operation': 'cache_get', 'cache_key': cache_key[:16]})
        return None

def cache_assessment(cache_key: str, assessment: Dict[str, Any]) -> None:
    """Cache assessment result in DynamoDB"""
    try:
        table = get_dynamodb_table()
        
        # Calculate TTL (expire after 24 hours)
        ttl = int((datetime.utcnow() + timedelta(hours=24)).timestamp())
        
        table.put_item(
            Item={
                'assessment_id': cache_key,
                'assessment': assessment,
                'timestamp': assessment['timestamp'],
                'ttl': ttl
            }
        )
        
        logger.info(f"Assessment cached for key: {cache_key[:16]}...")
        
    except ClientError as e:
        log_error(logger, e, {'operation': 'cache_put', 'cache_key': cache_key[:16]})
    except Exception as e:
        log_error(logger, e, {'operation': 'cache_put', 'cache_key': cache_key[:16]})

def success_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """Generate success response"""
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,X-Api-Key,Authorization',
            'Access-Control-Allow-Methods': 'POST,OPTIONS'
        },
        'body': json.dumps(data, cls=DecimalEncoder)
    }

def error_response(status_code: int, message: str) -> Dict[str, Any]:
    """Generate error response"""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,X-Api-Key,Authorization',
            'Access-Control-Allow-Methods': 'POST,OPTIONS'
        },
        'body': json.dumps({
            'error': message,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }, cls=DecimalEncoder)
    }