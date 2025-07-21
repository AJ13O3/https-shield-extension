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

# Import ML and external API services
from ml_inference import get_combined_ml_prediction
from external_apis import get_combined_intelligence, is_test_url

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
            # For test URLs, log that we're using cached data
            if is_test_url(url):
                logger.info(f"Using cached result for test URL: {url}")
            log_performance_metric(logger, 'total_request', (time.time() - start_time) * 1000, cache_hit=True)
            return success_response(cached_result)
        
        # Log cache miss
        logger.info(f"Cache miss for URL: {url}")
        if is_test_url(url):
            logger.info(f"No cache found for test URL: {url}, will perform fresh analysis")
        
        # Perform risk assessment
        assessment_start = time.time()
        assessment = perform_risk_assessment(url, error_code, user_agent)
        log_performance_metric(logger, 'risk_assessment', (time.time() - assessment_start) * 1000)
        
        # Cache the result with appropriate TTL
        cache_write_start = time.time()
        cache_assessment(cache_key, assessment, url)
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
    Perform comprehensive risk assessment for a URL using ML models and external APIs
    
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
    
    # Get external intelligence data
    try:
        logger.info(f"Getting external intelligence for URL: {url}")
        external_data = get_combined_intelligence(url)
        if external_data:
            assessment['external_intelligence'] = external_data
            logger.info(f"External intelligence result: {external_data}")
        else:
            external_data = {'combined_risk_score': 0.0, 'domain_age': 0, 'reputation_score': 0.5}
            assessment['external_intelligence'] = {'error': 'No external intelligence available'}
            logger.warning("No external intelligence data received")
    except Exception as e:
        log_error(logger, e, {'operation': 'external_intelligence', 'url': url})
        external_data = {'combined_risk_score': 0.0, 'domain_age': 0, 'reputation_score': 0.5}
        assessment['external_intelligence'] = {'error': 'External intelligence failed'}
    
    # Get ML model predictions
    try:
        logger.info(f"Getting ML predictions for URL: {url}")
        ml_prediction = get_combined_ml_prediction(
            url, 
            assessment['analysis']['domain_analysis'],
            assessment['analysis']['error_analysis'],
            external_data
        )
        assessment['ml_prediction'] = ml_prediction
        logger.info(f"ML prediction result: {ml_prediction}")
    except Exception as e:
        log_error(logger, e, {'operation': 'ml_prediction', 'url': url})
        ml_prediction = {
            'ml_risk_score': 0.0, 
            'ml_confidence': 0.0,
            'error': 'ML prediction failed (SageMaker endpoints not deployed)'
        }
        assessment['ml_prediction'] = ml_prediction
    
    # Calculate enhanced risk score
    enhanced_risk_score = calculate_enhanced_risk_score(
        assessment['analysis'],
        external_data,
        ml_prediction
    )
    
    assessment['riskScore'] = enhanced_risk_score
    assessment['riskLevel'] = get_risk_level(enhanced_risk_score)
    assessment['recommendations'] = get_enhanced_recommendations(
        assessment['riskLevel'], 
        assessment['analysis'],
        external_data,
        ml_prediction
    )
    
    # Log detailed scoring breakdown for debugging
    logger.info(f"Risk score breakdown - Domain: {assessment['analysis']['domain_analysis']}, "
               f"Error: {assessment['analysis']['error_analysis']['severity']}, "
               f"External: {external_data.get('combined_risk_score', 0)}, "
               f"ML: {ml_prediction.get('ml_risk_score', 0)}, "
               f"Final: {enhanced_risk_score}")
    
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
    """Calculate basic risk score from analysis results (fallback method)"""
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

def calculate_enhanced_risk_score(analysis: Dict[str, Any], 
                                external_data: Dict[str, Any], 
                                ml_prediction: Dict[str, Any]) -> int:
    """Calculate enhanced risk score using ML models and external intelligence"""
    
    # Get basic analysis score
    basic_score = calculate_risk_score(analysis)
    
    # Get ML prediction score
    ml_score = ml_prediction.get('ml_risk_score', 0.0)
    ml_confidence = ml_prediction.get('ml_confidence', 0.0)
    ml_available = ml_confidence > 0.0  # Check if ML models are actually available
    
    # Get external intelligence score
    external_score = external_data.get('combined_risk_score', 0.0)
    
    # Dynamic weight allocation based on available data
    if ml_available:
        # All sources available - use original weighting
        weights = {
            'basic': 0.3,
            'ml': 0.4,
            'external': 0.3
        }
        
        # Adjust ML weight based on confidence
        if ml_confidence < 0.5:
            weights['ml'] = 0.2
            weights['basic'] = 0.5
        elif ml_confidence > 0.8:
            weights['ml'] = 0.5
            weights['basic'] = 0.2
    else:
        # ML not available - redistribute weights between basic and external
        weights = {
            'basic': 0.4,
            'ml': 0.0,
            'external': 0.6  # Give more weight to external intelligence
        }
    
    # Calculate weighted score
    final_score = (
        basic_score * weights['basic'] +
        ml_score * weights['ml'] +
        external_score * weights['external']
    )
    
    # Apply threat-based overrides (critical security feature)
    threat_indicators = external_data.get('threat_indicators', [])
    if threat_indicators:
        # Check for critical threats
        has_malware = any(
            threat.get('type') == 'MALWARE' if isinstance(threat, dict) else 'malware' in str(threat).lower()
            for threat in threat_indicators
        )
        
        if has_malware:
            # Malware detected - ensure minimum HIGH risk level
            final_score = max(final_score, 75)
        else:
            # Other threats - ensure minimum MEDIUM risk level
            final_score = max(final_score, 50)
    
    # Apply additional risk factors
    risk_multiplier = 1.0
    
    # Very new domains are riskier
    domain_age = external_data.get('domain_age', 365)
    if domain_age < 30:
        risk_multiplier += 0.3
    elif domain_age < 90:
        risk_multiplier += 0.2
    
    # Apply multiplier and cap at 100
    final_score = min(final_score * risk_multiplier, 100)
    
    return int(final_score)

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
    """Generate basic recommendations (fallback method)"""
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

def get_enhanced_recommendations(risk_level: str, analysis: Dict[str, Any], 
                               external_data: Dict[str, Any], 
                               ml_prediction: Dict[str, Any]) -> List[str]:
    """Generate enhanced recommendations using ML and external intelligence"""
    recommendations = []
    
    # Start with base recommendations
    recommendations.extend(get_recommendations(risk_level, analysis))
    
    # Add ML-based recommendations
    if 'individual_predictions' in ml_prediction:
        models_used = ml_prediction.get('models_used', [])
        if 'urlbert' in models_used:
            recommendations.append('AI analysis indicates potential security concerns')
        if 'xgboost' in models_used:
            recommendations.append('Machine learning model flagged suspicious URL patterns')
    
    # Add external intelligence recommendations only if data exists
    if external_data and not external_data.get('error'):
        threat_indicators = external_data.get('threat_indicators', [])
        if threat_indicators:
            recommendations.append('External security services have flagged this site')
            for indicator in threat_indicators[:3]:  # Show max 3 indicators
                recommendations.append(f'Security alert: {indicator}')
        
        # Domain age recommendations
        domain_age = external_data.get('domain_age', 365)
        if domain_age < 30:
            recommendations.append('This domain was registered very recently (high risk)')
        elif domain_age < 90:
            recommendations.append('This domain is relatively new (moderate risk)')
        
        # Reputation-based recommendations
        reputation_score = external_data.get('reputation_score', 0.5)
        if reputation_score < 0.3:
            recommendations.append('This site has poor reputation scores')
        elif reputation_score > 0.8:
            recommendations.append('This site has good reputation scores')
        
        # VirusTotal specific recommendations
        if 'virustotal' in external_data:
            vt_data = external_data['virustotal']
            if not vt_data.get('is_safe', True):
                detections = vt_data.get('detections', 0)
                total = vt_data.get('total_scanners', 0)
                recommendations.append(f'VirusTotal detected threats: {detections}/{total} scanners')
        
        # Google Safe Browsing recommendations
        if 'google_safebrowsing' in external_data:
            gsb_data = external_data['google_safebrowsing']
            if not gsb_data.get('is_safe', True):
                recommendations.append('Google Safe Browsing flagged this site as dangerous')
    
    # Remove duplicates while preserving order
    seen = set()
    unique_recommendations = []
    for rec in recommendations:
        if rec not in seen:
            seen.add(rec)
            unique_recommendations.append(rec)
    
    return unique_recommendations

def generate_cache_key(url: str, error_code: str) -> str:
    """Generate cache key for DynamoDB storage with version control"""
    version = "v4"  # Updated version to force cache refresh
    combined = f"{version}|{url}|{error_code}"
    return hashlib.sha256(combined.encode()).hexdigest()

def get_cached_assessment(cache_key: str) -> Optional[Dict[str, Any]]:
    """Retrieve cached assessment from DynamoDB"""
    try:
        table = get_dynamodb_table()
        response = table.get_item(Key={'assessment_id': cache_key})
        
        if 'Item' in response:
            item = response['Item']
            # Check if cache is still valid (TTL is managed by DynamoDB)
            logger.info(f"Cache hit for key: {cache_key[:16]}...")
            return item['assessment']
        else:
            logger.info(f"Cache miss for key: {cache_key[:16]}...")
        
        return None
    except ClientError as e:
        log_error(logger, e, {'operation': 'cache_get', 'cache_key': cache_key[:16]})
        return None
    except Exception as e:
        log_error(logger, e, {'operation': 'cache_get', 'cache_key': cache_key[:16]})
        return None

def convert_floats_to_decimal(obj):
    """Recursively convert all float values to Decimal for DynamoDB compatibility"""
    if isinstance(obj, dict):
        return {k: convert_floats_to_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_floats_to_decimal(item) for item in obj]
    elif isinstance(obj, float):
        # Handle special float values
        if obj != obj:  # NaN check
            return Decimal('0')
        elif obj == float('inf'):
            return Decimal('999999')
        elif obj == float('-inf'):
            return Decimal('-999999')
        else:
            return Decimal(str(obj))
    elif isinstance(obj, (int, bool)):
        return obj  # Keep integers and booleans as-is
    elif obj is None:
        return obj  # Keep None as-is
    else:
        return obj

def cache_assessment(cache_key: str, assessment: Dict[str, Any], url: str) -> None:
    """Cache assessment result in DynamoDB with appropriate TTL"""
    try:
        table = get_dynamodb_table()
        
        # Calculate TTL based on URL type
        if is_test_url(url):
            ttl = int((datetime.utcnow() + timedelta(minutes=5)).timestamp())  # 5 minutes for test URLs
            logger.info(f"Using short TTL (5 minutes) for test URL: {url}")
        else:
            ttl = int((datetime.utcnow() + timedelta(hours=24)).timestamp())  # 24 hours for regular URLs
        
        # Convert all float values to Decimal for DynamoDB compatibility
        assessment_for_cache = convert_floats_to_decimal(assessment)
        
        table.put_item(
            Item={
                'assessment_id': cache_key,
                'assessment': assessment_for_cache,
                'timestamp': assessment['timestamp'],
                'ttl': ttl
            }
        )
        
        logger.info(f"Assessment cached for key: {cache_key[:16]}... with TTL: {ttl}")
        
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