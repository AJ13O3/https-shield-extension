"""
HTTPS Shield URL Risk Assessment Lambda Function

This Lambda function analyzes URLs for security risks and provides recommendations.
It integrates with DynamoDB for caching and external APIs for enhanced analysis.
"""

import json
import os
import re
import hashlib
import time
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from typing import Dict, Any, Optional, List
import boto3
from botocore.exceptions import ClientError
from decimal import Decimal

# Import logger configuration
from logger_config import setup_logger, log_lambda_event, log_performance_metric, log_error, log_api_request

# Import ML and external API services
from ml_inference import get_combined_threat_assessment
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

def generate_assessment_id(url: str) -> str:
    """Generate unique assessment ID for this risk assessment"""
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
    url_hash = hashlib.sha256(url.encode()).hexdigest()[:8]
    return f"RISK-{timestamp}-{url_hash}"

def generate_session_id() -> str:
    """Generate unique session ID for conversation continuity"""
    return f"SESSION-{str(uuid.uuid4())}"

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
            "threat_assessment": {...},
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
        Dictionary containing risk assessment results with assessment and session IDs
    """
    parsed_url = urlparse(url)
    
    # Generate unique identifiers for this assessment
    assessment_id = generate_assessment_id(url)
    session_id = generate_session_id()
    
    # Initialize assessment
    assessment = {
        'url': url,
        'domain': parsed_url.netloc,
        'protocol': parsed_url.scheme,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'errorCode': error_code,
        'assessmentId': assessment_id,
        'sessionId': session_id
    }
    
    # Get external intelligence data
    try:
        logger.info(f"Getting external intelligence for URL: {url}")
        external_data = get_combined_intelligence(url)
        if external_data:
            logger.info(f"External intelligence result: {external_data}")
        else:
            external_data = {'combined_risk_score': 0.0, 'domain_age': 0, 'reputation_score': 0.5}
            logger.warning("No external intelligence data received")
    except Exception as e:
        log_error(logger, e, {'operation': 'external_intelligence', 'url': url})
        external_data = {'combined_risk_score': 0.0, 'domain_age': 0, 'reputation_score': 0.5}
    
    # Get combined threat assessment using new aggregation method
    try:
        logger.info(f"Getting combined threat assessment for URL: {url}")
        threat_assessment = get_combined_threat_assessment(url, external_data)
        assessment['threat_assessment'] = threat_assessment
        logger.info(f"Threat assessment result: {threat_assessment}")
    except Exception as e:
        log_error(logger, e, {'operation': 'threat_assessment', 'url': url})
        threat_assessment = {
            'final_risk_score': 0.0,
            'individual_scores': {},
            'error': 'Threat assessment failed'
        }
        assessment['threat_assessment'] = threat_assessment
    
    # Use final risk score from threat assessment (already 0-100 scale)
    enhanced_risk_score = threat_assessment.get('final_risk_score', 0.0)
    
    assessment['riskScore'] = enhanced_risk_score
    assessment['riskLevel'] = get_risk_level(enhanced_risk_score)
    
    # Log detailed scoring breakdown for debugging
    individual_scores = threat_assessment.get('individual_scores', {})
    logger.info(f"Risk score breakdown - URL: {url}, "
               f"ErrorCode: {error_code}, "
               f"URLBERT: {individual_scores.get('urlbert', 0)}, "
               f"SafeBrowsing: {individual_scores.get('google_safebrowsing', 0)}, "
               f"VirusTotal: {individual_scores.get('virustotal', 0)}, "
               f"WHOIS: {individual_scores.get('whois', 0)}, "
               f"Final: {enhanced_risk_score}")
    
    return assessment






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
            ttl = int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp())  # 5 minutes for test URLs
            logger.info(f"Using short TTL (5 minutes) for test URL: {url}")
        else:
            ttl = int((datetime.now(timezone.utc) + timedelta(hours=24)).timestamp())  # 24 hours for regular URLs
        
        # Convert all float values to Decimal for DynamoDB compatibility
        assessment_for_cache = convert_floats_to_decimal(assessment)
        
        # Store with original cache key for URL-based lookups
        table.put_item(
            Item={
                'assessment_id': cache_key,
                'assessment': assessment_for_cache,
                'timestamp': assessment['timestamp'],
                'ttl': ttl
            }
        )
        
        # Also store with assessmentId for chatbot retrieval
        if 'assessmentId' in assessment:
            table.put_item(
                Item={
                    'assessment_id': assessment['assessmentId'],
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
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, cls=DecimalEncoder)
    }