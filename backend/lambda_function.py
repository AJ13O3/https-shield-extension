import json
import logging
import random  # For prototype mock responses

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Main Lambda handler for HTTPS risk assessment
    
    Expected input:
    {
        "url": "http://example.com",
        "errorCode": "ERR_CERT_DATE_INVALID"
    }
    """
    try:
        # Parse request body
        body = json.loads(event.get('body', '{}'))
        url = body.get('url', '')
        error_code = body.get('errorCode', '')
        
        logger.info(f"Assessing risk for URL: {url}, Error: {error_code}")
        
        # Mock risk assessment for prototype
        # In Phase 2, this will call the actual URLBERT model
        risk_score = random.randint(20, 80)
        risk_level = get_risk_level(risk_score)
        
        # Prepare response
        assessment = {
            'url': url,
            'riskScore': risk_score,
            'riskLevel': risk_level,
            'message': f'Mock assessment for {url}. Real ML model coming in Phase 2.',
            'recommendations': get_recommendations(risk_level),
            'timestamp': event.get('requestContext', {}).get('requestTime', '')
        }
        
        response = {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Api-Key',
                'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
            },
            'body': json.dumps(assessment)
        }
        
        logger.info(f"Risk assessment complete: {risk_level} ({risk_score}/100)")
        return response
        
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in request body: {str(e)}")
        return error_response(400, 'Invalid request body')
        
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        return error_response(500, 'Internal server error')

def get_risk_level(score):
    """Convert numeric score to risk level"""
    if score < 33:
        return 'low'
    elif score < 66:
        return 'medium'
    else:
        return 'high'

def get_recommendations(risk_level):
    """Get safety recommendations based on risk level"""
    recommendations = {
        'low': [
            'Site appears relatively safe',
            'Still verify the URL is correct',
            'Look for HTTPS in the address bar'
        ],
        'medium': [
            'Exercise caution with this site',
            'Avoid entering sensitive information',
            'Consider if you trust this website'
        ],
        'high': [
            'This site may be dangerous',
            'Do not enter any personal information',
            'Consider leaving this site immediately'
        ]
    }
    return recommendations.get(risk_level, [])

def error_response(status_code, message):
    """Generate error response"""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({
            'error': message
        })
    }