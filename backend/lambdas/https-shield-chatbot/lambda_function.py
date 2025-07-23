"""
HTTPS Shield Chatbot Lambda Function
Main handler for LLM interactions using Amazon Bedrock with RAG capabilities
"""

import json
import uuid
from datetime import datetime, timezone

# Import custom modules
from logger_config import logger
from model_response import generate_response, generate_suggested_questions
from dynamoDB import get_conversation_history, store_conversation_turn, get_risk_assessment

def lambda_handler(event, context):
    """
    Main Lambda handler for chatbot requests
    
    Args:
        event (dict): API Gateway event
        context (object): Lambda context object
        
    Returns:
        dict: HTTP response with status code, headers, and body
    """
    session_id = None
    
    try:
        # Parse request
        body = json.loads(event.get('body', '{}'))
        message = body.get('message', '')
        session_id = body.get('sessionId', str(uuid.uuid4()))
        assessment_id = body.get('assessmentId', '')
        risk_context = body.get('context', {})
        
        logger.info(f"Processing chat request for session: {session_id}, assessment: {assessment_id}")
        
        # Retrieve full risk assessment data if assessment ID is provided
        if assessment_id:
            risk_assessment = get_risk_assessment(assessment_id)
            if risk_assessment:
                # Use complete risk assessment data as context
                risk_context = risk_assessment
                logger.info(f"Retrieved risk assessment data for {assessment_id}")
            else:
                logger.warning(f"No risk assessment found for ID: {assessment_id}")
        
        # Handle auto-message generation for initial chatbot display
        if message.strip().lower() == 'auto' and risk_context:
            logger.info("Generating automatic initial message")
            auto_message = generate_auto_message(risk_context)
            
            # Generate suggested questions for the initial display
            suggested_questions = generate_suggested_questions(risk_context, [])
            
            # Store the auto-generated conversation turn
            store_success = store_conversation_turn(session_id, 'auto', auto_message, risk_context)
            if not store_success:
                logger.warning(f"Failed to store auto conversation for session: {session_id}")
            
            return create_success_response(auto_message, session_id, suggested_questions)
        
        # Validate input for regular messages
        if not message.strip():
            return create_error_response(
                400, 
                'Message cannot be empty', 
                session_id
            )
        
        # Get conversation history
        conversation_history = get_conversation_history(session_id)
        
        # Generate response using Bedrock with RAG
        response_text = generate_response(message, risk_context, conversation_history)
        
        # Generate suggested questions for the next user interaction
        suggested_questions = generate_suggested_questions(risk_context, conversation_history)
        
        # Store conversation turn
        store_success = store_conversation_turn(session_id, message, response_text, risk_context)
        if not store_success:
            logger.warning(f"Failed to store conversation for session: {session_id}")
        
        # Return successful response with suggested questions
        return create_success_response(response_text, session_id, suggested_questions)
        
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in request body: {e}")
        return create_error_response(
            400, 
            'Invalid JSON in request body', 
            session_id or str(uuid.uuid4())
        )
    except Exception as e:
        logger.error(f"Unexpected error processing chat request: {str(e)}")
        return create_error_response(
            500, 
            'Internal server error', 
            session_id or str(uuid.uuid4())
        )

def create_success_response(response_text, session_id, suggested_questions=None):
    """
    Create a successful HTTP response
    
    Args:
        response_text (str): Generated response text
        session_id (str): Session identifier
        suggested_questions (list): Optional list of suggested questions
        
    Returns:
        dict: HTTP response
    """
    response_body = {
        'response': response_text,
        'sessionId': session_id,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    
    # Add suggested questions if provided
    if suggested_questions:
        response_body['suggestedQuestions'] = suggested_questions
    
    return {
        'statusCode': 200,
        'headers': get_cors_headers(),
        'body': json.dumps(response_body)
    }

def create_error_response(status_code, error_message, session_id):
    """
    Create an error HTTP response
    
    Args:
        status_code (int): HTTP status code
        error_message (str): Error message
        session_id (str): Session identifier
        
    Returns:
        dict: HTTP error response
    """
    return {
        'statusCode': status_code,
        'headers': get_cors_headers(),
        'body': json.dumps({
            'error': error_message,
            'sessionId': session_id,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
    }

def generate_auto_message(risk_context):
    """
    Generate automatic initial message summarizing the risk assessment
    
    Args:
        risk_context (dict): Complete risk assessment data
        
    Returns:
        str: Auto-generated summary message
    """
    url = risk_context.get('url', 'this website')
    risk_level = risk_context.get('riskLevel', 'UNKNOWN')
    risk_score = risk_context.get('riskScore', 0)
    protocol = risk_context.get('protocol', 'unknown')
    
    # Get threat assessment details if available
    threat_assessment = risk_context.get('threat_assessment', {})
    individual_scores = threat_assessment.get('individual_scores', {})
    
    # Build initial summary based on risk level
    if risk_level == 'CRITICAL':
        severity_msg = "🚨 **CRITICAL SECURITY ALERT** 🚨"
        advice = "I strongly recommend **going back to safety immediately**. This site poses serious security risks."
    elif risk_level == 'HIGH':
        severity_msg = "⚠️ **HIGH SECURITY RISK** ⚠️"
        advice = "Please proceed with **extreme caution**. Consider finding a safer alternative."
    elif risk_level == 'MEDIUM':
        severity_msg = "⚠️ **MODERATE SECURITY CONCERN** ⚠️"
        advice = "This site has some security issues. Be cautious with sensitive information."
    else:
        severity_msg = "ℹ️ **SECURITY ASSESSMENT COMPLETE** ℹ️"
        advice = "This site appears to have minimal security concerns, but stay vigilant."
    
    # Build threat details
    threat_details = []
    if protocol == 'http':
        threat_details.append("• **Unencrypted connection** - Data can be intercepted")
    
    if individual_scores.get('google_safebrowsing', 0) > 0:
        threat_details.append("• **Known security threats** detected by Google Safe Browsing")
    
    if individual_scores.get('virustotal', 0) > 0.1:
        threat_details.append("• **Malware signatures** detected by security engines")
    
    if individual_scores.get('urlbert', 0) > 50:
        threat_details.append("• **Suspicious URL patterns** identified by AI analysis")
    
    # Construct the full message
    message_parts = [
        severity_msg,
        f"\nI've analyzed **{url}** and found a **{risk_level}** risk level (Score: {risk_score}/100).\n",
        advice
    ]
    
    if threat_details:
        message_parts.append("\n**Key Security Issues:**")
        message_parts.extend(threat_details)
    
    message_parts.extend([
        "\n**How can I help?**",
        "• Ask me to explain any security warnings",
        "• Get advice on whether it's safe to proceed", 
        "• Learn about protecting yourself online",
        "• Understand what these security threats mean"
    ])
    
    return "\n".join(message_parts)

def get_cors_headers():
    """
    Return CORS headers for API Gateway
    
    Returns:
        dict: CORS headers
    """
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
        'Access-Control-Allow-Methods': 'OPTIONS,POST'
    }