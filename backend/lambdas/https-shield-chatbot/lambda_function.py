"""
HTTPS Shield Chatbot Lambda Function
Main handler for LLM interactions using Amazon Bedrock with RAG capabilities
"""

import json
import uuid
from datetime import datetime, timezone

# Import custom modules
from logger_config import logger
from model_response import generate_response
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
        logger.info(f"Initial risk context keys: {list(risk_context.keys()) if risk_context else 'None'}")
        logger.debug(f"Initial risk context: {json.dumps(risk_context, indent=2, default=str) if risk_context else 'None'}")
        
        # Retrieve full risk assessment data if assessment ID is provided
        if assessment_id:
            risk_assessment = get_risk_assessment(assessment_id)
            if risk_assessment:
                # Use complete risk assessment data as context
                risk_context = risk_assessment
                logger.info(f"Retrieved risk assessment data for {assessment_id}")
                logger.info(f"Risk assessment keys: {list(risk_assessment.keys())}")
                logger.debug(f"Complete risk assessment: {json.dumps(risk_assessment, indent=2, default=str)}")
            else:
                logger.warning(f"No risk assessment found for ID: {assessment_id}")
        
        # Handle auto-message generation for initial chatbot display
        if message.strip().lower() == 'auto' and risk_context:
            logger.info("Generating automatic initial message using LLM")
            
            # Use LLM to generate auto message with suggestions
            llm_result = generate_response('auto', risk_context, [], response_mode='auto')
            
            if llm_result is None:
                logger.error("LLM failed to generate auto message")
                return create_error_response(500, 'AI assistant temporarily unavailable', session_id)
            
            response_text = llm_result.get('response', '')
            suggested_questions = llm_result.get('suggestions', [])
            
            if not response_text:
                logger.error("Auto message response is empty")
                return create_error_response(500, 'AI assistant temporarily unavailable', session_id)
            
            # Store the auto-generated conversation turn
            store_success = store_conversation_turn(session_id, 'auto', response_text, risk_context)
            if not store_success:
                logger.warning(f"Failed to store auto conversation for session: {session_id}")
            
            return create_success_response(response_text, session_id, suggested_questions)
        
        # Validate input for regular messages
        if not message.strip():
            return create_error_response(
                400, 
                'Message cannot be empty', 
                session_id
            )
        
        # Get conversation history
        conversation_history = get_conversation_history(session_id)
        
        # Generate response using Bedrock with structured output
        llm_result = generate_response(message, risk_context, conversation_history)
        
        if llm_result is None:
            logger.error("LLM failed to generate response")
            return create_error_response(
                500, 
                'AI assistant temporarily unavailable', 
                session_id
            )
        
        response_text = llm_result.get('response', '')
        suggested_questions = llm_result.get('suggestions', [])
        
        if not response_text:
            logger.error("Response text is empty")
            return create_error_response(
                500, 
                'AI assistant temporarily unavailable', 
                session_id
            )
        
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

# Removed generate_auto_message - now handled by LLM with structured prompts

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