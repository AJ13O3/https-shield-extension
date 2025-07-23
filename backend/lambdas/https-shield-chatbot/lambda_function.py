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
from dynamoDB import get_conversation_history, store_conversation_turn

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
        risk_context = body.get('context', {})
        
        logger.info(f"Processing chat request for session: {session_id}")
        
        # Validate input
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
        
        # Store conversation turn
        store_success = store_conversation_turn(session_id, message, response_text, risk_context)
        if not store_success:
            logger.warning(f"Failed to store conversation for session: {session_id}")
        
        # Return successful response
        return create_success_response(response_text, session_id)
        
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

def create_success_response(response_text, session_id):
    """
    Create a successful HTTP response
    
    Args:
        response_text (str): Generated response text
        session_id (str): Session identifier
        
    Returns:
        dict: HTTP response
    """
    return {
        'statusCode': 200,
        'headers': get_cors_headers(),
        'body': json.dumps({
            'response': response_text,
            'sessionId': session_id,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
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