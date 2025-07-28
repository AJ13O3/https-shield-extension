"""
DynamoDB operations for HTTPS Shield Chatbot Lambda
Handles conversation history storage and retrieval
"""

import os
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import boto3
from botocore.exceptions import ClientError
from logger_config import logger

# Initialize DynamoDB
dynamodb = boto3.resource('dynamodb', region_name='eu-west-2')
CONVERSATIONS_TABLE_NAME = os.environ.get('CONVERSATIONS_TABLE_NAME', 'https-shield-conversations')
RISK_ASSESSMENTS_TABLE_NAME = os.environ.get('RISK_ASSESSMENTS_TABLE_NAME', 'https-shield-risk-assessments')
conversations_table = dynamodb.Table(CONVERSATIONS_TABLE_NAME)
risk_assessments_table = dynamodb.Table(RISK_ASSESSMENTS_TABLE_NAME)

def get_conversation_history(session_id, limit=10):
    """
    Retrieve recent conversation history for context using single-item architecture
    
    Args:
        session_id (str): Session identifier
        limit (int): Maximum number of conversation turns to retrieve
        
    Returns:
        list: List of conversation turns in chronological order (oldest first)
    """
    try:
        # Query for the session - there should only be one item per session
        # but we still need to use the timestamp sort key
        response = conversations_table.query(
            KeyConditionExpression='session_id = :sid',
            ExpressionAttributeValues={':sid': session_id},
            Limit=1  # We expect only one item per session
        )
        
        items = response.get('Items', [])
        if not items:
            logger.info(f"No conversation history found for session: {session_id}")
            return []
        
        session_data = items[0]  # Take the first (and should be only) item
        conversation_turns = session_data.get('conversation_turns', [])
        
        # Apply limit - take the most recent turns if limit is specified
        if limit and len(conversation_turns) > limit:
            # Take the last N turns (most recent)
            limited_turns = conversation_turns[-limit:]
        else:
            limited_turns = conversation_turns
        
        # Convert Decimal objects back to Python numbers for processing
        history = convert_decimals_to_numbers(limited_turns)
        
        logger.info(f"Retrieved {len(history)} conversation turns for session: {session_id}")
        return history
        
    except ClientError as e:
        logger.warning(f"Could not retrieve conversation history for {session_id}: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error retrieving conversation history: {e}")
        return []

def store_conversation_turn(session_id, user_message, bot_response, risk_context):
    """
    Store conversation turn in DynamoDB using single-item architecture
    
    Args:
        session_id (str): Session identifier
        user_message (str): User's message
        bot_response (str): Bot's response
        risk_context (dict): Risk assessment context
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        current_time = datetime.now(timezone.utc)
        timestamp = current_time.isoformat()
        ttl = int((current_time + timedelta(days=7)).timestamp())  # 7 day TTL
        
        # Convert all float values to Decimal for DynamoDB compatibility
        risk_context_for_storage = convert_floats_to_decimal(risk_context) if risk_context else {}
        
        # First, try to check if session exists using query (since we have composite key)
        try:
            response = conversations_table.query(
                KeyConditionExpression='session_id = :sid',
                ExpressionAttributeValues={':sid': session_id},
                Limit=1
            )
            items = response.get('Items', [])
            session_exists = len(items) > 0
            
            if session_exists:
                existing_item = items[0]
                # Get current turn count
                current_turns = len(existing_item.get('conversation_turns', []))
                turn_number = current_turns + 1
                # Store the existing timestamp for updates
                existing_timestamp = existing_item['timestamp']
            else:
                turn_number = 1
                existing_timestamp = None
                
        except ClientError:
            # If query fails, assume session doesn't exist
            session_exists = False
            turn_number = 1
            existing_timestamp = None
        
        # Create new conversation turn
        new_turn = {
            'timestamp': timestamp,
            'user_message': user_message,
            'bot_response': bot_response,
            'turn_number': turn_number
        }
        new_turn = convert_floats_to_decimal(new_turn)
        
        if session_exists:
            # Update existing session using the existing timestamp as sort key
            conversations_table.update_item(
                Key={
                    'session_id': session_id,
                    'timestamp': existing_timestamp
                },
                UpdateExpression='SET conversation_turns = list_append(conversation_turns, :new_turn), '
                                'last_updated = :timestamp, '
                                '#ttl = :ttl '
                                'ADD session_metadata.total_turns :inc',
                ExpressionAttributeNames={
                    '#ttl': 'ttl'
                },
                ExpressionAttributeValues={
                    ':new_turn': [new_turn],
                    ':timestamp': timestamp,
                    ':ttl': ttl,
                    ':inc': 1
                }
            )
            logger.info(f"Updated existing session {session_id} with turn #{turn_number}")
        else:
            # Create new session using current timestamp as sort key
            assessment_id = risk_context_for_storage.get('assessmentId', '')
            url = risk_context_for_storage.get('url', '')
            risk_level = risk_context_for_storage.get('riskLevel', '')
            
            conversations_table.put_item(
                Item={
                    'session_id': session_id,
                    'timestamp': timestamp,  # This becomes the sort key
                    'created_at': timestamp,
                    'last_updated': timestamp,
                    'conversation_turns': [new_turn],
                    'risk_context': risk_context_for_storage,
                    'session_metadata': {
                        'total_turns': 1,
                        'assessment_id': assessment_id,
                        'url': url,
                        'risk_level': risk_level
                    },
                    'ttl': ttl
                }
            )
            logger.info(f"Created new session {session_id} with turn #{turn_number}")
        
        return True
        
    except ClientError as e:
        logger.error(f"Failed to store conversation for {session_id}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error storing conversation: {e}")
        return False


def get_risk_assessment(assessment_id):
    """
    Retrieve risk assessment data using assessment ID
    
    Args:
        assessment_id (str): Assessment identifier (e.g., RISK-20240115123456-abcd1234)
        
    Returns:
        dict: Risk assessment data or None if not found
    """
    if not assessment_id:
        logger.warning("Assessment ID is required")
        return None
        
    try:
        logger.info(f"Querying DynamoDB for assessment_id: {assessment_id}")
        logger.info(f"Assessment ID type: {type(assessment_id)}, length: {len(assessment_id)}")
        
        response = risk_assessments_table.get_item(
            Key={'assessment_id': assessment_id}
        )
        
        if 'Item' in response:
            assessment_data = response['Item']['assessment']
            logger.info(f"Successfully retrieved risk assessment for ID: {assessment_id}")
            logger.info(f"Retrieved assessment keys: {list(assessment_data.keys())}")
            logger.info(f"Assessment has threat_assessment: {'threat_assessment' in assessment_data}")
            if 'threat_assessment' in assessment_data:
                threat_keys = list(assessment_data['threat_assessment'].keys()) if isinstance(assessment_data['threat_assessment'], dict) else 'Not a dict'
                logger.info(f"threat_assessment keys: {threat_keys}")
            
            # Convert Decimal objects back to float/int for JSON serialization
            assessment_data = convert_decimals_to_numbers(assessment_data)
            return assessment_data
        else:
            logger.error(f"No Item found in DynamoDB response for ID: {assessment_id}")
            logger.error(f"DynamoDB response: {response}")
            return None
            
    except ClientError as e:
        logger.error(f"DynamoDB error retrieving assessment {assessment_id}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error retrieving assessment {assessment_id}: {e}")
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

def convert_decimals_to_numbers(obj):
    """
    Recursively convert DynamoDB Decimal objects to Python numbers
    
    Args:
        obj: Object that may contain Decimal values
        
    Returns:
        Object with Decimals converted to int/float
    """
    if isinstance(obj, dict):
        return {key: convert_decimals_to_numbers(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_decimals_to_numbers(item) for item in obj]
    elif isinstance(obj, Decimal):
        # Convert Decimal to int if it's a whole number, otherwise float
        if obj % 1 == 0:
            return int(obj)
        else:
            return float(obj)
    else:
        return obj

def get_session_statistics(session_id):
    """
    Get statistics for a conversation session using single-item architecture
    
    Args:
        session_id (str): Session identifier
        
    Returns:
        dict: Session statistics
    """
    try:
        response = conversations_table.query(
            KeyConditionExpression='session_id = :sid',
            ExpressionAttributeValues={':sid': session_id},
            Limit=1,
            ProjectionExpression='session_metadata, created_at, last_updated'
        )
        
        items = response.get('Items', [])
        if not items:
            return {
                'session_id': session_id,
                'total_turns': 0,
                'messages_per_user': 0,
                'created_at': None,
                'last_updated': None
            }
        
        session_data = items[0]
        metadata = session_data.get('session_metadata', {})
        total_turns = int(metadata.get('total_turns', 0))
        
        return {
            'session_id': session_id,
            'total_turns': total_turns,
            'messages_per_user': total_turns // 2 if total_turns > 0 else 0,
            'created_at': session_data.get('created_at'),
            'last_updated': session_data.get('last_updated'),
            'assessment_id': metadata.get('assessment_id', ''),
            'url': metadata.get('url', ''),
            'risk_level': metadata.get('risk_level', '')
        }
        
    except ClientError as e:
        logger.warning(f"Could not get session statistics for {session_id}: {e}")
        return {
            'session_id': session_id,
            'total_turns': 0,
            'messages_per_user': 0,
            'error': str(e)
        }
    except Exception as e:
        logger.error(f"Unexpected error getting session statistics: {e}")
        return {
            'session_id': session_id,
            'total_turns': 0,
            'messages_per_user': 0,
            'error': str(e)
        }