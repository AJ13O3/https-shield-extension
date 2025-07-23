"""
DynamoDB operations for HTTPS Shield Chatbot Lambda
Handles conversation history storage and retrieval
"""

import os
from datetime import datetime, timedelta, timezone
import boto3
from botocore.exceptions import ClientError
from logger_config import logger

# Initialize DynamoDB
dynamodb = boto3.resource('dynamodb', region_name='eu-west-2')
CONVERSATIONS_TABLE_NAME = os.environ.get('CONVERSATIONS_TABLE_NAME', 'https-shield-conversations')
conversations_table = dynamodb.Table(CONVERSATIONS_TABLE_NAME)

def get_conversation_history(session_id, limit=10):
    """
    Retrieve recent conversation history for context
    
    Args:
        session_id (str): Session identifier
        limit (int): Maximum number of conversation turns to retrieve
        
    Returns:
        list: List of conversation turns in chronological order
    """
    try:
        response = conversations_table.query(
            KeyConditionExpression='session_id = :sid',
            ExpressionAttributeValues={':sid': session_id},
            ScanIndexForward=False,  # Most recent first
            Limit=limit
        )
        
        # Return in chronological order (oldest first)
        history = list(reversed(response.get('Items', [])))
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
    Store conversation turn in DynamoDB with TTL
    
    Args:
        session_id (str): Session identifier
        user_message (str): User's message
        bot_response (str): Bot's response
        risk_context (dict): Risk assessment context
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        timestamp = datetime.now(timezone.utc).isoformat()
        ttl = int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp())  # 7 day TTL
        
        conversations_table.put_item(
            Item={
                'session_id': session_id,
                'timestamp': timestamp,
                'user_message': user_message,
                'bot_response': bot_response,
                'risk_context': risk_context,
                'ttl': ttl
            }
        )
        
        logger.info(f"Stored conversation turn for session: {session_id}")
        return True
        
    except ClientError as e:
        logger.error(f"Failed to store conversation for {session_id}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error storing conversation: {e}")
        return False

def cleanup_expired_conversations():
    """
    Manual cleanup of expired conversations (TTL handles this automatically)
    This function is provided for manual maintenance if needed
    
    Returns:
        int: Number of items cleaned up
    """
    try:
        current_time = int(datetime.now(timezone.utc).timestamp())
        
        # Scan for expired items (this is expensive, use TTL instead in production)
        response = conversations_table.scan(
            FilterExpression='#ttl < :current_time',
            ExpressionAttributeNames={'#ttl': 'ttl'},
            ExpressionAttributeValues={':current_time': current_time}
        )
        
        items_to_delete = response.get('Items', [])
        
        # Delete expired items
        deleted_count = 0
        for item in items_to_delete:
            try:
                conversations_table.delete_item(
                    Key={
                        'session_id': item['session_id'],
                        'timestamp': item['timestamp']
                    }
                )
                deleted_count += 1
            except ClientError as e:
                logger.warning(f"Failed to delete expired item: {e}")
        
        logger.info(f"Manually cleaned up {deleted_count} expired conversation items")
        return deleted_count
        
    except Exception as e:
        logger.error(f"Error during manual cleanup: {e}")
        return 0

def get_session_statistics(session_id):
    """
    Get statistics for a conversation session
    
    Args:
        session_id (str): Session identifier
        
    Returns:
        dict: Session statistics
    """
    try:
        response = conversations_table.query(
            KeyConditionExpression='session_id = :sid',
            ExpressionAttributeValues={':sid': session_id},
            Select='COUNT'
        )
        
        turn_count = response.get('Count', 0)
        
        return {
            'session_id': session_id,
            'total_turns': turn_count,
            'messages_per_user': turn_count // 2 if turn_count > 0 else 0
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