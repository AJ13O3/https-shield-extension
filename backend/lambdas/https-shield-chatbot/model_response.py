"""
Model response generation for HTTPS Shield Chatbot Lambda
Handles Bedrock API calls, prompt building, and Kendra RAG integration
"""

import os
import boto3
from botocore.exceptions import ClientError
from logger_config import logger

# Initialize AWS clients
bedrock_runtime = boto3.client('bedrock-runtime', region_name='eu-west-2')
kendra = boto3.client('kendra', region_name='eu-west-2')

# Environment variables
KENDRA_INDEX_ID = os.environ.get('KENDRA_INDEX_ID', '')
BEDROCK_MODEL_ID = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-haiku-20240307-v1:0')

def generate_response(message, risk_context, conversation_history):
    """
    Generate response using Amazon Bedrock with RAG enhancement
    
    Args:
        message (str): User's message
        risk_context (dict): Risk assessment context
        conversation_history (list): Previous conversation turns
        
    Returns:
        str: Generated response text
    """
    try:
        # Enhance message with knowledge base context
        enhanced_context = enhance_with_knowledge_base(message, risk_context)
        
        # Build the system prompt
        system_prompt = build_system_prompt(risk_context, enhanced_context)
        
        # Build messages array from conversation history
        messages = build_messages_array(message, conversation_history)
        
        # Call Bedrock using converse
        response = bedrock_runtime.converse(
            modelId=BEDROCK_MODEL_ID,
            messages=messages,
            system=[{"text": system_prompt}],
            inferenceConfig={
                "maxTokens": 1000,
                "temperature": 0.7
            }
        )
        
        # Extract response text
        output_message = response['output']['message']
        if output_message['content'] and len(output_message['content']) > 0:
            response_text = output_message['content'][0]['text']
            logger.info(f"Generated response using Bedrock model: {BEDROCK_MODEL_ID}")
            return response_text
        else:
            logger.warning("Empty response from Bedrock")
            return get_fallback_response(message, risk_context)
        
    except ClientError as e:
        logger.error(f"Bedrock API error: {e}")
        return get_fallback_response(message, risk_context)
    except Exception as e:
        logger.error(f"Unexpected error in Bedrock response: {e}")
        return get_fallback_response(message, risk_context)

def enhance_with_knowledge_base(message, risk_context):
    """
    Use Kendra to enhance the message with relevant security knowledge
    
    Args:
        message (str): User's message
        risk_context (dict): Risk assessment context
        
    Returns:
        str: Enhanced context from knowledge base
    """
    if not KENDRA_INDEX_ID:
        logger.info("Kendra not configured, skipping knowledge enhancement")
        return ""
    
    try:
        # Create search query combining user message and risk context
        search_query = build_kendra_query(message, risk_context)
        
        response = kendra.query(
            IndexId=KENDRA_INDEX_ID,
            QueryText=search_query,
            PageSize=3  # Top 3 most relevant results
        )
        
        # Extract relevant passages
        knowledge_context = []
        for item in response.get('ResultItems', []):
            if item.get('Type') == 'DOCUMENT':
                excerpt = item.get('DocumentExcerpt', {}).get('Text', '')
                if excerpt:
                    knowledge_context.append(excerpt)
        
        enhanced_context = "\n\n".join(knowledge_context) if knowledge_context else ""
        logger.info(f"Enhanced context with {len(knowledge_context)} Kendra results")
        return enhanced_context
        
    except ClientError as e:
        logger.warning(f"Kendra query failed: {e}")
        return ""
    except Exception as e:
        logger.error(f"Unexpected error in Kendra enhancement: {e}")
        return ""

def build_kendra_query(message, risk_context):
    """
    Build an effective search query for Kendra based on user message and risk context
    
    Args:
        message (str): User's message
        risk_context (dict): Risk assessment context
        
    Returns:
        str: Optimized search query
    """
    query_parts = [message]
    
    # Add context-specific terms
    risk_level = risk_context.get('riskLevel', '')
    if risk_level == 'CRITICAL':
        query_parts.append("malware phishing security threat")
    elif risk_level == 'HIGH':
        query_parts.append("security risk warning")
    
    # Add threat-specific terms
    if 'threats' in risk_context:
        for threat in risk_context['threats']:
            if isinstance(threat, dict):
                threat_type = threat.get('type', '')
                if threat_type:
                    query_parts.append(threat_type)
    
    # Add protocol context
    if risk_context.get('protocol') == 'http':
        query_parts.append("HTTP HTTPS encryption")
    
    query = " ".join(query_parts)
    logger.debug(f"Built Kendra query: {query}")
    return query

def build_system_prompt(risk_context, enhanced_context):
    """
    Build the system prompt with current context
    
    Args:
        risk_context (dict): Risk assessment context
        enhanced_context (str): Enhanced context from knowledge base
        
    Returns:
        str: Complete system prompt
    """
    base_prompt = """You are a security expert assistant for the HTTPS Shield browser extension. 
Your role is to help users understand web security risks in simple, non-technical terms.

Guidelines:
- Provide clear, actionable advice
- Avoid technical jargon
- Be concise but helpful
- Focus on user safety
- Explain risks in terms users can understand"""
    
    # Add current context if available
    context_parts = []
    
    if risk_context:
        url = risk_context.get('url', 'Unknown')
        risk_score = risk_context.get('riskScore', 'Unknown')
        risk_level = risk_context.get('riskLevel', 'Unknown')
        
        context_parts.append(f"""
Current Security Context:
- URL: {url}
- Risk Level: {risk_level} ({risk_score}/100)
- Protocol: {risk_context.get('protocol', 'Unknown')}""")
        
        if 'threats' in risk_context and risk_context['threats']:
            threats_list = []
            for threat in risk_context['threats'][:3]:  # Show top 3 threats
                if isinstance(threat, dict):
                    threats_list.append(f"- {threat.get('type', 'Unknown threat')}")
                else:
                    threats_list.append(f"- {threat}")
            
            if threats_list:
                context_parts.append(f"Detected Issues:\n" + "\n".join(threats_list))
    
    # Add knowledge base context if available
    if enhanced_context:
        context_parts.append(f"Relevant Security Information:\n{enhanced_context}")
    
    if context_parts:
        full_prompt = base_prompt + "\n\n" + "\n\n".join(context_parts)
    else:
        full_prompt = base_prompt
    
    logger.debug(f"Built system prompt with {len(context_parts)} context sections")
    return full_prompt

def build_messages_array(message, conversation_history):
    """
    Build the messages array for the converse API including conversation history
    
    Args:
        message (str): Current user message
        conversation_history (list): Previous conversation turns
        
    Returns:
        list: Messages array for Bedrock converse API
    """
    messages = []
    
    # Add recent conversation history
    for turn in conversation_history[-5:]:  # Last 5 turns for context
        user_msg = turn.get('user_message', '')
        bot_response = turn.get('bot_response', '')
        
        if user_msg:
            messages.append({
                "role": "user",
                "content": [{"text": user_msg}]
            })
        
        if bot_response:
            messages.append({
                "role": "assistant", 
                "content": [{"text": bot_response}]
            })
    
    # Add current message
    messages.append({
        "role": "user",
        "content": [{"text": message}]
    })
    
    logger.debug(f"Built messages array with {len(messages)} messages")
    return messages

def get_fallback_response(message, risk_context):
    """
    Provide fallback response when Bedrock is unavailable
    
    Args:
        message (str): User's message
        risk_context (dict): Risk assessment context
        
    Returns:
        str: Fallback response text
    """
    risk_level = risk_context.get('riskLevel', '').upper()
    
    # Check if user is asking about safety specifically
    safety_keywords = ['safe', 'dangerous', 'secure', 'risk', 'threat']
    is_safety_question = any(keyword in message.lower() for keyword in safety_keywords)
    
    logger.info(f"Using fallback response for risk level: {risk_level}")
    
    if risk_level == 'CRITICAL':
        return """I detect this site has critical security risks. I strongly recommend:
1. Do not enter any personal information
2. Do not download anything from this site
3. Go back to safety immediately
4. Consider running a malware scan if you've already interacted with the site"""
    
    elif risk_level == 'HIGH':
        return """This site appears to have security concerns. I recommend:
1. Proceed with extreme caution
2. Avoid entering sensitive information
3. Consider finding an alternative HTTPS version of this site
4. Only continue if you trust this specific site"""
    
    elif risk_level == 'MEDIUM':
        return """This site has some security issues. Consider:
1. Check if there's an HTTPS version available
2. Be cautious about entering personal information
3. Only proceed if necessary and you trust the site"""
    
    else:
        if is_safety_question:
            return """Based on the current analysis, this site appears to have minimal security concerns. However, always:
1. Check for HTTPS when entering sensitive information
2. Be cautious with downloads from any site
3. Keep your browser updated for best security"""
        else:
            return """I'm here to help you understand web security risks. You can ask me about:
- What the security warnings mean
- Whether a site is safe to use
- How to protect yourself online
- What to do if you encounter threats"""

def get_model_info():
    """
    Get information about the current Bedrock model configuration
    
    Returns:
        dict: Model configuration information
    """
    return {
        'model_id': BEDROCK_MODEL_ID,
        'kendra_enabled': bool(KENDRA_INDEX_ID),
        'kendra_index_id': KENDRA_INDEX_ID,
        'region': 'eu-west-2'
    }