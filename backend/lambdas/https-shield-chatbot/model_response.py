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
bedrock_agent_runtime = boto3.client('bedrock-agent-runtime', region_name='eu-west-2')

# Environment variables
KNOWLEDGE_BASE_ID = os.environ.get('KNOWLEDGE_BASE_ID', '')
KNOWLEDGE_BASE_MODEL_ARN = os.environ.get('KNOWLEDGE_BASE_MODEL_ARN', 'arn:aws:bedrock:eu-west-2::foundation-model/anthropic.claude-3-haiku-20240307-v1:0')
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
        # Try Knowledge Base enhanced response first
        if KNOWLEDGE_BASE_ID:
            kb_response = query_knowledge_base(message, risk_context)
            if kb_response['success']:
                logger.info("Generated response using Bedrock Knowledge Base")
                return kb_response['response']
            else:
                logger.warning(f"Knowledge Base query failed: {kb_response.get('error', 'Unknown error')}")
        
        # Fallback to regular converse API without Knowledge Base
        logger.info("Using fallback converse API without Knowledge Base")
        
        # Build the system prompt with risk context only
        system_prompt = build_system_prompt(risk_context, "")
        
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
            logger.info(f"Generated response using Bedrock converse API: {BEDROCK_MODEL_ID}")
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

def query_knowledge_base(message, risk_context, session_id=None):
    """
    Query Bedrock Knowledge Base for enhanced security guidance
    
    Args:
        message (str): User's message
        risk_context (dict): Risk assessment context
        session_id (str): Optional session ID for conversation continuity
        
    Returns:
        dict: Response with success status, response text, session ID, and citations
    """
    if not KNOWLEDGE_BASE_ID:
        logger.info("Knowledge Base not configured")
        return {'success': False, 'error': 'Knowledge Base not configured'}
    
    try:
        # Build enhanced query with risk context
        enhanced_query = build_knowledge_base_query(message, risk_context)
        
        # Prepare the request parameters
        request_params = {
            'input': {'text': enhanced_query},
            'retrieveAndGenerateConfiguration': {
                'type': 'KNOWLEDGE_BASE',
                'knowledgeBaseConfiguration': {
                    'knowledgeBaseId': KNOWLEDGE_BASE_ID,
                    'modelArn': KNOWLEDGE_BASE_MODEL_ARN,
                    'retrievalConfiguration': {
                        'vectorSearchConfiguration': {
                            'numberOfResults': 5,
                            'overrideSearchType': 'SEMANTIC'
                        }
                    },
                    'generationConfiguration': {
                        'promptTemplate': {
                            'textPromptTemplate': """You are an expert security assistant for the HTTPS Shield browser extension. 
Based on the following security knowledge: $search_results$

User context: The user is browsing a website with the following security assessment:
- Risk Level: {risk_level}
- Risk Score: {risk_score}/100
- URL: {url}
- Protocol: {protocol}

User question: $query$

Provide clear, actionable security guidance that:
1. Explains the security situation in simple terms
2. Offers specific steps the user can take
3. Indicates the urgency/severity appropriately
4. Focuses on practical protection measures

Response:""".format(
                                risk_level=risk_context.get('riskLevel', 'Unknown'),
                                risk_score=risk_context.get('riskScore', 'Unknown'),
                                url=risk_context.get('url', 'Unknown'),
                                protocol=risk_context.get('protocol', 'Unknown')
                            )
                        }
                    }
                }
            }
        }
        
        # Add session ID if provided for conversation continuity
        if session_id:
            request_params['sessionId'] = session_id
        
        # Query the knowledge base
        response = bedrock_agent_runtime.retrieve_and_generate(**request_params)
        
        logger.info(f"Knowledge Base query successful for session: {response.get('sessionId', 'N/A')}")
        
        return {
            'success': True,
            'response': response['output']['text'],
            'session_id': response['sessionId'],
            'citations': response.get('citations', []),
            'guardrails': response.get('guardrails', {})
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        logger.error(f"Knowledge Base query failed: {error_code} - {error_message}")
        
        return {
            'success': False,
            'error': f"{error_code}: {error_message}",
            'error_code': error_code
        }
    except Exception as e:
        logger.error(f"Unexpected error in Knowledge Base query: {e}")
        return {
            'success': False,
            'error': f"Unexpected error: {str(e)}"
        }

def build_knowledge_base_query(message, risk_context):
    """
    Build an effective query for Bedrock Knowledge Base including risk context
    
    Args:
        message (str): User's message
        risk_context (dict): Risk assessment context
        
    Returns:
        str: Enhanced query for knowledge base
    """
    query_parts = [message]
    
    # Add risk level context
    risk_level = risk_context.get('riskLevel', '')
    if risk_level == 'CRITICAL':
        query_parts.append("critical security threat malware phishing protection")
    elif risk_level == 'HIGH':
        query_parts.append("high security risk warning protection measures")
    elif risk_level == 'MEDIUM':
        query_parts.append("security concern best practices")
    
    # Add threat-specific context
    if 'threats' in risk_context and risk_context['threats']:
        threat_types = []
        for threat in risk_context['threats'][:3]:  # Top 3 threats
            if isinstance(threat, dict):
                threat_type = threat.get('type', '')
                if threat_type:
                    threat_types.append(threat_type)
            else:
                threat_types.append(str(threat))
        
        if threat_types:
            query_parts.append(" ".join(threat_types))
    
    # Add protocol and URL context
    if risk_context.get('protocol') == 'http':
        query_parts.append("HTTP insecure HTTPS encryption mixed content")
    
    # Add domain context if available
    if 'domain' in risk_context:
        domain = risk_context['domain']
        if any(tld in domain for tld in ['.tk', '.ml', '.ga', '.cf']):
            query_parts.append("suspicious domain free TLD security")
    
    enhanced_query = " ".join(query_parts)
    logger.debug(f"Built Knowledge Base query: {enhanced_query}")
    return enhanced_query

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

def generate_suggested_questions(risk_context, conversation_history):
    """
    Generate contextual suggested questions based on the current risk assessment and conversation
    
    Args:
        risk_context (dict): Risk assessment context
        conversation_history (list): Previous conversation turns
        
    Returns:
        list: List of suggested questions
    """
    risk_level = risk_context.get('riskLevel', '').upper()
    protocol = risk_context.get('protocol', '')
    threat_assessment = risk_context.get('threat_assessment', {})
    individual_scores = threat_assessment.get('individual_scores', {})
    
    # Base questions available for all risk levels
    base_questions = []
    
    # Risk level specific questions
    if risk_level == 'CRITICAL':
        base_questions.extend([
            "What makes this site so dangerous?",
            "How can I protect my computer from malware?",
            "What should I do if I already visited this site?",
            "Can this site steal my personal information?"
        ])
    elif risk_level == 'HIGH':
        base_questions.extend([
            "Why is this site flagged as high risk?",
            "Is it safe to enter my password here?",
            "How can I find a safer alternative?",
            "What information could be at risk?"
        ])
    elif risk_level == 'MEDIUM':
        base_questions.extend([
            "What security issues does this site have?",
            "Should I avoid entering personal information?",
            "How can I make this connection more secure?",
            "When is it okay to proceed anyway?"
        ])
    else:
        base_questions.extend([
            "How can I verify this site is really safe?",
            "What security best practices should I follow?",
            "How do I know if a site is encrypted?",
            "What signs should I watch for?"
        ])
    
    # Protocol-specific questions
    if protocol == 'http':
        base_questions.append("Why is HTTPS important for security?")
    
    # Threat-specific questions based on individual scores
    if individual_scores.get('google_safebrowsing', 0) > 0:
        base_questions.append("What did Google Safe Browsing detect?")
    
    if individual_scores.get('virustotal', 0) > 0.1:
        base_questions.append("What kind of malware was detected?")
    
    if individual_scores.get('urlbert', 0) > 50:
        base_questions.append("What makes this URL look suspicious?")
    
    # Remove questions that have already been asked in conversation
    asked_questions = set()
    for turn in conversation_history:
        user_msg = turn.get('user_message', '').lower()
        if user_msg and user_msg != 'auto':
            asked_questions.add(user_msg)
    
    # Filter out similar questions and limit to 4
    filtered_questions = []
    for question in base_questions:
        question_lower = question.lower()
        # Simple similarity check - if core words don't match previous questions
        if not any(
            len(set(question_lower.split()) & set(asked.split())) > 2 
            for asked in asked_questions
        ):
            filtered_questions.append(question)
        
        if len(filtered_questions) >= 4:
            break
    
    logger.debug(f"Generated {len(filtered_questions)} suggested questions for risk level: {risk_level}")
    return filtered_questions

def get_model_info():
    """
    Get information about the current Bedrock model configuration
    
    Returns:
        dict: Model configuration information
    """
    return {
        'bedrock_model_id': BEDROCK_MODEL_ID,
        'knowledge_base_enabled': bool(KNOWLEDGE_BASE_ID),
        'knowledge_base_id': KNOWLEDGE_BASE_ID,
        'knowledge_base_model_arn': KNOWLEDGE_BASE_MODEL_ARN,
        'region': 'eu-west-2'
    }