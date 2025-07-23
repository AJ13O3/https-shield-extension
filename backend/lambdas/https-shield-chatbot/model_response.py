"""
Model response generation for HTTPS Shield Chatbot Lambda
Handles Bedrock API calls, prompt building, and Kendra RAG integration
"""

import os
import json
import re
import boto3
from botocore.exceptions import ClientError
from logger_config import logger
from config import AUTO_MESSAGE_PROMPT, CONVERSATION_PROMPT, KNOWLEDGE_BASE_PROMPT_TEMPLATE

# Initialize AWS clients
bedrock_runtime = boto3.client('bedrock-runtime', region_name='eu-west-2')
bedrock_agent_runtime = boto3.client('bedrock-agent-runtime', region_name='eu-west-2')

# Environment variables
KNOWLEDGE_BASE_ID = os.environ.get('KNOWLEDGE_BASE_ID', '')
KNOWLEDGE_BASE_MODEL_ARN = os.environ.get('KNOWLEDGE_BASE_MODEL_ARN', 'arn:aws:bedrock:eu-west-2::foundation-model/anthropic.claude-3-haiku-20240307-v1:0')
BEDROCK_MODEL_ID = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-haiku-20240307-v1:0')

def generate_response(message, risk_context, conversation_history, response_mode='regular'):
    """
    Generate response using Amazon Bedrock with structured output
    
    Args:
        message (str): User's message or 'auto' for initial display
        risk_context (dict): Risk assessment context
        conversation_history (list): Previous conversation turns
        response_mode (str): 'auto' or 'regular'
        
    Returns:
        dict: {'response': str, 'suggestions': list}
    """
    try:
        # Try Knowledge Base for regular messages (not auto)
        if KNOWLEDGE_BASE_ID and response_mode == 'regular':
            kb_response = query_knowledge_base(message, risk_context)
            if kb_response['success']:
                logger.info("Generated response using Bedrock Knowledge Base")
                # Parse KB response for JSON structure
                parsed_response = parse_json_response(kb_response['response'])
                if parsed_response:
                    return parsed_response
                else:
                    # If parsing fails, use raw response with empty suggestions
                    return {
                        'response': kb_response['response'],
                        'suggestions': []
                    }
            else:
                logger.warning(f"Knowledge Base query failed: {kb_response.get('error', 'Unknown error')}")
        
        # Build appropriate prompt based on mode
        if response_mode == 'auto':
            system_prompt = build_auto_prompt(risk_context)
            messages = [{"role": "user", "content": [{"text": "Generate security assessment"}]}]
        else:
            system_prompt = build_conversation_prompt(risk_context, conversation_history, message)
            messages = build_messages_array(message, conversation_history)
        
        # Log the complete LLM call setup
        logger.info(f"Using Bedrock converse API in {response_mode} mode")
        logger.info(f"Model ID: {BEDROCK_MODEL_ID}")
        logger.info(f"Messages array length: {len(messages)}")
        logger.debug(f"Messages to LLM: {json.dumps(messages, indent=2, default=str)}")
        logger.info("=== SYSTEM PROMPT TO LLM ===")
        logger.info(system_prompt)
        logger.info("=== END SYSTEM PROMPT ===")
        
        # Call Bedrock
        response = bedrock_runtime.converse(
            modelId=BEDROCK_MODEL_ID,
            messages=messages,
            system=[{"text": system_prompt}],
            inferenceConfig={
                "maxTokens": 1500,
                "temperature": 0.7
            }
        )
        
        # Log LLM response
        logger.info("=== RAW LLM RESPONSE ===")
        logger.info(json.dumps(response, indent=2, default=str))
        logger.info("=== END RAW LLM RESPONSE ===")
        
        # Parse structured response
        output_message = response['output']['message']
        if output_message['content'] and len(output_message['content']) > 0:
            response_text = output_message['content'][0]['text']
            logger.info(f"Extracted response text length: {len(response_text)}")
            logger.debug(f"Raw LLM response: {response_text[:200]}...")
            
            parsed = parse_json_response(response_text)
            if parsed:
                logger.info("Successfully parsed structured response")
                return parsed
            else:
                logger.error("Failed to parse JSON response from LLM")
                return None
        else:
            logger.error("Empty response from Bedrock")
            return None
        
    except ClientError as e:
        logger.error(f"Bedrock API error: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error in generate_response: {e}")
        return None

def build_auto_prompt(risk_context):
    """Build prompt for auto-message generation"""
    # Log the complete risk context being processed
    logger.info(f"Building auto prompt with risk context keys: {list(risk_context.keys())}")
    logger.debug(f"Complete risk context: {json.dumps(risk_context, indent=2, default=str)}")
    
    # Extract detailed threat analysis
    detailed_analysis = extract_detailed_threat_analysis(risk_context)
    
    prompt = AUTO_MESSAGE_PROMPT.format(
        url=risk_context.get('url', 'Unknown'),
        domain=risk_context.get('domain', 'Unknown'),
        protocol=risk_context.get('protocol', 'Unknown'),
        error_code=risk_context.get('errorCode', ''),
        risk_level=risk_context.get('riskLevel', 'Unknown'),
        risk_score=risk_context.get('riskScore', 0),
        timestamp=risk_context.get('timestamp', 'Unknown'),
        detailed_threat_analysis=detailed_analysis
    )
    
    # Log the complete prompt being sent to LLM
    logger.info("=== AUTO MESSAGE PROMPT TO LLM ===")
    logger.info(prompt)
    logger.info("=== END AUTO MESSAGE PROMPT ===")
    
    return prompt

def build_conversation_prompt(risk_context, conversation_history, user_message):
    """Build prompt for regular conversation"""
    # Log the conversation setup
    logger.info(f"Building conversation prompt for message: {user_message}")
    logger.info(f"Risk context keys available: {list(risk_context.keys())}")
    logger.debug(f"Complete risk context: {json.dumps(risk_context, indent=2, default=str)}")
    
    # Extract detailed threat analysis and threats summary
    detailed_analysis = extract_detailed_threat_analysis(risk_context)
    threats_context = extract_threats_summary(risk_context)
    
    logger.info(f"Generated detailed analysis length: {len(detailed_analysis)}")
    logger.info(f"Generated threats summary: {threats_context}")
    
    # Format conversation history
    history_text = format_conversation_history(conversation_history)
    
    prompt = CONVERSATION_PROMPT.format(
        url=risk_context.get('url', 'Unknown'),
        domain=risk_context.get('domain', 'Unknown'),
        protocol=risk_context.get('protocol', 'Unknown'),
        risk_level=risk_context.get('riskLevel', 'Unknown'),
        risk_score=risk_context.get('riskScore', 0),
        timestamp=risk_context.get('timestamp', 'Unknown'),
        detailed_threat_analysis=detailed_analysis,
        threats_context=threats_context,
        conversation_history=history_text,
        user_message=user_message
    )
    
    # Log the complete prompt being sent to LLM
    logger.info("=== CONVERSATION PROMPT TO LLM ===")
    logger.info(prompt)
    logger.info("=== END CONVERSATION PROMPT ===")
    
    return prompt

def format_conversation_history(conversation_history):
    """Format conversation history for prompt"""
    if not conversation_history:
        return "No previous conversation"
    
    history_parts = []
    for turn in conversation_history[-3:]:  # Last 3 turns
        user_msg = turn.get('user_message', '')
        bot_response = turn.get('bot_response', '')
        
        if user_msg and user_msg != 'auto':
            history_parts.append(f"User: {user_msg}")
        if bot_response:
            # Extract just the text, not the full JSON if present
            if isinstance(bot_response, str) and bot_response.startswith('{'):
                try:
                    parsed = json.loads(bot_response)
                    bot_response = parsed.get('response', bot_response)
                except:
                    pass
            history_parts.append(f"Assistant: {bot_response[:200]}...")  # Truncate long responses
    
    return "\n".join(history_parts) if history_parts else "No previous conversation"

def parse_json_response(text):
    """Parse JSON response from LLM output with multiple fallback strategies"""
    if not text:
        return None
    
    try:
        # Strategy 1: Direct JSON parsing
        parsed = json.loads(text)
        if 'response' in parsed and 'suggestions' in parsed:
            return {
                'response': parsed['response'],
                'suggestions': validate_suggestions(parsed['suggestions'])
            }
    except json.JSONDecodeError:
        pass
    
    try:
        # Strategy 2: Extract JSON from code blocks
        json_match = re.search(r'```(?:json)?\s*\n?({.*?})\s*\n?```', text, re.DOTALL)
        if json_match:
            parsed = json.loads(json_match.group(1))
            return {
                'response': parsed.get('response', ''),
                'suggestions': validate_suggestions(parsed.get('suggestions', []))
            }
    except:
        pass
    
    try:
        # Strategy 3: Find JSON object in text
        json_match = re.search(r'({[^{}]*"response"[^{}]*"suggestions"[^{}]*})', text, re.DOTALL)
        if json_match:
            parsed = json.loads(json_match.group(1))
            return {
                'response': parsed.get('response', ''),
                'suggestions': validate_suggestions(parsed.get('suggestions', []))
            }
    except:
        pass
    
    # Strategy 4: Extract components separately
    try:
        response_match = re.search(r'"response"\s*:\s*"([^"]*(?:\\.[^"]*)*)"', text, re.DOTALL)
        suggestions_match = re.search(r'"suggestions"\s*:\s*\[(.*?)\]', text, re.DOTALL)
        
        if response_match:
            response = response_match.group(1).replace('\\"', '"').replace('\\n', '\n')
            suggestions = []
            
            if suggestions_match:
                suggestions_text = suggestions_match.group(1)
                suggestion_matches = re.findall(r'"([^"]+)"', suggestions_text)
                suggestions = suggestion_matches[:4]
            
            return {
                "response": response,
                "suggestions": validate_suggestions(suggestions)
            }
    except:
        pass
    
    logger.debug(f"Failed to parse JSON from response: {text[:100]}...")
    return None

def validate_suggestions(suggestions):
    """Validate suggestions without adding fake ones"""
    validated = []
    
    if isinstance(suggestions, list):
        for s in suggestions[:4]:
            if isinstance(s, str) and 10 <= len(s) <= 200:  # Allow longer suggestions
                validated.append(s.strip())
    
    # Return only valid suggestions, don't pad with fake ones
    return validated

def extract_detailed_threat_analysis(risk_context):
    """
    Extract and format detailed threat analysis from risk assessment data
    
    Args:
        risk_context (dict): Complete risk assessment data
        
    Returns:
        str: Formatted detailed threat analysis
    """
    threat_assessment = risk_context.get('threat_assessment', {})
    individual_scores = threat_assessment.get('individual_scores', {})
    full_responses = threat_assessment.get('full_responses', {})
    
    analysis_parts = []
    
    # URLBERT Analysis
    urlbert_data = full_responses.get('urlbert', {})
    if urlbert_data:
        urlbert_score = individual_scores.get('urlbert', 0)
        confidence = urlbert_data.get('confidence', 0) * 100
        classification = urlbert_data.get('classification', 'unknown')
        probabilities = urlbert_data.get('probabilities', {})
        
        analysis_parts.append(f"""URLBERT AI Analysis:
- Risk Score: {urlbert_score:.1f}/100
- Classification: {classification.upper()}
- Confidence Level: {confidence:.1f}%
- Malicious Probability: {probabilities.get('malicious', 0)*100:.1f}%
- Benign Probability: {probabilities.get('benign', 0)*100:.1f}%
- Model Version: {urlbert_data.get('model_version', 'unknown')}""")
    
    # Google Safe Browsing Analysis
    gsb_data = full_responses.get('google_safebrowsing', {})
    if gsb_data:
        is_safe = gsb_data.get('is_safe', True)
        threat_count = gsb_data.get('threat_count', 0)
        threats = gsb_data.get('threats', [])
        
        if not is_safe and threat_count > 0:
            threat_details = []
            for threat in threats:
                threat_type = threat.get('type', 'UNKNOWN')
                platform = threat.get('platform', 'ANY_PLATFORM')
                severity = threat.get('severity', 'Unknown')
                threat_details.append(f"  - {threat_type} (Platform: {platform}, Severity: {severity})")
            
            analysis_parts.append(f"""Google Safe Browsing Analysis:
- Status: THREAT DETECTED
- Threat Count: {threat_count}
- Detected Threats:
{chr(10).join(threat_details)}
- Risk Assessment: CRITICAL - Confirmed by Google's threat intelligence""")
        else:
            analysis_parts.append("""Google Safe Browsing Analysis:
- Status: CLEAN
- No known threats detected
- Risk Assessment: No immediate Google-flagged concerns""")
    
    # VirusTotal Analysis
    vt_data = full_responses.get('virustotal', {})
    if vt_data:
        full_vt = vt_data.get('full_response', {})
        positives = full_vt.get('positives', 0)
        total = full_vt.get('total', 0)
        scan_date = full_vt.get('scan_date', 'Unknown')
        detection_ratio = f"{positives}/{total}" if total > 0 else "0/0"
        
        # Extract specific detections
        scans = full_vt.get('scans', {})
        positive_detections = []
        for engine, result in scans.items():
            if result.get('detected', False):
                detection_result = result.get('result', 'malware')
                positive_detections.append(f"  - {engine}: {detection_result}")
        
        analysis_parts.append(f"""VirusTotal Analysis:
- Detection Ratio: {detection_ratio} ({(positives/total*100 if total > 0 else 0):.1f}%)
- Scan Date: {scan_date}
- Total Engines: {total}
- Positive Detections: {positives}
{chr(10).join(positive_detections[:10]) if positive_detections else '  - No detections'}
- Permalink: {vt_data.get('permalink', 'N/A')}""")
    
    # WHOIS Analysis
    whois_data = full_responses.get('whois')
    if whois_data and whois_data is not None:
        whois_score = individual_scores.get('whois', 0)
        analysis_parts.append(f"""WHOIS Analysis:
- Domain Risk Score: {whois_score:.1f}/100
- Domain Information: Available
- Assessment: Domain reputation analysis completed""")
    else:
        analysis_parts.append("""WHOIS Analysis:
- Status: No domain information available
- Assessment: Unable to perform domain reputation analysis""")
    
    # Final Risk Assessment Summary
    final_score = threat_assessment.get('final_risk_score', 0)
    analysis_parts.append(f"""Combined Risk Assessment:
- Final Risk Score: {final_score:.2f}/100
- Risk Level: {risk_context.get('riskLevel', 'UNKNOWN')}
- Assessment Method: Threat-weighted aggregation of all security services
- Confidence: High (Multiple independent sources analyzed)""")
    
    return "\n\n".join(analysis_parts)

def extract_threats_summary(risk_context):
    """
    Extract a concise summary of detected threats
    
    Args:
        risk_context (dict): Complete risk assessment data
        
    Returns:
        str: Formatted threats summary
    """
    threat_assessment = risk_context.get('threat_assessment', {})
    individual_scores = threat_assessment.get('individual_scores', {})
    full_responses = threat_assessment.get('full_responses', {})
    
    threats = []
    
    # Check Google Safe Browsing threats
    gsb_data = full_responses.get('google_safebrowsing', {})
    if gsb_data and not gsb_data.get('is_safe', True):
        gsb_threats = gsb_data.get('threats', [])
        for threat in gsb_threats:
            threats.append(f"🛡️ {threat.get('type', 'Security concern')} identified by Google Safe Browsing")
    
    # Check VirusTotal detections
    vt_data = full_responses.get('virustotal', {})
    if vt_data:
        positives = vt_data.get('full_response', {}).get('positives', 0)
        total = vt_data.get('full_response', {}).get('total', 0)
        if positives > 0:
            threats.append(f"📊 {positives}/{total} security engines flagged this URL")
    
    # Check URLBERT classification
    urlbert_data = full_responses.get('urlbert', {})
    if urlbert_data and urlbert_data.get('classification') == 'malicious':
        confidence = urlbert_data.get('confidence', 0) * 100
        threats.append(f"🤖 AI analysis indicates security concerns ({confidence:.1f}% confidence)")
    
    # Check protocol security
    if risk_context.get('protocol') == 'http':
        threats.append("🔓 Unencrypted connection - consider HTTPS alternatives")
    
    # Check error codes
    error_code = risk_context.get('errorCode', '')
    if error_code and error_code != 'none':
        threats.append(f"⚠️ Browser reported: {error_code}")
    
    if not threats:
        threats.append("✅ No significant security concerns detected")
    
    return "\n".join(threats)

# Removed fallback functions - Lambda should fail gracefully if LLM fails

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
        
        # Log Knowledge Base query setup
        logger.info(f"Setting up Knowledge Base query for message: {message}")
        logger.info(f"Enhanced query: {enhanced_query}")
        logger.debug(f"Risk context for KB: {json.dumps(risk_context, indent=2, default=str)}")
        
        # Extract detailed threat analysis for KB context
        detailed_analysis = extract_detailed_threat_analysis(risk_context)
        threats_summary = extract_threats_summary(risk_context)
        
        # Build the KB prompt template
        kb_prompt_template = KNOWLEDGE_BASE_PROMPT_TEMPLATE.format(
            url=risk_context.get('url', 'Unknown'),
            domain=risk_context.get('domain', 'Unknown'),
            protocol=risk_context.get('protocol', 'Unknown'),
            risk_level=risk_context.get('riskLevel', 'Unknown'),
            risk_score=risk_context.get('riskScore', 'Unknown'),
            timestamp=risk_context.get('timestamp', 'Unknown'),
            detailed_threat_analysis=detailed_analysis,
            threats_summary=threats_summary
        )
        
        # Log the Knowledge Base prompt template
        logger.info("=== KNOWLEDGE BASE PROMPT TEMPLATE ===")
        logger.info(kb_prompt_template)
        logger.info("=== END KB PROMPT TEMPLATE ===")
        
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
                            'textPromptTemplate': kb_prompt_template
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
        
        # The KB response should now include JSON with suggestions
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

# Removed build_system_prompt - replaced by build_auto_prompt and build_conversation_prompt

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

# Removed generate_suggested_questions - now handled by LLM in structured response

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