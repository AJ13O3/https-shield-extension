"""
ML Inference Service for HTTPS Shield

This module handles communication with SageMaker endpoints for ML model inference.
It provides URLBERT model predictions and simple threat aggregation logic.
"""

import json
import time
import os
import boto3
from typing import Dict, Any, List, Optional
from botocore.exceptions import ClientError
from logger_config import setup_logger, log_error, log_performance_metric

# Configure logging
logger = setup_logger(__name__)

# Initialize SageMaker runtime client
sagemaker_runtime = boto3.client('sagemaker-runtime')

def _get_endpoint_names() -> Dict[str, str]:
    """Get SageMaker endpoint names from environment variables"""
    return {
        'urlbert': os.environ.get('URLBERT_ENDPOINT_NAME')
    }

def get_urlbert_prediction(url: str) -> Dict[str, Any]:
    """
    Get URL classification from URLBERT model
    
    Args:
        url: The URL to analyze
        
    Returns:
        Dictionary containing prediction results or None if endpoint unavailable
    """
    endpoints = _get_endpoint_names()
    
    if not endpoints['urlbert']:
        logger.warning("URLBERT endpoint not configured")
        return None
    
    try:
        logger.info(f"Requesting URLBERT prediction for URL: {url[:50]}...")
        
        # Prepare input for URLBERT (compatible with new endpoint)
        input_data = {
            "inputs": url
        }
        
        # Make prediction request
        start_time = time.time()
        response = sagemaker_runtime.invoke_endpoint(
            EndpointName=endpoints['urlbert'],
            ContentType='application/json',
            Body=json.dumps(input_data),
            Accept='application/json'
        )
        
        # Log performance
        inference_time = (time.time() - start_time) * 1000
        log_performance_metric(logger, 'urlbert_inference', inference_time)
        
        # Parse response
        result = json.loads(response['Body'].read().decode())
        
        # Extract prediction data
        prediction = _process_urlbert_response(result)
        
        logger.info(f"URLBERT prediction complete: {prediction['risk_score']:.2f}")
        return prediction
        
    except ClientError as e:
        log_error(logger, e, {'operation': 'urlbert_prediction', 'url': url[:50]})
        return None
    except Exception as e:
        log_error(logger, e, {'operation': 'urlbert_prediction', 'url': url[:50]})
        return None

def _process_urlbert_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """Process URLBERT model response"""
    try:
        # Extract prediction from response
        predictions = response.get('predictions', [])
        if not predictions:
            raise ValueError("No predictions in URLBERT response")
        
        prediction = predictions[0]
        
        # URLBERT returns risk_score as 0-1 probability (malicious probability)
        # No need to multiply by 100 as we want to keep it as percentage
        risk_score = float(prediction.get('risk_score', 0.5)) * 100
        
        # Extract probabilities if available
        probabilities = prediction.get('probabilities', {})
        
        return {
            'risk_score': risk_score,
            'confidence': float(prediction.get('confidence', 0.5)),
            'model_version': 'urlbert-1.0',
            'classification': prediction.get('classification', 'unknown'),
            'probabilities': {
                'benign': probabilities.get('benign', 0.5),
                'malicious': probabilities.get('malicious', 0.5)
            }
        }
        
    except Exception as e:
        logger.error(f"Error processing URLBERT response: {e}")
        return None

def calculate_final_risk_score(urlbert_score: float, safebrowsing_binary: float, 
                              virustotal_ratio: float, whois_heuristic: float) -> float:
    """
    Calculate final risk score using simple threat-weighted aggregation
    
    Args:
        urlbert_score: URLBERT prediction (0.0-1.0)
        safebrowsing_binary: Google Safe Browsing binary flag (0 or 1)
        virustotal_ratio: VirusTotal detection ratio (0.0-1.0)
        whois_heuristic: WHOIS heuristic score (0.0-1.0)
        
    Returns:
        Final risk score (0.0-1.0)
    """
    # If any critical threat detected, boost the score significantly
    threat_boost = 0.0
    if virustotal_ratio > 0:  # Any detection
        if virustotal_ratio >= 0.5:  # Majority of engines flagged
            threat_boost = 0.5
        elif virustotal_ratio >= 0.1:  # Multiple engines flagged (10%+)
            threat_boost = 0.4
        elif virustotal_ratio >= 0.03:  # Few engines flagged (3%+)
            threat_boost = 0.35
        else:  # Single engine flagged
            threat_boost = 0.25
    elif safebrowsing_binary == 1:  # Google detected threats (only if VT didn't)
        threat_boost = 0.3
    
    # Base weighted combination
    base_score = (
        virustotal_ratio * 0.35 +    # VirusTotal (equal weight with URLBERT)
        urlbert_score * 0.35 +       # URLBERT (equal weight with VirusTotal)
        safebrowsing_binary * 0.2 +  # Google Safe Browsing (binary)
        whois_heuristic * 0.1        # WHOIS (domain reputation)
    )
    
    # Apply threat boost and cap at 1.0
    final_score = min(base_score + threat_boost, 1.0)
    
    logger.info(f"Risk score calculation: URLBERT={urlbert_score:.3f}, "
               f"SafeBrowsing={safebrowsing_binary}, VT={virustotal_ratio:.3f}, "
               f"WHOIS={whois_heuristic:.3f}, boost={threat_boost}, final={final_score:.3f}")
    
    return final_score

def get_combined_threat_assessment(url: str, external_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get combined threat assessment using URLBERT and external API scores
    
    Args:
        url: The URL being analyzed
        external_data: External intelligence data with individual API scores
        
    Returns:
        Combined threat assessment results
    """
    try:
        # Get URLBERT prediction
        urlbert_result = None
        urlbert_score = 0.0
        
        try:
            urlbert_result = get_urlbert_prediction(url)
            if urlbert_result:
                # Convert URLBERT score from 0-100 to 0-1 for aggregation
                urlbert_score = urlbert_result.get('risk_score', 0.0) / 100.0
        except Exception as e:
            logger.warning(f"URLBERT prediction failed: {e}")
        
        # Extract individual API scores from external data
        safebrowsing_score = 0.0
        virustotal_score = 0.0
        whois_score = 0.0
        
        # Google Safe Browsing binary score
        if external_data.get('google_safebrowsing'):
            safebrowsing_score = external_data['google_safebrowsing'].get('extracted_score', 0.0)
        
        # VirusTotal detection ratio
        if external_data.get('virustotal'):
            virustotal_score = external_data['virustotal'].get('extracted_score', 0.0)
        
        # WHOIS heuristic score
        if external_data.get('whois'):
            whois_score = external_data['whois'].get('extracted_score', 0.0)
        
        # Calculate final risk score using simple aggregation
        final_risk_score = calculate_final_risk_score(
            urlbert_score, safebrowsing_score, virustotal_score, whois_score
        )
        
        # Build result with full context for LLM
        result = {
            'final_risk_score': final_risk_score * 100,  # Convert to 0-100 scale
            'individual_scores': {
                'urlbert': urlbert_score * 100,  # Show original URLBERT score (0-100)
                'google_safebrowsing': safebrowsing_score * 100,
                'virustotal': virustotal_score * 100,
                'whois': whois_score * 100
            },
            'full_responses': {  # Preserve for LLM context
                'urlbert': urlbert_result,
                'google_safebrowsing': external_data.get('google_safebrowsing'),
                'virustotal': external_data.get('virustotal'),
                'whois': external_data.get('whois')
            }
        }
        
        logger.info(f"Combined threat assessment complete: {final_risk_score:.3f}")
        return result
        
    except Exception as e:
        log_error(logger, e, {'operation': 'combined_threat_assessment', 'url': url[:50]})
        return {
            'final_risk_score': 0.0,
            'individual_scores': {},
            'full_responses': {},
            'error': 'Combined threat assessment failed'
        }