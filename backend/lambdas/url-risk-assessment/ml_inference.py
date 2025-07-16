"""
ML Inference Service for HTTPS Shield

This module handles communication with SageMaker endpoints for ML model inference.
It provides a unified interface for URLBERT and XGBoost model predictions.

Author: HTTPS Shield Extension Team
Version: 2.0.0 (Function-based)
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
        'urlbert': os.environ.get('URLBERT_ENDPOINT_NAME'),
        'xgboost': os.environ.get('XGBOOST_ENDPOINT_NAME')
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
        
        # Prepare input for URLBERT
        input_data = {
            "instances": [{"url": url}]
        }
        
        # Make prediction request
        start_time = time.time()
        response = sagemaker_runtime.invoke_endpoint(
            EndpointName=endpoints['urlbert'],
            ContentType='application/json',
            Body=json.dumps(input_data)
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
        
        # URLBERT typically returns classification scores
        return {
            'risk_score': float(prediction.get('risk_score', 0.5)) * 100,
            'confidence': float(prediction.get('confidence', 0.5)),
            'model_version': 'urlbert-1.0',
            'categories': prediction.get('categories', {}),
            'features_used': prediction.get('features', [])
        }
        
    except Exception as e:
        logger.error(f"Error processing URLBERT response: {e}")
        return None

def get_xgboost_prediction(features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get risk prediction from XGBoost model
    
    Args:
        features: Feature dictionary for XGBoost model
        
    Returns:
        Dictionary containing prediction results or None if endpoint unavailable
    """
    endpoints = _get_endpoint_names()
    
    if not endpoints['xgboost']:
        logger.warning("XGBoost endpoint not configured")
        return None
    
    try:
        logger.info("Requesting XGBoost prediction")
        
        # Prepare features for XGBoost
        feature_vector = _prepare_xgboost_features(features)
        input_data = {
            "instances": [feature_vector]
        }
        
        # Make prediction request
        start_time = time.time()
        response = sagemaker_runtime.invoke_endpoint(
            EndpointName=endpoints['xgboost'],
            ContentType='application/json',
            Body=json.dumps(input_data)
        )
        
        # Log performance
        inference_time = (time.time() - start_time) * 1000
        log_performance_metric(logger, 'xgboost_inference', inference_time)
        
        # Parse response
        result = json.loads(response['Body'].read().decode())
        
        # Extract prediction data
        prediction = _process_xgboost_response(result)
        
        logger.info(f"XGBoost prediction complete: {prediction['risk_score']:.2f}")
        return prediction
        
    except ClientError as e:
        log_error(logger, e, {'operation': 'xgboost_prediction', 'features': str(features)})
        return None
    except Exception as e:
        log_error(logger, e, {'operation': 'xgboost_prediction', 'features': str(features)})
        return None

def _process_xgboost_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """Process XGBoost model response"""
    try:
        # Extract prediction from response
        predictions = response.get('predictions', [])
        if not predictions:
            raise ValueError("No predictions in XGBoost response")
        
        prediction = predictions[0]
        
        # XGBoost typically returns probability scores
        return {
            'risk_score': float(prediction.get('risk_probability', 0.5)) * 100,
            'confidence': float(prediction.get('confidence', 0.5)),
            'model_version': 'xgboost-1.0',
            'feature_importance': prediction.get('feature_importance', {}),
            'decision_path': prediction.get('decision_path', [])
        }
        
    except Exception as e:
        logger.error(f"Error processing XGBoost response: {e}")
        return None

def _prepare_xgboost_features(features: Dict[str, Any]) -> List[float]:
    """
    Prepare features for XGBoost model inference
    
    Args:
        features: Raw feature dictionary
        
    Returns:
        List of feature values in correct order
    """
    # Define feature order for XGBoost model
    feature_order = [
        'url_length',
        'domain_length',
        'subdomain_count',
        'has_ip_address',
        'has_suspicious_tld',
        'has_suspicious_keywords',
        'protocol_is_https',
        'has_ssl_errors',
        'domain_age_days',
        'reputation_score',
        'external_threat_score'
    ]
    
    # Extract features in correct order
    feature_vector = []
    for feature_name in feature_order:
        value = features.get(feature_name, 0.0)
        # Ensure numeric value
        if isinstance(value, bool):
            value = 1.0 if value else 0.0
        elif not isinstance(value, (int, float)):
            value = 0.0
        feature_vector.append(float(value))
    
    return feature_vector

def create_ml_features(url: str, domain_analysis: Dict[str, Any], 
                      error_analysis: Dict[str, Any], 
                      external_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create feature dictionary for ML models
    
    Args:
        url: The URL being analyzed
        domain_analysis: Domain analysis results
        error_analysis: Error analysis results
        external_data: External intelligence data
        
    Returns:
        Dictionary of features for ML inference
    """
    features = {
        # URL-based features
        'url_length': len(url),
        'domain_length': domain_analysis.get('length', 0),
        'subdomain_count': domain_analysis.get('subdomain_count', 0),
        'has_ip_address': len(domain_analysis.get('suspicious_patterns', [])) > 0,
        'has_suspicious_tld': any('tk' in pattern or 'ml' in pattern 
                                for pattern in domain_analysis.get('suspicious_patterns', [])),
        'has_suspicious_keywords': len(domain_analysis.get('risk_indicators', [])) > 0,
        
        # Security features
        'protocol_is_https': url.startswith('https://'),
        'has_ssl_errors': error_analysis.get('severity', 'UNKNOWN') in ['HIGH', 'CRITICAL'],
        
        # External intelligence features
        'domain_age_days': external_data.get('domain_age', 0),
        'reputation_score': external_data.get('reputation_score', 0.5),
        'external_threat_score': external_data.get('combined_risk_score', 0.0) / 100.0,
    }
    
    return features

def get_combined_ml_prediction(url: str, domain_analysis: Dict[str, Any], 
                              error_analysis: Dict[str, Any], 
                              external_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get combined prediction from both ML models
    
    Args:
        url: The URL being analyzed
        domain_analysis: Domain analysis results
        error_analysis: Error analysis results
        external_data: External intelligence data
        
    Returns:
        Combined ML prediction results
    """
    try:
        # Create features for ML models
        features = create_ml_features(url, domain_analysis, error_analysis, external_data)
        
        # Get predictions from both models
        urlbert_prediction = None
        xgboost_prediction = None
        
        # Try URLBERT prediction
        try:
            urlbert_prediction = get_urlbert_prediction(url)
        except Exception as e:
            logger.warning(f"URLBERT prediction failed: {e}")
        
        # Try XGBoost prediction
        try:
            xgboost_prediction = get_xgboost_prediction(features)
        except Exception as e:
            logger.warning(f"XGBoost prediction failed: {e}")
        
        # Combine predictions
        return _combine_predictions(urlbert_prediction, xgboost_prediction)
        
    except Exception as e:
        log_error(logger, e, {'operation': 'combined_ml_prediction', 'url': url[:50]})
        return {
            'ml_risk_score': 0.0,
            'ml_confidence': 0.0,
            'models_used': [],
            'individual_predictions': {},
            'error': 'Combined ML prediction failed'
        }

def _combine_predictions(urlbert_prediction: Optional[Dict[str, Any]], 
                        xgboost_prediction: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Combine predictions from multiple ML models
    
    Args:
        urlbert_prediction: URLBERT prediction results
        xgboost_prediction: XGBoost prediction results
        
    Returns:
        Combined prediction results
    """
    if not urlbert_prediction and not xgboost_prediction:
        return {
            'ml_risk_score': 0.0,
            'ml_confidence': 0.0,
            'models_used': [],
            'individual_predictions': {},
            'error': 'No ML predictions available (SageMaker endpoints not deployed)'
        }
    
    # Initialize result
    result = {
        'ml_risk_score': 0.0,
        'ml_confidence': 0.0,
        'models_used': [],
        'individual_predictions': {}
    }
    
    scores = []
    confidences = []
    
    # Process URLBERT prediction
    if urlbert_prediction:
        score = urlbert_prediction.get('risk_score', 0.0)
        confidence = urlbert_prediction.get('confidence', 0.0)
        scores.append(score)
        confidences.append(confidence)
        result['models_used'].append('urlbert')
        result['individual_predictions']['urlbert'] = urlbert_prediction
    
    # Process XGBoost prediction
    if xgboost_prediction:
        score = xgboost_prediction.get('risk_score', 0.0)
        confidence = xgboost_prediction.get('confidence', 0.0)
        scores.append(score)
        confidences.append(confidence)
        result['models_used'].append('xgboost')
        result['individual_predictions']['xgboost'] = xgboost_prediction
    
    # Combine scores (weighted average based on confidence)
    if confidences:
        total_confidence = sum(confidences)
        if total_confidence > 0:
            weighted_score = sum(s * c for s, c in zip(scores, confidences)) / total_confidence
            result['ml_risk_score'] = weighted_score
            result['ml_confidence'] = total_confidence / len(confidences)
        else:
            result['ml_risk_score'] = sum(scores) / len(scores)
            result['ml_confidence'] = 0.5
    
    return result