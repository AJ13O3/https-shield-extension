"""
XGBoost Inference Script for SageMaker

This script handles inference requests for the XGBoost model in SageMaker.
It processes feature vectors and returns risk predictions.
"""

import json
import logging
import os
import pickle
import numpy as np
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class XGBoostPredictor:
    """
    XGBoost model predictor for URL risk assessment
    """
    
    def __init__(self):
        self.model = None
        self.feature_names = None
        self.scaler = None
        
    def model_fn(self, model_dir):
        """
        Load the XGBoost model from the model directory
        """
        try:
            logger.info(f"Loading XGBoost model from {model_dir}")
            
            # Load the trained model
            model_path = os.path.join(model_dir, 'xgboost-model')
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            
            # Load feature names if available
            feature_names_path = os.path.join(model_dir, 'feature_names.json')
            if os.path.exists(feature_names_path):
                with open(feature_names_path, 'r') as f:
                    self.feature_names = json.load(f)
            else:
                # Default feature names
                self.feature_names = [
                    'url_length', 'domain_length', 'subdomain_count',
                    'has_ip_address', 'has_suspicious_tld', 'has_suspicious_keywords',
                    'protocol_is_https', 'has_ssl_errors', 'domain_age_days',
                    'reputation_score', 'external_threat_score'
                ]
            
            # Load scaler if available
            scaler_path = os.path.join(model_dir, 'scaler.pkl')
            if os.path.exists(scaler_path):
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
            
            logger.info("XGBoost model loaded successfully")
            return self.model
            
        except Exception as e:
            logger.error(f"Error loading XGBoost model: {str(e)}")
            raise
    
    def input_fn(self, request_body, request_content_type):
        """
        Parse input request
        """
        try:
            if request_content_type == 'application/json':
                input_data = json.loads(request_body)
                
                # Extract feature vectors from instances
                feature_vectors = []
                if 'instances' in input_data:
                    for instance in input_data['instances']:
                        if isinstance(instance, list):
                            # Direct feature vector
                            feature_vectors.append(instance)
                        elif isinstance(instance, dict):
                            # Feature dictionary - convert to vector
                            feature_vector = self.dict_to_vector(instance)
                            feature_vectors.append(feature_vector)
                        else:
                            raise ValueError(f"Invalid instance format: {type(instance)}")
                else:
                    # Direct input
                    if isinstance(input_data, list):
                        feature_vectors = [input_data]
                    elif isinstance(input_data, dict):
                        feature_vector = self.dict_to_vector(input_data)
                        feature_vectors = [feature_vector]
                
                return np.array(feature_vectors)
                
            else:
                raise ValueError(f"Unsupported content type: {request_content_type}")
                
        except Exception as e:
            logger.error(f"Error parsing input: {str(e)}")
            raise
    
    def dict_to_vector(self, feature_dict):
        """
        Convert feature dictionary to vector using feature names
        """
        feature_vector = []
        
        for feature_name in self.feature_names:
            value = feature_dict.get(feature_name, 0.0)
            
            # Handle boolean values
            if isinstance(value, bool):
                value = 1.0 if value else 0.0
            elif not isinstance(value, (int, float)):
                value = 0.0
            
            feature_vector.append(float(value))
        
        return feature_vector
    
    def predict_fn(self, feature_vectors, model):
        """
        Make predictions on feature vectors
        """
        try:
            # Apply scaling if scaler is available
            if self.scaler:
                feature_vectors = self.scaler.transform(feature_vectors)
            
            # Make predictions
            predictions = []
            
            for i, features in enumerate(feature_vectors):
                # Reshape for single prediction
                features_reshaped = features.reshape(1, -1)
                
                # Get prediction probability
                try:
                    # Try predict_proba first (for classifiers)
                    if hasattr(model, 'predict_proba'):
                        prob = model.predict_proba(features_reshaped)[0]
                        risk_probability = prob[1] if len(prob) > 1 else prob[0]
                    else:
                        # Fallback to predict (for regressors)
                        risk_probability = model.predict(features_reshaped)[0]
                        # Ensure probability is in [0, 1] range
                        risk_probability = max(0.0, min(1.0, risk_probability))
                        
                except Exception as e:
                    logger.warning(f"Error getting probability: {e}")
                    risk_probability = 0.5  # Default to medium risk
                
                # Get feature importance
                feature_importance = {}
                if hasattr(model, 'feature_importances_'):
                    importance_values = model.feature_importances_
                    for j, importance in enumerate(importance_values):
                        if j < len(self.feature_names):
                            feature_importance[self.feature_names[j]] = float(importance)
                
                # Get decision path (if available)
                decision_path = []
                try:
                    if hasattr(model, 'decision_path'):
                        path = model.decision_path(features_reshaped)
                        decision_path = self.interpret_decision_path(path, features)
                except Exception:
                    # Decision path not available or failed
                    pass
                
                # Calculate confidence based on prediction certainty
                confidence = abs(risk_probability - 0.5) * 2  # Distance from 0.5, scaled to [0, 1]
                
                # Create prediction result
                prediction = {
                    'risk_probability': float(risk_probability),
                    'confidence': float(confidence),
                    'feature_importance': feature_importance,
                    'decision_path': decision_path,
                    'features_used': self.feature_names,
                    'feature_values': features.tolist() if hasattr(features, 'tolist') else list(features)
                }
                
                predictions.append(prediction)
            
            return predictions
            
        except Exception as e:
            logger.error(f"Error making predictions: {str(e)}")
            raise
    
    def interpret_decision_path(self, path, features):
        """
        Interpret XGBoost decision path for explainability
        """
        decision_steps = []
        
        try:
            # This is a simplified interpretation
            # In practice, you'd need to parse the actual tree structure
            for i, (feature_idx, threshold) in enumerate(path):
                if feature_idx < len(self.feature_names):
                    feature_name = self.feature_names[feature_idx]
                    feature_value = features[feature_idx]
                    
                    if feature_value <= threshold:
                        decision = f"{feature_name} <= {threshold:.3f}"
                    else:
                        decision = f"{feature_name} > {threshold:.3f}"
                    
                    decision_steps.append({
                        'step': i + 1,
                        'decision': decision,
                        'feature': feature_name,
                        'value': float(feature_value),
                        'threshold': float(threshold)
                    })
                    
        except Exception as e:
            logger.warning(f"Error interpreting decision path: {e}")
        
        return decision_steps
    
    def output_fn(self, predictions, accept):
        """
        Format output response
        """
        try:
            if accept == 'application/json':
                return json.dumps({
                    'predictions': predictions,
                    'model_version': 'xgboost-1.0',
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'feature_names': self.feature_names
                })
            else:
                raise ValueError(f"Unsupported accept type: {accept}")
                
        except Exception as e:
            logger.error(f"Error formatting output: {str(e)}")
            raise

# Create global predictor instance
predictor = XGBoostPredictor()

# SageMaker entry points
def model_fn(model_dir):
    return predictor.model_fn(model_dir)

def input_fn(request_body, request_content_type):
    return predictor.input_fn(request_body, request_content_type)

def predict_fn(input_data, model):
    return predictor.predict_fn(input_data, model)

def output_fn(predictions, accept):
    return predictor.output_fn(predictions, accept)