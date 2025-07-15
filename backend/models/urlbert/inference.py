"""
URLBERT Inference Script for SageMaker

This script handles inference requests for the URLBERT model in SageMaker.
It tokenizes URLs and returns risk predictions.
"""

import json
import logging
import os
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import numpy as np

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class URLBERTPredictor:
    """
    URLBERT model predictor for URL security classification
    """
    
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
    def model_fn(self, model_dir):
        """
        Load the URLBERT model from the model directory
        """
        try:
            logger.info(f"Loading URLBERT model from {model_dir}")
            
            # Load tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(model_dir)
            
            # Load model
            self.model = AutoModelForSequenceClassification.from_pretrained(
                model_dir,
                num_labels=2  # Binary classification: safe/unsafe
            )
            
            self.model.to(self.device)
            self.model.eval()
            
            logger.info("URLBERT model loaded successfully")
            return self.model
            
        except Exception as e:
            logger.error(f"Error loading URLBERT model: {str(e)}")
            raise
    
    def input_fn(self, request_body, request_content_type):
        """
        Parse input request
        """
        try:
            if request_content_type == 'application/json':
                input_data = json.loads(request_body)
                
                # Extract URLs from instances
                urls = []
                if 'instances' in input_data:
                    for instance in input_data['instances']:
                        if 'url' in instance:
                            urls.append(instance['url'])
                        else:
                            urls.append(str(instance))
                else:
                    # Direct URL input
                    urls = [input_data.get('url', '')]
                
                return urls
                
            else:
                raise ValueError(f"Unsupported content type: {request_content_type}")
                
        except Exception as e:
            logger.error(f"Error parsing input: {str(e)}")
            raise
    
    def predict_fn(self, urls, model):
        """
        Make predictions on URLs
        """
        try:
            predictions = []
            
            for url in urls:
                # Preprocess URL
                processed_url = self.preprocess_url(url)
                
                # Tokenize URL
                inputs = self.tokenizer(
                    processed_url,
                    max_length=512,
                    truncation=True,
                    padding=True,
                    return_tensors='pt'
                )
                
                # Move to device
                inputs = {key: val.to(self.device) for key, val in inputs.items()}
                
                # Make prediction
                with torch.no_grad():
                    outputs = model(**inputs)
                    logits = outputs.logits
                    
                    # Apply softmax to get probabilities
                    probabilities = torch.nn.functional.softmax(logits, dim=-1)
                    
                    # Get prediction
                    predicted_class = torch.argmax(probabilities, dim=-1).item()
                    confidence = torch.max(probabilities, dim=-1)[0].item()
                    
                    # Class 0 = safe, Class 1 = unsafe
                    risk_score = probabilities[0][1].item()  # Probability of unsafe
                    
                    # Create prediction result
                    prediction = {
                        'url': url,
                        'risk_score': risk_score,
                        'confidence': confidence,
                        'predicted_class': predicted_class,
                        'probabilities': {
                            'safe': probabilities[0][0].item(),
                            'unsafe': probabilities[0][1].item()
                        },
                        'categories': self.get_risk_categories(risk_score),
                        'features': self.extract_url_features(url)
                    }
                    
                    predictions.append(prediction)
            
            return predictions
            
        except Exception as e:
            logger.error(f"Error making predictions: {str(e)}")
            raise
    
    def preprocess_url(self, url):
        """
        Preprocess URL for URLBERT model
        """
        # Remove protocol if present
        if url.startswith('http://'):
            url = url[7:]
        elif url.startswith('https://'):
            url = url[8:]
        
        # Normalize URL
        url = url.lower().strip()
        
        # Add special tokens for different URL parts
        if '/' in url:
            domain, path = url.split('/', 1)
            url = f"[DOMAIN]{domain}[PATH]{path}"
        else:
            url = f"[DOMAIN]{url}"
        
        return url
    
    def extract_url_features(self, url):
        """
        Extract features from URL for explainability
        """
        features = []
        
        # Length features
        if len(url) > 100:
            features.append('very_long_url')
        elif len(url) > 50:
            features.append('long_url')
        
        # Domain features
        if url.count('.') > 3:
            features.append('multiple_subdomains')
        
        # Special characters
        if '-' in url:
            features.append('contains_hyphens')
        if '_' in url:
            features.append('contains_underscores')
        if url.count('/') > 3:
            features.append('deep_path')
        
        # Suspicious patterns
        suspicious_keywords = ['secure', 'bank', 'paypal', 'login', 'verify']
        for keyword in suspicious_keywords:
            if keyword in url.lower():
                features.append(f'suspicious_keyword_{keyword}')
        
        # IP address pattern
        import re
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        if re.search(ip_pattern, url):
            features.append('ip_address')
        
        return features
    
    def get_risk_categories(self, risk_score):
        """
        Categorize risk based on score
        """
        categories = {}
        
        if risk_score > 0.8:
            categories['malware'] = 'high'
        elif risk_score > 0.6:
            categories['malware'] = 'medium'
        else:
            categories['malware'] = 'low'
        
        if risk_score > 0.7:
            categories['phishing'] = 'high'
        elif risk_score > 0.4:
            categories['phishing'] = 'medium'
        else:
            categories['phishing'] = 'low'
        
        return categories
    
    def output_fn(self, predictions, accept):
        """
        Format output response
        """
        try:
            if accept == 'application/json':
                return json.dumps({
                    'predictions': predictions,
                    'model_version': 'urlbert-1.0',
                    'timestamp': torch.backends.mps.is_available()
                })
            else:
                raise ValueError(f"Unsupported accept type: {accept}")
                
        except Exception as e:
            logger.error(f"Error formatting output: {str(e)}")
            raise

# Create global predictor instance
predictor = URLBERTPredictor()

# SageMaker entry points
def model_fn(model_dir):
    return predictor.model_fn(model_dir)

def input_fn(request_body, request_content_type):
    return predictor.input_fn(request_body, request_content_type)

def predict_fn(input_data, model):
    return predictor.predict_fn(input_data, model)

def output_fn(predictions, accept):
    return predictor.output_fn(predictions, accept)