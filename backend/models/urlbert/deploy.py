import boto3
import time
import tarfile
import os
import tempfile

print("URLBERT DEPLOYMENT")
print("Matches training script structure")
print("=" * 60)

# Initialize clients
sagemaker_client = boto3.client('sagemaker')
s3_client = boto3.client('s3')
sts_client = boto3.client('sts')

# Get current account and region
account_id = sts_client.get_caller_identity()['Account']
region = boto3.Session().region_name

# Configuration
model_artifacts_uri = 's3://https-shield-ml-models/urlbert-training/pytorch-training-2025-07-16-22-25-20-148/output/model.tar.gz'
endpoint_name = "urlbert-endpoint"
model_name = f"urlbert-model-{int(time.time())}"
endpoint_config_name = f"urlbert-model-config-{int(time.time())}"

# Get PyTorch inference image URI
image_uri = f"763104351884.dkr.ecr.{region}.amazonaws.com/pytorch-inference:2.0.0-cpu-py310-ubuntu20.04-sagemaker"

print(f"Model artifacts: {model_artifacts_uri}")
print(f"Endpoint name: {endpoint_name}")

print("Creating inference script...")

# Create the inference script (vocab will be loaded from model artifacts)
inference = '''"""
URLBERT Inference Script
"""

import json
import logging
import os
import sys
import torch
import torch.nn as nn
import torch.nn.functional as F
import time
import traceback
from transformers import AutoConfig, AutoModelForMaskedLM, BertTokenizer

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BertForSequenceClassification(nn.Module):
    """
    BERT model for binary sequence classification (benign vs malicious)
    Based on research paper implementation
    """
    def __init__(self, bert_model, num_labels=2):
        super(BertForSequenceClassification, self).__init__()
        self.bert = bert_model
        
        # Enable gradient computation for all parameters
        for name, param in self.bert.named_parameters():
            param.requires_grad = True
            
        self.dropout = nn.Dropout(p=0.1)
        self.classifier = nn.Linear(768, num_labels)  # Binary classification
        
        # Remove the MLM head to save memory
        self.bert.cls = nn.Sequential()

    def forward(self, input_ids, attention_mask=None, token_type_ids=None):
        """
        Forward pass for classification
        """
        outputs = self.bert(
            input_ids=input_ids,
            attention_mask=attention_mask,
            token_type_ids=token_type_ids,
            output_hidden_states=True
        )
        
        # Get [CLS] token representation
        hidden_states = outputs.hidden_states[-1][:, 0, :]
        hidden_states = self.dropout(hidden_states)
        logits = self.classifier(hidden_states)
        
        return logits

def model_fn(model_dir):
    """Load model"""
    try:
        logger.info("=" * 50)
        logger.info("URLBERT MODEL LOADING")
        logger.info("=" * 50)
        
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        logger.info(f"Using device: {device}")
        
        # Look for vocab.txt in model directory
        vocab_path = os.path.join(model_dir, 'vocab.txt')
        if not os.path.exists(vocab_path):
            logger.error(f"vocab.txt not found at {vocab_path}")
            # List all files to debug
            logger.info("Files in model directory:")
            for root, dirs, files in os.walk(model_dir):
                for file in files:
                    logger.info(f"  {os.path.join(root, file)}")
            raise FileNotFoundError(f"vocab.txt not found in {model_dir}")
        
        # Initialize tokeniser
        tokenizer = BertTokenizer(vocab_file=vocab_path, do_lower_case=True)
        logger.info(f"Tokenizer initialized with {len(tokenizer.vocab)} tokens")
        
        # Load config
        config_path = os.path.join(model_dir, 'config.json')
        if os.path.exists(config_path):
            config = AutoConfig.from_pretrained(config_path)
            logger.info("Loaded config from model directory")
        else:
            logger.error("config.json not found in model directory")
            raise FileNotFoundError(f"config.json not found in {model_dir}")
        
        # Create BERT model
        bert_model = AutoModelForMaskedLM.from_config(config)
        bert_model.resize_token_embeddings(5000)
        
        # Create classification model
        model = BertForSequenceClassification(bert_model, num_labels=2)
        
        # Load the saved state dict
        model_path = os.path.join(model_dir, 'pytorch_model.bin')
        if not os.path.exists(model_path):
            # Try other common names
            for fname in ['model.pth', 'model.pt', 'pytorch_model.pt']:
                alt_path = os.path.join(model_dir, fname)
                if os.path.exists(alt_path):
                    model_path = alt_path
                    break
        
        logger.info(f"Loading model from: {model_path}")
        state_dict = torch.load(model_path, map_location=device)
        
        # Load state dict
        model.load_state_dict(state_dict)
        logger.info("Model weights loaded successfully")
        
        # Verify the structure
        logger.info("Model structure verification:")
        logger.info(f"  - Has bert.bert structure: {'bert.bert.embeddings.word_embeddings.weight' in state_dict}")
        logger.info(f"  - Has classifier: {'classifier.weight' in state_dict}")
        logger.info(f"  - Classifier shape: {state_dict['classifier.weight'].shape}")
        
        model.to(device)
        model.eval()
        
        # Disable gradients for inference
        for param in model.parameters():
            param.requires_grad = False
        
        logger.info("Model ready for inference")
        
        return {
            'model': model,
            'tokenizer': tokenizer,
            'device': device,
            'max_length': 200
        }
        
    except Exception as e:
        logger.error(f"ERROR in model loading: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise

def preprocess_url(url, tokenizer, max_length=200):
    """
    Preprocess URL
    """
    # Tokenize URL (character-level tokenization)
    tokens = tokenizer.tokenize(url)
    
    # Add special tokens
    tokens = ["[CLS]"] + tokens + ["[SEP]"]
    
    # Convert to IDs
    ids = tokenizer.convert_tokens_to_ids(tokens)
    
    # Create attention mask and token type IDs
    masks = [1] * len(ids)
    types = [0] * len(ids)
    
    # Pad or truncate to max_length
    if len(ids) < max_length:
        # Pad
        padding_length = max_length - len(ids)
        ids = ids + [0] * padding_length
        masks = masks + [0] * padding_length
        types = types + [1] * padding_length  # Use 1 for padding
    else:
        # Truncate
        ids = ids[:max_length]
        masks = masks[:max_length]
        types = types[:max_length]
    
    assert len(ids) == len(masks) == len(types) == max_length
    
    return ids, masks, types

def input_fn(request_body, content_type='application/json'):
    """Parse input request"""
    logger.info(f"Input: {request_body}")
    if content_type == 'application/json':
        if isinstance(request_body, str):
            data = json.loads(request_body)
        else:
            data = request_body
        
        # Extract URL
        if 'inputs' in data:
            url = data['inputs']
        elif 'url' in data:
            url = data['url']
        else:
            raise Exception("No URL found in request")
            
        logger.info(f"Extracted URL: {url}")
        return str(url)
    else:
        raise Exception(f"Unsupported content type: {content_type}")

def predict_fn(url, model_artifacts):
    """Make prediction"""
    try:
        logger.info(f"Making prediction for: {url}")
        
        model = model_artifacts['model']
        tokenizer = model_artifacts['tokenizer']
        device = model_artifacts['device']
        max_length = model_artifacts['max_length']
        
        # Preprocess URL
        input_ids, attention_masks, token_type_ids = preprocess_url(url, tokenizer, max_length)
        
        # Convert to tensors
        input_ids = torch.tensor([input_ids], dtype=torch.long).to(device)
        attention_masks = torch.tensor([attention_masks], dtype=torch.long).to(device)
        token_type_ids = torch.tensor([token_type_ids], dtype=torch.long).to(device)
        
        logger.info(f"Input shapes - ids: {input_ids.shape}, masks: {attention_masks.shape}, types: {token_type_ids.shape}")
        
        # Make prediction
        with torch.no_grad():
            # Forward pass
            logits = model(
                input_ids=input_ids,
                attention_mask=attention_masks,
                token_type_ids=token_type_ids
            )
            
            # Get probabilities
            probabilities = F.softmax(logits, dim=-1)
            
            # Get prediction
            predictions = torch.argmax(logits, dim=-1)
            predicted_class = predictions.item()
            
            # Extract probabilities - Training uses:
            # Label 0 = benign, Label 1 = malicious
            prob_benign = probabilities[0][0].item()
            prob_malicious = probabilities[0][1].item()
            
            # Classification
            classification = 'malicious' if predicted_class == 1 else 'benign'
            confidence = probabilities[0][predicted_class].item()
            
            logger.info(f"Raw logits: {logits.tolist()}")
            logger.info(f"Probabilities - benign: {prob_benign:.4f}, malicious: {prob_malicious:.4f}")
            logger.info(f"Classification: {classification} (class {predicted_class})")
            
            result = {
                'url': url,
                'risk_score': prob_malicious,
                'classification': classification,
                'confidence': confidence,
                'probabilities': {
                    'benign': prob_benign,
                    'malicious': prob_malicious
                },
                'predicted_class': predicted_class,
                'logits': logits.tolist(),
                'model_type': 'urlbert',
                'device': str(device),
                'status': 'success'
            }
            
            return result
            
    except Exception as e:
        logger.error(f"Prediction FAILED: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return {
            'url': url,
            'error': str(e),
            'status': 'prediction_failed'
        }

def output_fn(prediction, accept='application/json'):
    """Format output"""
    return json.dumps({
        'predictions': [prediction],
        'model_version': 'urlbert-v1',
        'timestamp': time.time()
    })
'''

# Download and repackage model
print("\nDownloading and repackaging model...")

with tempfile.TemporaryDirectory() as temp_dir:
    # Parse S3 URI
    bucket_name = model_artifacts_uri.split('/')[2]
    s3_key = '/'.join(model_artifacts_uri.split('/')[3:])
    
    # Download original model
    original_path = os.path.join(temp_dir, 'original_model.tar.gz')
    print(f"Downloading from s3://{bucket_name}/{s3_key}")
    s3_client.download_file(bucket_name, s3_key, original_path)
    print("Model downloaded")
    
    # Extract original model
    extract_dir = os.path.join(temp_dir, 'extracted')
    os.makedirs(extract_dir)
    
    with tarfile.open(original_path, 'r:gz') as tar:
        tar.extractall(extract_dir)
    
    print(f"Extracted contents: {os.listdir(extract_dir)}")
    
    # Check if vocab.txt exists
    if not os.path.exists(os.path.join(extract_dir, 'vocab.txt')):
        print("vocab.txt not found in model artifacts")
    
    # Add inference script
    code_dir = os.path.join(extract_dir, 'code')
    os.makedirs(code_dir, exist_ok=True)
    
    inference_path = os.path.join(code_dir, 'inference.py')
    with open(inference_path, 'w') as f:
        f.write(inference)
    
    # Add requirements
    requirements_content = """transformers==4.30.0
torch>=2.0.0
numpy
"""
    
    requirements_path = os.path.join(code_dir, 'requirements.txt')
    with open(requirements_path, 'w') as f:
        f.write(requirements_content)
    
    print("Added inference script")
    
    # Create new model package
    new_model_path = os.path.join(temp_dir, 'urlbert.tar.gz')
    with tarfile.open(new_model_path, 'w:gz') as tar:
        for item in os.listdir(extract_dir):
            item_path = os.path.join(extract_dir, item)
            tar.add(item_path, arcname=item)
    
    # Upload to S3
    bucket = 'https-shield-ml-models'
    key = f'urlbert/model-{int(time.time())}.tar.gz'
    model_uri = f's3://{bucket}/{key}'
    
    print(f"Uploading to {model_uri}")
    s3_client.upload_file(new_model_path, bucket, key)
    print("Upload completed")

# Get execution role
print("\nGetting execution role...")
try:
    import sagemaker
    role = sagemaker.get_execution_role()
    print(f"Using SageMaker execution role")
except:
    # Use the role from your training script
    role = "arn:aws:iam::738470489149:role/SageMaker-ExecutionRole-HTTPSShield"
    print(f"Using configured role: {role}")

# Delete existing endpoint if it exists
print(f"\nChecking for existing endpoint: {endpoint_name}")
try:
    sagemaker_client.describe_endpoint(EndpointName=endpoint_name)
    print(f"Deleting existing endpoint: {endpoint_name}")
    sagemaker_client.delete_endpoint(EndpointName=endpoint_name)
    
    # Wait for deletion
    while True:
        try:
            sagemaker_client.describe_endpoint(EndpointName=endpoint_name)
            print("Waiting for endpoint deletion...")
            time.sleep(10)
        except:
            break
    print("Existing endpoint deleted")
except:
    print("No existing endpoint found")

# Create SageMaker Model
print(f"\nCreating SageMaker model: {model_name}")

try:
    model_response = sagemaker_client.create_model(
        ModelName=model_name,
        PrimaryContainer={
            'Image': image_uri,
            'ModelDataUrl': model_uri,
            'Environment': {
                'SAGEMAKER_SUBMIT_DIRECTORY': '/opt/ml/code',
                'SAGEMAKER_PROGRAM': 'inference.py',
                'SAGEMAKER_REGION': region,
                'PYTORCH_JIT': '0',
                'TS_DEFAULT_WORKERS_PER_MODEL': '1'
            }
        },
        ExecutionRoleArn=role
    )
    print(f"Model created")
except Exception as e:
    print(f"Model creation failed: {e}")
    raise

# Create Endpoint Configuration
print(f"\nCreating endpoint configuration: {endpoint_config_name}")

try:
    config_response = sagemaker_client.create_endpoint_config(
        EndpointConfigName=endpoint_config_name,
        ProductionVariants=[
            {
                'VariantName': 'primary',
                'ModelName': model_name,
                'InitialInstanceCount': 1,
                'InstanceType': 'ml.t2.medium',
                'InitialVariantWeight': 1
            }
        ]
    )
    print(f"Endpoint config created")
except Exception as e:
    print(f"Endpoint config creation failed: {e}")
    raise

# Create Endpoint
print(f"\nCreating endpoint: {endpoint_name}")

try:
    endpoint_response = sagemaker_client.create_endpoint(
        EndpointName=endpoint_name,
        EndpointConfigName=endpoint_config_name
    )
    
    print(f"\nDEPLOYMENT INITIATED")
    print(f"Endpoint: {endpoint_name}")
    print("Instance: ml.t2.medium (CPU-accelerated)")

except Exception as e:
    print(f"Endpoint creation failed: {e}")
    raise

print(f"\nDEPLOYMENT COMPLETED")