"""
URLBERT Training Script for SageMaker
Based on research paper implementation with optimizations for ml.p3.16xlarge
"""

import os
import sys
import json
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset, RandomSampler, SequentialSampler
import pandas as pd
import numpy as np
from transformers import AutoConfig, AutoModelForMaskedLM, BertTokenizer
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import logging
import time
import argparse
from tqdm import tqdm

# Configure logging
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

def preprocess_data_from_csv(filename, tokenizer, max_length=200):
    """
    Preprocess data from CSV file with URL and label columns
    Based on research paper preprocessing
    """
    logger.info(f"Loading data from {filename}")
    
    data = pd.read_csv(filename)
    logger.info(f"Loaded {len(data)} samples")
    
    input_ids = []
    attention_masks = []
    token_type_ids = []
    labels = []
    
    for idx, row in tqdm(data.iterrows(), total=len(data), desc="Preprocessing"):
        url = row['url']
        label = row['label']
        
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
            types = types + [1] * padding_length  # Use 1 for padding as per research paper
        else:
            # Truncate
            ids = ids[:max_length]
            masks = masks[:max_length]
            types = types[:max_length]
        
        assert len(ids) == len(masks) == len(types) == max_length
        
        input_ids.append(ids)
        attention_masks.append(masks)
        token_type_ids.append(types)
        
        # Process label
        if label == 'malicious' or label == '1':
            labels.append(1)
        elif label == 'benign' or label == '0':
            labels.append(0)
        else:
            logger.warning(f"Unknown label: {label}")
            labels.append(0)  # Default to benign
    
    logger.info(f"Processed {len(input_ids)} samples")
    return input_ids, attention_masks, token_type_ids, labels

def create_data_loader(input_ids, attention_masks, token_type_ids, labels, batch_size, shuffle=True):
    """
    Create PyTorch DataLoader
    """
    dataset = TensorDataset(
        torch.tensor(input_ids, dtype=torch.long),
        torch.tensor(attention_masks, dtype=torch.long),
        torch.tensor(token_type_ids, dtype=torch.long),
        torch.tensor(labels, dtype=torch.long)
    )
    
    sampler = RandomSampler(dataset) if shuffle else SequentialSampler(dataset)
    dataloader = DataLoader(dataset, sampler=sampler, batch_size=batch_size)
    
    return dataloader

def train_epoch(model, dataloader, optimizer, device, epoch):
    """
    Train for one epoch
    """
    model.train()
    total_loss = 0
    total_samples = 0
    
    for batch_idx, (input_ids, attention_masks, token_type_ids, labels) in enumerate(dataloader):
        # Move to device
        input_ids = input_ids.to(device)
        attention_masks = attention_masks.to(device)
        token_type_ids = token_type_ids.to(device)
        labels = labels.to(device)
        
        # Forward pass
        logits = model(
            input_ids=input_ids,
            attention_mask=attention_masks,
            token_type_ids=token_type_ids
        )
        
        # Calculate loss
        loss = F.cross_entropy(logits, labels)
        
        # Backward pass
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        
        total_loss += loss.item()
        total_samples += labels.size(0)
        
        # Log progress
        if (batch_idx + 1) % 100 == 0:
            avg_loss = total_loss / (batch_idx + 1)
            logger.info(f'Epoch {epoch}, Batch {batch_idx + 1}/{len(dataloader)}, Loss: {avg_loss:.4f}')
    
    return total_loss / len(dataloader)

def evaluate(model, dataloader, device):
    """
    Evaluate model on validation set
    """
    model.eval()
    total_loss = 0
    all_predictions = []
    all_labels = []
    
    with torch.no_grad():
        for input_ids, attention_masks, token_type_ids, labels in dataloader:
            # Move to device
            input_ids = input_ids.to(device)
            attention_masks = attention_masks.to(device)
            token_type_ids = token_type_ids.to(device)
            labels = labels.to(device)
            
            # Forward pass
            logits = model(
                input_ids=input_ids,
                attention_mask=attention_masks,
                token_type_ids=token_type_ids
            )
            
            # Calculate loss
            loss = F.cross_entropy(logits, labels)
            total_loss += loss.item()
            
            # Get predictions
            predictions = torch.argmax(logits, dim=-1)
            all_predictions.extend(predictions.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
    
    # Calculate metrics
    accuracy = accuracy_score(all_labels, all_predictions)
    precision = precision_score(all_labels, all_predictions, zero_division=0)
    recall = recall_score(all_labels, all_predictions, zero_division=0)
    f1 = f1_score(all_labels, all_predictions, zero_division=0)
    
    avg_loss = total_loss / len(dataloader)
    
    return avg_loss, accuracy, precision, recall, f1

def main():
    parser = argparse.ArgumentParser()
    
    # Data paths
    parser.add_argument('--train-data', type=str, default='/opt/ml/input/data/train/Train.csv')
    parser.add_argument('--test-data', type=str, default='/opt/ml/input/data/test/Test.csv')
    parser.add_argument('--model-dir', type=str, default='/opt/ml/model')
    parser.add_argument('--output-dir', type=str, default='/opt/ml/output')
    
    # Model parameters
    parser.add_argument('--vocab-path', type=str, default='/opt/ml/input/data/vocab/vocab.txt')
    parser.add_argument('--config-path', type=str, default='/opt/ml/input/data/config/config.json')
    parser.add_argument('--pretrained-model', type=str, default='/opt/ml/input/data/model/bert_model.bin')
    
    # Training parameters
    parser.add_argument('--batch-size', type=int, default=64)
    parser.add_argument('--epochs', type=int, default=5)
    parser.add_argument('--learning-rate', type=float, default=2e-5)
    parser.add_argument('--weight-decay', type=float, default=1e-4)
    parser.add_argument('--max-length', type=int, default=200)
    
    args = parser.parse_args()
    
    # Set up device
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Using device: {device}")
    
    if torch.cuda.is_available():
        logger.info(f"GPU count: {torch.cuda.device_count()}")
        for i in range(torch.cuda.device_count()):
            logger.info(f"GPU {i}: {torch.cuda.get_device_name(i)}")
    
    # Load tokenizer
    logger.info("Loading tokenizer...")
    tokenizer = BertTokenizer(vocab_file=args.vocab_path, do_lower_case=True)
    
    # Load model configuration
    logger.info("Loading model configuration...")
    config = AutoConfig.from_pretrained(args.config_path)
    config.vocab_size = 5000  # URLBERT vocabulary size
    
    # Load pre-trained URLBERT model
    logger.info("Loading pre-trained URLBERT model...")
    bert_model = AutoModelForMaskedLM.from_config(config)
    bert_model.resize_token_embeddings(config.vocab_size)
    
    # Load pre-trained weights
    if os.path.exists(args.pretrained_model):
        logger.info(f"Loading pre-trained weights from {args.pretrained_model}")
        bert_dict = torch.load(args.pretrained_model, map_location='cpu')
        bert_model.load_state_dict(bert_dict)
    else:
        logger.warning("No pre-trained weights found, starting from scratch")
    
    # Create classification model
    model = BertForSequenceClassification(bert_model, num_labels=2)
    
    # Multi-GPU setup
    if torch.cuda.device_count() > 1:
        logger.info(f"Using {torch.cuda.device_count()} GPUs")
        model = nn.DataParallel(model)
    
    model.to(device)
    
    # Load and preprocess data
    logger.info("Loading training data...")
    train_input_ids, train_attention_masks, train_token_type_ids, train_labels = preprocess_data_from_csv(
        args.train_data, tokenizer, args.max_length
    )
    
    logger.info("Loading test data...")
    test_input_ids, test_attention_masks, test_token_type_ids, test_labels = preprocess_data_from_csv(
        args.test_data, tokenizer, args.max_length
    )
    
    # Create data loaders
    # Scale batch size for multiple GPUs
    effective_batch_size = args.batch_size * max(1, torch.cuda.device_count())
    logger.info(f"Effective batch size: {effective_batch_size}")
    
    train_loader = create_data_loader(
        train_input_ids, train_attention_masks, train_token_type_ids, train_labels,
        effective_batch_size, shuffle=True
    )
    
    test_loader = create_data_loader(
        test_input_ids, test_attention_masks, test_token_type_ids, test_labels,
        effective_batch_size, shuffle=False
    )
    
    # Set up optimizer
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.learning_rate, weight_decay=args.weight_decay)
    
    # Training loop
    logger.info("Starting training...")
    best_accuracy = 0.0
    
    for epoch in range(1, args.epochs + 1):
        start_time = time.time()
        
        # Train
        train_loss = train_epoch(model, train_loader, optimizer, device, epoch)
        
        # Evaluate
        test_loss, accuracy, precision, recall, f1 = evaluate(model, test_loader, device)
        
        epoch_time = time.time() - start_time
        
        logger.info(f"Epoch {epoch}/{args.epochs}")
        logger.info(f"Train Loss: {train_loss:.4f}")
        logger.info(f"Test Loss: {test_loss:.4f}")
        logger.info(f"Accuracy: {accuracy:.4f}")
        logger.info(f"Precision: {precision:.4f}")
        logger.info(f"Recall: {recall:.4f}")
        logger.info(f"F1: {f1:.4f}")
        logger.info(f"Epoch Time: {epoch_time:.2f}s")
        logger.info("-" * 50)
        
        # Save best model
        if accuracy > best_accuracy:
            best_accuracy = accuracy
            logger.info(f"New best accuracy: {best_accuracy:.4f}")
            
            # Save model
            model_to_save = model.module if hasattr(model, 'module') else model
            torch.save(model_to_save.state_dict(), os.path.join(args.model_dir, 'pytorch_model.bin'))
            
            # Save tokenizer
            tokenizer.save_pretrained(args.model_dir)
            
            # Save config
            config.save_pretrained(args.model_dir)
            
            # Save metrics
            metrics = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1': f1,
                'epoch': epoch
            }
            
            with open(os.path.join(args.model_dir, 'metrics.json'), 'w') as f:
                json.dump(metrics, f, indent=2)
    
    logger.info("Training completed!")
    logger.info(f"Best accuracy: {best_accuracy:.4f}")

if __name__ == "__main__":
    main()