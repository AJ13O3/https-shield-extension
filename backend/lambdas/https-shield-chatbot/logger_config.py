"""
Logging configuration for HTTPS Shield Chatbot Lambda
"""

import logging
import os

def setup_logger():
    """
    Configure and return logger for the chatbot Lambda function
    """
    # Get log level from environment variable, default to INFO
    log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
    
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create and configure logger
    logger = logging.getLogger(__name__)
    logger.setLevel(getattr(logging, log_level, logging.INFO))
    
    return logger

# Create logger instance for module use
logger = setup_logger()