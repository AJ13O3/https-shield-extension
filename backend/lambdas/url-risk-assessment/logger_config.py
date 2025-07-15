"""
Logger Configuration for HTTPS Shield Lambda Functions

Provides centralized logging configuration for all Lambda functions
with structured logging, proper formatting, and CloudWatch integration.

Author: HTTPS Shield Extension Team
Version: 1.0.0
"""

import logging
import json
import os
from datetime import datetime
from typing import Any, Dict

class StructuredFormatter(logging.Formatter):
    """Custom formatter for structured logging in CloudWatch"""
    
    def format(self, record: logging.LogRecord) -> str:
        # Create structured log entry
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'message': record.getMessage(),
            'logger': record.name,
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add Lambda context if available
        if hasattr(record, 'request_id'):
            log_entry['request_id'] = record.request_id
        
        # Add function info from environment
        log_entry['lambda_function'] = os.environ.get('AWS_LAMBDA_FUNCTION_NAME', 'unknown')
        log_entry['lambda_version'] = os.environ.get('AWS_LAMBDA_FUNCTION_VERSION', 'unknown')
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields if present
        if hasattr(record, 'extra_fields'):
            log_entry.update(record.extra_fields)
        
        return json.dumps(log_entry)

def setup_logger(name: str = __name__, level: str = None) -> logging.Logger:
    """
    Set up logger with CloudWatch-optimized configuration
    
    Args:
        name: Logger name (usually __name__)
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    
    Returns:
        Configured logger instance
    """
    # Get log level from environment or use default
    log_level = level or os.environ.get('LOG_LEVEL', 'INFO')
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger
    
    # Create console handler (CloudWatch captures stdout)
    handler = logging.StreamHandler()
    handler.setLevel(getattr(logging, log_level.upper()))
    
    # Set formatter
    formatter = StructuredFormatter()
    handler.setFormatter(formatter)
    
    # Add handler to logger
    logger.addHandler(handler)
    
    # Prevent propagation to avoid duplicate logs
    logger.propagate = False
    
    return logger

def log_lambda_event(logger: logging.Logger, event: Dict[str, Any], context: Any = None):
    """
    Log Lambda event with structured format
    
    Args:
        logger: Logger instance
        event: Lambda event
        context: Lambda context (optional)
    """
    log_data = {
        'event_type': 'lambda_invocation',
        'event': event
    }
    
    if context:
        log_data['context'] = {
            'function_name': getattr(context, 'function_name', 'unknown'),
            'function_version': getattr(context, 'function_version', 'unknown'),
            'invoked_function_arn': getattr(context, 'invoked_function_arn', 'unknown'),
            'memory_limit_in_mb': getattr(context, 'memory_limit_in_mb', 'unknown'),
            'remaining_time_in_millis': getattr(context, 'get_remaining_time_in_millis', lambda: 0)(),
            'aws_request_id': getattr(context, 'aws_request_id', 'unknown')
        }
    
    logger.info("Lambda function invoked", extra={'extra_fields': log_data})

def log_performance_metric(logger: logging.Logger, operation: str, duration_ms: float, **kwargs):
    """
    Log performance metrics
    
    Args:
        logger: Logger instance
        operation: Operation name
        duration_ms: Duration in milliseconds
        **kwargs: Additional metrics
    """
    metrics = {
        'metric_type': 'performance',
        'operation': operation,
        'duration_ms': duration_ms,
        **kwargs
    }
    
    logger.info(f"Performance metric: {operation}", extra={'extra_fields': metrics})

def log_error(logger: logging.Logger, error: Exception, context: Dict[str, Any] = None):
    """
    Log error with structured format
    
    Args:
        logger: Logger instance
        error: Exception instance
        context: Additional context
    """
    error_data = {
        'error_type': 'exception',
        'error_class': error.__class__.__name__,
        'error_message': str(error)
    }
    
    if context:
        error_data['context'] = context
    
    logger.error(f"Error occurred: {error}", extra={'extra_fields': error_data}, exc_info=True)

def log_api_request(logger: logging.Logger, url: str, method: str, status_code: int, duration_ms: float):
    """
    Log API request details
    
    Args:
        logger: Logger instance
        url: Request URL
        method: HTTP method
        status_code: Response status code
        duration_ms: Request duration
    """
    api_data = {
        'metric_type': 'api_request',
        'url': url,
        'method': method,
        'status_code': status_code,
        'duration_ms': duration_ms
    }
    
    logger.info(f"API request: {method} {url}", extra={'extra_fields': api_data})

def log_security_event(logger: logging.Logger, event_type: str, details: Dict[str, Any]):
    """
    Log security-related events
    
    Args:
        logger: Logger instance
        event_type: Type of security event
        details: Event details
    """
    security_data = {
        'event_type': 'security',
        'security_event_type': event_type,
        'details': details
    }
    
    logger.warning(f"Security event: {event_type}", extra={'extra_fields': security_data})

# Create default logger instance
default_logger = setup_logger('https_shield')

# Export commonly used functions
__all__ = [
    'setup_logger',
    'log_lambda_event',
    'log_performance_metric',
    'log_error',
    'log_api_request',
    'log_security_event',
    'default_logger'
]