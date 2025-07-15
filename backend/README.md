# HTTPS Shield Backend - AWS Lambda Functions

## Overview
This directory contains the AWS Lambda functions for the HTTPS Shield extension backend. The functions are organized following AWS best practices with proper logging, error handling, and monitoring.

## Architecture

```
backend/
├── lambdas/
│   └── url-risk-assessment/
│       ├── lambda_function.py      # Main Lambda handler
│       ├── logger_config.py        # Centralized logging configuration
│       └── requirements.txt        # Python dependencies
└── README.md                      # This file
```

## Lambda Functions

### 1. URL Risk Assessment Lambda
**Location**: `lambdas/url-risk-assessment/`

**Purpose**: Analyzes URLs for security risks using multiple factors:
- Protocol analysis (HTTP vs HTTPS)
- Certificate error analysis
- Domain reputation checks
- URL structure analysis
- Suspicious pattern detection

**Features**:
- DynamoDB caching for performance
- Comprehensive structured logging
- Error handling with fallback
- Performance monitoring
- Input validation

**API Endpoint**: `/analyze-url` (POST)

**Request Format**:
```json
{
  "url": "http://example.com",
  "errorCode": "ERR_CERT_DATE_INVALID",
  "userAgent": "Mozilla/5.0...",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Response Format**:
```json
{
  "url": "http://example.com",
  "riskScore": 75,
  "riskLevel": "HIGH",
  "analysis": {
    "protocol_analysis": {...},
    "error_analysis": {...},
    "domain_analysis": {...},
    "url_structure": {...}
  },
  "recommendations": [...],
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Logging Configuration

All Lambda functions use the centralized `logger_config.py` which provides:

- **Structured JSON logging** for CloudWatch
- **Performance metrics** tracking
- **Error logging** with context
- **Security event logging**
- **Lambda invocation tracking**

### Log Levels
- `DEBUG`: Detailed debugging information
- `INFO`: General information and metrics
- `WARNING`: Warning conditions
- `ERROR`: Error conditions
- `CRITICAL`: Critical failures

### Environment Variables
- `LOG_LEVEL`: Set logging level (default: INFO)
- `DYNAMODB_TABLE_NAME`: DynamoDB table name
- `AWS_REGION`: AWS region

## AWS Resources Required

### 1. DynamoDB Table
**Table Name**: `https-shield-risk-assessments`
- **Partition Key**: `assessment_id` (String)
- **TTL**: `ttl` (Number)
- **Billing Mode**: On-demand

### 2. IAM Role
**Role Name**: `https-shield-lambda-execution-role`
- **Policies**:
  - `AWSLambdaBasicExecutionRole`
  - Custom policy for DynamoDB access

### 3. Lambda Function Configuration
- **Runtime**: Python 3.9
- **Memory**: 128 MB
- **Timeout**: 30 seconds
- **Handler**: `lambda_function.lambda_handler`

## Deployment Steps

### 1. Create DynamoDB Table
```bash
# Will be done in AWS Console
```

### 2. Create IAM Role
```bash
# Will be done in AWS Console
```

### 3. Deploy Lambda Function
```bash
# Package the function
cd lambdas/url-risk-assessment
zip -r ../url-risk-assessment.zip .

# Upload to AWS Console
```

### 4. Configure Environment Variables
- `DYNAMODB_TABLE_NAME`: `https-shield-risk-assessments`
- `LOG_LEVEL`: `INFO`

### 5. Set up API Gateway
- Create REST API
- Create `/analyze-url` resource
- Configure CORS
- Set up API key authentication

## Testing

### Local Testing
```bash
cd lambdas/url-risk-assessment
python -c "
import lambda_function
event = {'body': '{\"url\": \"http://example.com\"}'}
result = lambda_function.lambda_handler(event, {})
print(result)
"
```

### AWS Console Testing
Use the AWS Lambda console test feature with sample events.

## Monitoring

### CloudWatch Logs
- All functions log to CloudWatch Logs
- Structured JSON format for easy parsing
- Performance metrics included

### CloudWatch Metrics
- Function duration
- Error rates
- Invocation counts
- Custom metrics via structured logging

### Alarms (To be configured)
- High error rate
- Long execution time
- DynamoDB throttling

## Performance Targets

- **Response Time**: < 500ms (target: < 200ms)
- **Error Rate**: < 1%
- **Availability**: 99.9%
- **Cache Hit Rate**: > 80%

## Security

- Input validation for all requests
- Proper error handling without information leakage
- Secure secrets management
- Rate limiting via API Gateway
- CORS configuration

## Next Steps

1. **AWS Console Setup**:
   - Create AWS account
   - Set up IAM roles
   - Create DynamoDB table
   - Deploy Lambda function
   - Configure API Gateway

2. **Extension Integration**:
   - Update risk assessment page to use API client
   - Configure API endpoint URL
   - Test end-to-end functionality

3. **Monitoring Setup**:
   - Configure CloudWatch dashboards
   - Set up alarms
   - Performance testing