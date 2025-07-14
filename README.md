# HTTPS Shield Extension

An AI-powered browser extension that enhances user understanding and interaction with HTTPS-only mode warnings.

## Project Structure

```
https-shield-extension/
├── extension/              # Chrome extension code
│   ├── src/                # Source files
│   ├── icons/              # Extension icons
│   └── dist/               # Built files (gitignored)
├── backend/                # Lambda function code
├── webpack.config.js       # Build configuration
└── package.json            # Node dependencies
```

## Development Setup

### Prerequisites
- Node.js 20.x and npm
- Python 3.11+
- Chrome browser
- AWS account

### Quick Start

1. Install dependencies:
   ```bash
   npm install
   ```

2. Build the extension:
   ```bash
   npm run build
   ```

3. For development with auto-rebuild:
   ```bash
   npm run watch
   ```

4. Load the extension in Chrome:
   - Open Chrome and navigate to `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked"
   - Select the `extension` directory

## Phase 1 Goals

- Detect Chrome HTTPS warnings
- Send URL to AWS Lambda for risk assessment
- Display risk level to user
- Basic extension functionality

## AWS Setup (Manual via Console)

1. Create Lambda function with Python 3.11 runtime
2. Set up API Gateway with POST endpoint
3. Enable CORS and create API key
4. Update `background.js` with your API endpoint URL

## Testing

- Extension: Load unpacked in Chrome and test on HTTP sites
- Lambda: Use the `test_lambda.py` script for local testing