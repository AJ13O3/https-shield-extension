# HTTPS Shield Extension 🛡️

An AI-powered browser extension that enhances HTTPS-only mode warnings with real-time risk assessment and interactive chatbot support.

## 🎯 Project Overview

This project investigates HTTPS-only modes in web browsers and develops an AI-powered extension to improve user understanding and decision-making when encountering security warnings. The extension provides personalized risk assessments and an LLM-based chatbot to help users make informed decisions about website security.

## ✨ Key Features

- **Real-time Risk Assessment**: Dual AI model system (URLBERT + XGBoost) analyzes URLs for potential threats
- **Interactive Chatbot**: LLM-powered assistant provides contextual explanations and guidance
- **Cloud-Based Processing**: Minimal performance impact on user's browser
- **Comprehensive Analysis**: Integrates data from Google Safe Browsing, VirusTotal, PhishTank, and WHOIS
- **User-Friendly Interface**: Non-intrusive overlay with color-coded risk levels

## 🏗️ System Architecture

The extension follows a cloud-native architecture:
- **Frontend**: Chrome browser extension (JavaScript)
- **Backend**: Python FastAPI hosted on AWS Lambda
- **ML Models**: URLBERT and XGBoost models deployed on Amazon SageMaker
- **Database**: Amazon DynamoDB for session and risk assessment data
- **AI Services**: Amazon Bedrock for LLM chatbot functionality

## 🚀 Getting Started

### Prerequisites

- Python 3.9+
- Node.js 18+
- Chrome/Chromium browser
- AWS account with configured credentials

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/https-shield-extension.git
   cd https-shield-extension
   ```

2. **Set up the backend**
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Set up the extension**
   ```bash
   cd ../extension
   npm install
   npm run build
   ```

4. **Load the extension in Chrome**
   - Open Chrome and navigate to `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked" and select the `extension/dist` folder

## 📁 Project Structure

```
https-shield-extension/
├── extension/              # Browser extension source code
│   ├── src/
│   │   ├── background/    # Background scripts
│   │   ├── content/       # Content scripts
│   │   └── popup/         # Extension popup UI
│   └── manifest.json      # Extension manifest
├── backend/               # Python FastAPI backend
│   ├── app/
│   │   ├── api/          # API endpoints
│   │   ├── models/       # Data models
│   │   └── services/     # Business logic
│   └── requirements.txt
├── ml-models/            # Machine learning models
│   ├── training/         # Model training scripts
│   └── inference/        # Model inference code
└── research/             # Research materials and user study data
```
