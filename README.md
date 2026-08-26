# Phishing URL Detector

A Chrome browser extension that detects potentially malicious and phishing URLs using a combination of machine learning, heuristic analysis, PhishTank verification, and Google Safe Browsing.

## Features

- Machine learning based URL classification
- Heuristic analysis of suspicious URL characteristics
- PhishTank verification for known phishing URLs
- Google Safe Browsing API integration
- Chrome extension popup interface
- Risk classification:
  - LOW RISK
  - HIGH RISK
- URL feature extraction and analysis
- Local Flask API for prediction

## How It Works

The extension sends a URL to the local Flask backend.

```text
User enters URL
       ↓
Chrome Extension
       ↓
Flask Prediction API
       ↓
 ┌───────────────────────────────┐
 │ URL Feature Extraction        │
 │ Machine Learning Model        │
 │ Heuristic Detection           │
 │ PhishTank Verification        │
 │ Google Safe Browsing          │
 └───────────────────────────────┘
       ↓
Risk Assessment
       ↓
LOW RISK / HIGH RISK
       ↓
Result displayed in Extension
Detection Approach
1. Machine Learning

The project extracts URL-based features such as:

URL length
Domain length
Number of digits
Number of special characters
Subdomain count
Suspicious keywords
Suspicious TLDs
HTTPS usage
Character patterns

These features are passed to a trained machine learning model to estimate whether a URL resembles phishing or legitimate URLs.

2. Heuristic Detection

Additional rules identify suspicious characteristics such as:

HTTP instead of HTTPS
Phishing-related keywords
Suspicious domain/TLD patterns
Other unusual URL characteristics
3. PhishTank

Known phishing URLs can be checked against PhishTank. If a URL is identified as a verified and currently online phishing URL, it is immediately treated as high risk.

4. Google Safe Browsing

Google Safe Browsing is used as an additional security signal to check URLs against Google's threat information.

Technologies
Python
Flask
Pandas
Scikit-learn
Joblib
JavaScript
HTML
CSS
Chrome Extension APIs
PhishTank
Google Safe Browsing API
Project Structure
Phishing-URL-Detector/
│
├── manifest.json
├── popup.html
├── popup.css
├── popup.js
├── icons/
│   └── icon128.png
│
└── ml/
    ├── api.py
    ├── feature_extractor.py
    ├── heuristic_detector.py
    ├── phishing_model.pkl
    ├── predict.py
    ├── train_model.py
    ├── sanity_check.py
    ├── test_cases.py
    └── inspect_dataset.py
Setup
1. Install Python dependencies

Install the required Python packages:

pip install flask pandas scikit-learn joblib requests
2. Configure Google Safe Browsing

Open:

ml/api.py

Find:

SAFE_BROWSING_API_KEY = "PASTE_YOUR_KEY_HERE"

Replace the placeholder with your own Google Safe Browsing API key.

Do not commit or publish your real API key.

3. Start the backend

From the project directory:

python ml/api.py

The Flask API runs locally at:

http://127.0.0.1:5000
4. Load the Chrome Extension
Open Chrome.
Go to:
chrome://extensions
Enable Developer mode.
Click Load unpacked.
Select the project folder containing manifest.json.
The Phishing URL Detector extension will appear in Chrome.
Testing

Example URLs can be tested through the local API.

https://google.com
→ LOW RISK

http://google-account-verify.xyz/
→ HIGH RISK

https://mmmyyttsswebmaiii.weebly.com
→ HIGH RISK

The project was also tested against a set of verified and currently online phishing URLs from PhishTank.

Security

The project is designed to keep API credentials out of source control.

The repository contains only:

PASTE_YOUR_KEY_HERE

Users must provide their own API key locally.

Dataset files and generated testing files are excluded from the Git repository using .gitignore.

Limitations

This project analyzes URL structure and external threat intelligence signals. A LOW RISK result does not guarantee that a website is completely safe.

The machine learning model may also produce incorrect classifications for previously unseen URL patterns.

Future Improvements
Improve model accuracy with additional datasets
Add more URL and domain-based features
Improve false-positive and false-negative handling
Add domain reputation information
Add a confidence visualization
Deploy the backend securely instead of using a local Flask server
Publish the extension through the Chrome Web Store
Disclaimer

This project is intended for educational, research, and cybersecurity demonstration purposes. It should not be considered a complete replacement for professional security solutions.