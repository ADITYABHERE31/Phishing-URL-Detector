# 🛡️ PhishGuard

PhishGuard is a browser extension that detects potentially malicious and
phishing URLs using a combination of:

- Machine Learning
- URL Heuristic Analysis
- Google Safe Browsing
- PhishTank

The goal is to provide users with a quick risk assessment before visiting
a suspicious website.

---

## 🚀 Features

- Real-time URL scanning
- Machine-learning based phishing detection
- Heuristic URL analysis
- Google Safe Browsing integration
- PhishTank verified phishing URL detection
- Risk classification:
  - 🟢 LOW RISK
  - 🟠 SUSPICIOUS
  - 🔴 HIGH RISK
- Chrome browser extension interface
- Local Flask API for ML prediction

---

## ⚙️ How It Works

PhishGuard uses multiple detection layers instead of relying on a
single method.

### 1. User enters a URL

The user enters a website URL into the PhishGuard browser extension.

### 2. URL Feature Extraction

The URL is analyzed and features are extracted, including:

- URL length
- Domain length
- Number of digits
- Number of special characters
- Number of subdomains
- Hyphen count
- Suspicious keywords
- Suspicious TLD
- HTTPS usage
- IP address usage
- URL encoding
- Query parameters
- `@` symbol
- Port usage
- Character patterns

### 3. Machine Learning Detection

The extracted URL features are passed to the trained machine-learning
model.

The model predicts whether the URL has characteristics associated with
phishing.

### 4. Heuristic Detection

PhishGuard also applies rule-based checks to identify suspicious URL
patterns such as:

- HTTP instead of HTTPS
- Suspicious keywords
- Excessive hyphens
- Suspicious domain structure
- Suspicious TLDs
- IP-based URLs
- Other unusual URL characteristics

### 5. PhishTank Verification

PhishGuard checks whether the URL is listed as a verified and currently
online phishing URL in the PhishTank dataset.

If PhishTank identifies the URL as phishing, PhishGuard immediately
classifies it as HIGH RISK.

### 6. Google Safe Browsing

The URL is also checked against Google Safe Browsing.

If Google Safe Browsing identifies the URL as malicious, the result is
classified as HIGH RISK.

### 7. Final Risk Assessment

The results from the different detection layers are combined to produce
the final risk level.

```text
                    ┌─────────────────┐
                    │  User enters URL │
                    └────────┬────────┘
                             ↓
                    ┌─────────────────┐
                    │ Feature         │
                    │ Extraction      │
                    └────────┬────────┘
                             ↓
              ┌──────────────┼──────────────┐
              ↓              ↓              ↓
        ┌──────────┐   ┌──────────┐   ┌──────────────┐
        │    ML    │   │Heuristics│   │ PhishTank    │
        │  Model   │   │          │   │              │
        └────┬─────┘   └────┬─────┘   └──────┬───────┘
             │              │                │
             └──────────────┼────────────────┘
                            ↓
                  ┌──────────────────┐
                  │ Google Safe      │
                  │ Browsing         │
                  └────────┬─────────┘
                           ↓
                  ┌──────────────────┐
                  │ Final Risk Level │
                  └──────────────────┘