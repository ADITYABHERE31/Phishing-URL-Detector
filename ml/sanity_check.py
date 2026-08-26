import joblib
import pandas as pd
from feature_extractor import extract_features

model = joblib.load("ml/phishing_model.pkl")

# Known-legitimate real-world sites (NOT from the training CSV)
legit_urls = [
    "https://www.google.com/",
    "https://www.microsoft.com/en-in",
    "https://www.amazon.in/",
    "https://www.wikipedia.org/",
    "https://www.github.com/",
    "https://www.nytimes.com/",
    "https://www.apple.com/",
    "https://www.linkedin.com/",
]

# Known phishing-style patterns (typical lookalike/urgent-keyword tricks)
phishing_like_urls = [
    "http://secure-login-paypal.com.verify-account.tk/",
    "http://192.168.1.1/login.php",
    "http://amaz0n-account-update.xyz/signin",
    "http://microsoft-support-verify.info/wp-login",
]

correct = 0
total = 0

print("=== Legit sites (expect: Legitimate URL) ===")
for url in legit_urls:
    f = extract_features(url)
    X = pd.DataFrame([f])[model.feature_names_in_]
    pred = model.predict(X)[0]
    result = "Legitimate URL" if pred == 1 else "Phishing URL"
    ok = "OK" if pred == 1 else "WRONG"
    correct += (pred == 1)
    total += 1
    print(f"[{ok}] {url} -> {result}")

print("\n=== Phishing-style URLs (expect: Phishing URL) ===")
for url in phishing_like_urls:
    f = extract_features(url)
    X = pd.DataFrame([f])[model.feature_names_in_]
    pred = model.predict(X)[0]
    result = "Legitimate URL" if pred == 1 else "Phishing URL"
    ok = "OK" if pred == 0 else "WRONG"
    correct += (pred == 0)
    total += 1
    print(f"[{ok}] {url} -> {result}")

print(f"\nSanity check score: {correct}/{total}")