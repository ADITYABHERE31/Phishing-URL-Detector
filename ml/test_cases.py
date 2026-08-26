import sys
import os
import pandas as pd
import joblib

sys.path.insert(0, os.path.dirname(__file__))
from feature_extractor import extract_features
from heuristic_detector import analyze_url

model = joblib.load("ml/phishing_model.pkl")

TEST_CASES = [
    ("Legitimate — major site", "https://www.google.com/", "SAFE"),
    ("Legitimate — major site", "https://www.wikipedia.org/", "SAFE"),
    ("Legitimate — major site", "https://www.github.com/", "SAFE"),
    ("IP address as domain", "http://192.168.1.1/login.php", "HIGH RISK"),
    ("IP address as domain", "http://185.23.45.12/secure/account", "HIGH RISK"),
    ("Excessive subdomains", "http://login.account.verify.security.example.com/", "HIGH RISK"),
    ("Long URL with keywords", "http://example.com/account/verify/login/secure/update/confirm/session/token/12345", "HIGH RISK"),
    ("Hyphen-heavy lookalike domain", "http://secure-login-paypal-account.com/", "HIGH RISK"),
    ("Suspicious keyword + free TLD", "http://verify-account-update.tk/", "HIGH RISK"),
    ("@ symbol hiding destination", "http://google.com@malicious-site.ru/login", "HIGH RISK"),
    ("No HTTPS, otherwise plain", "http://example-shop.com/", "SUSPICIOUS"),
    ("Percent-encoded characters", "http://example.com/redirect?url=%68%74%74%70", "SUSPICIOUS"),
]

def run_tests():
    rows = []
    passed = 0
    for name, url, expected in TEST_CASES:
        heuristic_result = analyze_url(url)
        features = extract_features(url)
        input_data = pd.DataFrame([features])[model.feature_names_in_]
        ml_prediction = model.predict(input_data)[0]
        ml_says_phishing = (ml_prediction == 0)

        if ml_says_phishing or heuristic_result["level"] == "HIGH RISK":
            final_level = "HIGH RISK"
        elif heuristic_result["level"] == "SUSPICIOUS":
            final_level = "SUSPICIOUS"
        else:
            final_level = "SAFE"

        status = "PASS" if final_level == expected else "FAIL"
        passed += (status == "PASS")
        indicators = "; ".join(i["message"] for i in heuristic_result["indicators"]) or "None"

        rows.append({
            "Test Case": name, "Input URL": url, "Expected": expected,
            "Actual": final_level, "Heuristic Score": heuristic_result["score"],
            "ML Result": "Phishing" if ml_says_phishing else "Legitimate",
            "Indicators": indicators, "Result": status,
        })
    return rows, passed, len(TEST_CASES)

def print_markdown_table(rows):
    print("| Test Case | Input URL | Expected | Actual | Score | ML Result | Pass/Fail |")
    print("|---|---|---|---|---|---|---|")
    for r in rows:
        url_short = r["Input URL"] if len(r["Input URL"]) <= 50 else r["Input URL"][:47] + "..."
        print(f"| {r['Test Case']} | `{url_short}` | {r['Expected']} | {r['Actual']} | {r['Heuristic Score']} | {r['ML Result']} | {r['Result']} |")

if __name__ == "__main__":
    rows, passed, total = run_tests()
    print_markdown_table(rows)
    print(f"\n**Score: {passed}/{total} passed**\n")