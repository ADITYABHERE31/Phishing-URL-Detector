import os
import pandas as pd
from flask import Flask, request, jsonify
import joblib
import requests
from urllib.parse import urlparse

from feature_extractor import extract_features
from heuristic_detector import analyze_url


app = Flask(__name__)

model = joblib.load("ml/phishing_model.pkl")
PHISHTANK_FILE = "ml/phishtank.csv"

def check_phishtank(url):
    if not os.path.exists(PHISHTANK_FILE):
        return False

    try:
        df = pd.read_csv(PHISHTANK_FILE)

        df = df[
            (df["verified"] == "yes") &
            (df["online"] == "yes")
        ]

        return url.strip() in set(df["url"].astype(str).str.strip())

    except Exception:
        return False


SAFE_BROWSING_API_KEY = "PASTE_YOUR_KEY_HERE"

SAFE_BROWSING_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    f"?key={SAFE_BROWSING_API_KEY}"
)


# ---------------------------------------------------------
# Google Safe Browsing
# ---------------------------------------------------------

def check_safe_browsing(url):

    if not SAFE_BROWSING_API_KEY or SAFE_BROWSING_API_KEY == "PASTE_YOUR_KEY_HERE":

        return {
            "checked": False,
            "flagged": False,
            "reason": "No API key configured"
        }

    payload = {
        "client": {
            "clientId": "phishguard",
            "clientVersion": "1.0"
        },

        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE"
            ],

            "platformTypes": [
                "ANY_PLATFORM"
            ],

            "threatEntryTypes": [
                "URL"
            ],

            "threatEntries": [
                {
                    "url": url
                }
            ]
        }
    }

    try:

        response = requests.post(
            SAFE_BROWSING_URL,
            json=payload,
            timeout=3
        )

        response.raise_for_status()

        data = response.json()

        flagged = (
            "matches" in data
            and len(data["matches"]) > 0
        )

        return {
            "checked": True,
            "flagged": flagged,
            "raw": data if flagged else None
        }

    except Exception as e:

        return {
            "checked": False,
            "flagged": False,
            "reason": str(e)
        }


# ---------------------------------------------------------
# ML probability
# ---------------------------------------------------------

def get_ml_result(url):

    features = extract_features(url)

    input_data = pd.DataFrame(
        [features]
    )[model.feature_names_in_]

    probabilities = model.predict_proba(input_data)[0]

    # Model classes are [0 = phishing, 1 = legitimate]
    phishing_probability = float(probabilities[0])
    legitimate_probability = float(probabilities[1])

    return {
        "phishing_probability": phishing_probability,
        "legitimate_probability": legitimate_probability
    }


# ---------------------------------------------------------
# Final decision
# ---------------------------------------------------------

def combine_results(
    ml_result,
    heuristic_result,
    safe_browsing_result
):

    # ---------------------------------------------
    # 1. Google confirms malicious
    # ---------------------------------------------

    if safe_browsing_result["flagged"]:

        return "HIGH RISK"


    heuristic_level = heuristic_result["level"]
    heuristic_score = heuristic_result["score"]

    ml_phishing_probability = ml_result["phishing_probability"]


    # ---------------------------------------------
    # 2. Strong heuristic evidence
    # ---------------------------------------------

    if heuristic_level == "HIGH RISK":

        return "HIGH RISK"


    # ---------------------------------------------
    # 3. ML is only a supporting signal.
    #
    # Don't allow the URL-only model to declare
    # Google/ChatGPT/etc. phishing by itself.
    # ---------------------------------------------

    if (
        ml_phishing_probability >= 0.90
        and heuristic_score >= 25
    ):
        return "HIGH RISK"


    if (
        ml_phishing_probability >= 0.70
        and heuristic_score >= 25
    ):
        return "SUSPICIOUS"


    # ---------------------------------------------
    # 4. Moderate heuristic evidence
    # ---------------------------------------------

    if heuristic_level == "SUSPICIOUS":

        return "SUSPICIOUS"


    # ---------------------------------------------
    # 5. ML alone is NOT enough
    #
    # This is what fixes the Google/ChatGPT problem.
    # ---------------------------------------------

    return "LOW RISK"


# ---------------------------------------------------------
# API
# ---------------------------------------------------------

@app.route("/predict", methods=["POST"])
def predict():

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "No JSON data received."
        }), 400


    url = data.get("url", "").strip()


    if not url:

        return jsonify({
            "error": "URL is required."
        }), 400
    
    phishtank_flagged = check_phishtank(url)

    if phishtank_flagged:

         return jsonify({
            "url": url,
            "ml_result": "Known phishing URL",
            "ml_phishing_probability": 100.0,
            "ml_legitimate_probability": 0.0,
            "heuristic_score": 100,
            "heuristic_level": "HIGH RISK",
            "indicators": [
                "PhishTank identifies this URL as a verified and currently online phishing URL."
            ],
            "final_level": "HIGH RISK",
            "safe_browsing_checked": False,
            "phishtank_checked": True
        })


    parsed = urlparse(url)


    # -----------------------------------------------------
    # Browser internal pages
    # -----------------------------------------------------

    if parsed.scheme in [
        "chrome",
        "chrome-extension",
        "edge",
        "about",
        "brave"
    ]:

        return jsonify({

            "url": url,

            "ml_result": "Not Scanned",

            "heuristic_score": 0,

            "heuristic_level": "NOT APPLICABLE",

            "indicators": [
                "This is a browser internal page and is not a normal website."
            ],

            "final_level": "NOT APPLICABLE",

            "safe_browsing_checked": False

        })


    # -----------------------------------------------------
    # Heuristic analysis
    # -----------------------------------------------------

    heuristic_result = analyze_url(url)


    # -----------------------------------------------------
    # ML analysis
    # -----------------------------------------------------

    ml_result = get_ml_result(url)


    # -----------------------------------------------------
    # Safe Browsing
    # -----------------------------------------------------

    sb_result = check_safe_browsing(url)


    # -----------------------------------------------------
    # Final decision
    # -----------------------------------------------------

    final_level = combine_results(
        ml_result,
        heuristic_result,
        sb_result
    )


    # -----------------------------------------------------
    # Indicators
    # -----------------------------------------------------

    indicators = [
        indicator["message"]
        for indicator in heuristic_result["indicators"]
    ]


    if sb_result["flagged"]:

        indicators.insert(
            0,
            "Google Safe Browsing identified this URL as a known malicious site."
        )


    # -----------------------------------------------------
    # ML explanation
    # -----------------------------------------------------

    if final_level == "LOW RISK":

        ml_display = "No strong signs of phishing detected"

    elif final_level == "SUSPICIOUS":

        ml_display = "Some phishing indicators detected"

    else:

        ml_display = "Multiple strong phishing indicators detected"


    # -----------------------------------------------------
    # Terminal logging
    # -----------------------------------------------------

    print("\n==============================")

    print("URL:", url)

    print(
        "ML phishing probability:",
        round(ml_result["phishing_probability"] * 100, 2),
        "%"
    )

    print(
        "ML legitimate probability:",
        round(ml_result["legitimate_probability"] * 100, 2),
        "%"
    )

    print(
        "Heuristic:",
        heuristic_result["level"],
        heuristic_result["score"]
    )

    print("Safe Browsing:", sb_result)

    print("Final:", final_level)

    print("==============================\n")


    # -----------------------------------------------------
    # Response
    # -----------------------------------------------------

    return jsonify({

        "url": url,

        "ml_result": ml_display,


        "heuristic_score":
            heuristic_result["score"],

        "heuristic_level":
            heuristic_result["level"],

        "indicators":
            indicators,

        "final_level":
            final_level,

        "safe_browsing_checked":
            sb_result["checked"]

    })


# ---------------------------------------------------------
# Start server
# ---------------------------------------------------------

if __name__ == "__main__":

    app.run(
        port=5000,
        debug=False
    )