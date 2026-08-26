import re
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "signin", "banking", "password", "suspend", "unlock", "urgent",
    "billing", "webscr", "support",
]

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "info"
}


def analyze_url(url: str) -> dict:

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    triggered = []
    score = 0

    def fire(rule, points, message):
        nonlocal score
        score += points
        triggered.append({
            "rule": rule,
            "points": points,
            "message": message
        })

    # --------------------------------------------------
    # IP address
    # --------------------------------------------------

    if re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname):
        fire(
            "has_ip",
            25,
            "The domain is an IP address instead of a normal domain name."
        )

    # --------------------------------------------------
    # HTTP
    # --------------------------------------------------
    # HTTP is NOT automatically phishing.
    # Give it only a small warning score.

    if parsed.scheme == "http":
        fire(
            "no_https",
            5,
            "The site uses HTTP instead of HTTPS."
        )

    # --------------------------------------------------
    # @ symbol
    # --------------------------------------------------

    if "@" in url:
        fire(
            "has_at_symbol",
            25,
            "The URL contains an '@' symbol, which can hide the real destination."
        )

    # --------------------------------------------------
    # Too many subdomains
    # --------------------------------------------------

    subdomain_count = max(0, hostname.count(".") - 1)

    if subdomain_count > 2:
        fire(
            "many_subdomains",
            15,
            "The URL has an unusually high number of subdomains."
        )

    # --------------------------------------------------
    # Very long URL
    # --------------------------------------------------

    if len(url) > 100:
        fire(
            "long_url",
            10,
            "The URL is unusually long."
        )

    # --------------------------------------------------
    # Many hyphens
    # --------------------------------------------------

    if hostname.count("-") >= 3:
        fire(
            "many_hyphens",
            10,
            "The domain contains an unusually high number of hyphens."
        )

    # --------------------------------------------------
    # Suspicious keywords
    # --------------------------------------------------

    lowered_url = url.lower()

    matched_keywords = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in lowered_url
    ]

    if matched_keywords:

        # Keyword alone is weak evidence.
        fire(
            "suspicious_keyword",
            10,
            "The URL contains words commonly associated with phishing "
            f"(found: {', '.join(matched_keywords[:3])})."
        )

    # --------------------------------------------------
    # Encoded characters
    # --------------------------------------------------

    if re.search(r"%[0-9a-fA-F]{2}", url):
        fire(
            "has_encoded_chars",
            10,
            "The URL contains encoded characters that may disguise its content."
        )

    # --------------------------------------------------
    # Suspicious TLD
    # --------------------------------------------------

    tld = hostname.split(".")[-1] if "." in hostname else ""

    if tld in SUSPICIOUS_TLDS:
        fire(
            "suspicious_tld",
            10,
            "The domain uses a TLD that is frequently associated with abusive registrations."
        )

    # --------------------------------------------------
    # Important combination:
    #
    # A keyword is much more concerning when it appears
    # together with a suspicious domain structure.
    # --------------------------------------------------

    if (
        matched_keywords
        and hostname.count("-") >= 2
        and subdomain_count > 1
    ):
        fire(
            "combined_suspicious_structure",
            20,
            "The URL combines suspicious keywords with a highly unusual domain structure."
        )

    # --------------------------------------------------
    # Cap score
    # --------------------------------------------------

    score = min(score, 100)

    # --------------------------------------------------
    # Risk level
    # --------------------------------------------------

    if score >= 50:
        level = "HIGH RISK"
    elif score >= 25:
        level = "SUSPICIOUS"
    else:
        level = "SAFE"

    return {
        "score": score,
        "level": level,
        "indicators": triggered,
    }


if __name__ == "__main__":

    test_urls = [
        "https://www.google.com/",
        "https://chatgpt.com/",
        "http://192.168.1.1/login.php",
        "http://secure-login-paypal.com.verify-account.tk/",
    ]

    for test_url in test_urls:

        result = analyze_url(test_url)

        print(
            test_url,
            "->",
            result["level"],
            f"(score {result['score']})"
        )

        for indicator in result["indicators"]:
            print(" -", indicator["message"])