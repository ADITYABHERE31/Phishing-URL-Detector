import re
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "bank",
    "banking",
    "paypal",
    "payment",
    "billing",
    "unlock",
    "suspend",
    "urgent",
]


def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # Keep feature extraction identical for training and live scanning.
    url_lower = url.lower()

    features = {}

    # 1. URL length
    features["url_length"] = len(url)

    # 2. Domain length
    features["domain_length"] = len(hostname)

    # 3. IP address
    features["is_ip"] = int(
        re.fullmatch(r"\d+\.\d+\.\d+\.\d+", hostname) is not None
    )

    # 4. Number of subdomains
    parts = hostname.split(".") if hostname else []
    features["subdomain_count"] = max(0, len(parts) - 2)

    # 5. Digits
    features["digit_count"] = sum(c.isdigit() for c in url)

    # 6. Special characters
    features["special_char_count"] = sum(
        not c.isalnum() for c in url
    )

    # 7. @ symbol
    features["has_at"] = int("@" in url)

    # 8. Hyphens in hostname
    features["hyphen_count"] = hostname.count("-")

    # 9. Query parameters
    features["query_count"] = url.count("?")

    # 10. Equals
    features["equals_count"] = url.count("=")

    # 11. Ampersand
    features["ampersand_count"] = url.count("&")

    # 12. Percent encoding
    features["encoded_count"] = len(re.findall(r"%[0-9a-fA-F]{2}", url))

    # 13. HTTPS
    features["is_https"] = int(parsed.scheme.lower() == "https")

    # 14. Suspicious keywords
    features["suspicious_keyword_count"] = sum(
        1 for keyword in SUSPICIOUS_KEYWORDS
        if keyword in url_lower
    )

    # 15. Suspicious TLD
    suspicious_tlds = {
        "tk", "ml", "ga", "cf", "gq",
        "xyz", "top", "click", "info"
    }

    tld = hostname.rsplit(".", 1)[-1].lower() if "." in hostname else ""

    features["suspicious_tld"] = int(tld in suspicious_tlds)

    # 16. URL contains a port
    features["has_port"] = int(parsed.port is not None)

    # 17. Path length
    features["path_length"] = len(parsed.path)

    # 18. Query length
    features["query_length"] = len(parsed.query)

    # 19. Digit ratio
    features["digit_ratio"] = (
        features["digit_count"] / len(url)
        if url else 0
    )

    # 20. Letter ratio
    letter_count = sum(c.isalpha() for c in url)

    features["letter_ratio"] = (
        letter_count / len(url)
        if url else 0
    )

    # 21. Repeated-character runs
    max_run = 1
    current_run = 1

    for i in range(1, len(url)):
        if url[i] == url[i - 1]:
            current_run += 1
            max_run = max(max_run, current_run)
        else:
            current_run = 1

    features["max_character_run"] = max_run

    return features