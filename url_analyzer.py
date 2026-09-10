import re
from urllib.parse import urlparse


def analyze_url(url):

    parsed_url = urlparse(url)

    result = {}

    # 1. HTTPS check
    result["HTTPS"] = url.lower().startswith("https://")

    # 2. Long URL check
    result["Long URL"] = len(url) > 100

    # 3. @ symbol check
    result["@ Symbol"] = "@" in url

    # 4. IP address check
    hostname = parsed_url.hostname

    if hostname:
        ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
        result["IP Address"] = bool(re.match(ip_pattern, hostname))
    else:
        result["IP Address"] = False

    # 5. Too many dots
    result["Too Many Dots"] = url.count(".") >= 4

    # 6. Suspicious keywords
    suspicious_words = [
        "login",
        "verify",
        "update",
        "account",
        "password",
        "security",
        "signin",
        "confirm"
    ]

    url_lower = url.lower()

    result["Suspicious Keyword"] = any(
        word in url_lower for word in suspicious_words
    )

    return result


if __name__ == "__main__":

    url = input("Enter a URL: ")

    result = analyze_url(url)

    print("\n===== URL ANALYSIS =====")

    for feature, detected in result.items():
        print(feature, ":", detected)
