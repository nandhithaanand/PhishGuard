# Risk points for each suspicious feature
weights = {
    "HTTPS": 2,
    "Long URL": 1,
    "@ Symbol": 3,
    "IP Address": 3,
    "Too Many Dots": 1,
    "Suspicious Keyword": 2
}


def calculate_risk(result):

    score = 0
    reasons = []

    if not result["HTTPS"]:
        score += weights["HTTPS"]
        reasons.append("No HTTPS")

    if result["Long URL"]:
        score += weights["Long URL"]
        reasons.append("URL is too long")

    if result["@ Symbol"]:
        score += weights["@ Symbol"]
        reasons.append("@ symbol found")

    if result["IP Address"]:
        score += weights["IP Address"]
        reasons.append("IP address used instead of domain")

    if result["Too Many Dots"]:
        score += weights["Too Many Dots"]
        reasons.append("Too many dots in URL")

    if result["Suspicious Keyword"]:
        score += weights["Suspicious Keyword"]
        reasons.append("Suspicious keyword found")

    warning_count = len(reasons)

    if warning_count >= 4:
        score += 2
        reasons.append("Multiple suspicious signs")

    if result["IP Address"] and result["Suspicious Keyword"]:
        score += 2
        reasons.append("IP address combined with suspicious keyword")

    if not result["HTTPS"] and result["@ Symbol"]:
        score += 2
        reasons.append("HTTP combined with @ symbol")

    if score <= 2:
        level = "LOW"
    elif score <= 5:
        level = "MEDIUM"
    elif score <= 8:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return score, level, reasons
