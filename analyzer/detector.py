import re

PATTERNS = {
    "SQL_INJECTION": {
        "pattern": re.compile(r"(union\s+select|or\s+1=1|--)", re.IGNORECASE),
        "severity": "HIGH"
    },
    "PATH_TRAVERSAL": {
        "pattern": re.compile(r"(\.\./|\.\.\\)+"),
        "severity": "HIGH"
    },
    "BRUTE_FORCE": {
        "pattern": re.compile(r"(failed|unauthorized|invalid password)", re.IGNORECASE),
        "severity": "MEDIUM"
    }
}

IP_REGEX = re.compile(r"(\d{1,3}\.){3}\d{1,3}")

def detect_suspicious(lines):
    results = []

    for line in lines:
        matched_types = []

        for attack_type, data in PATTERNS.items():
            if data["pattern"].search(line):
                matched_types.append({
                    "type": attack_type,
                    "severity": data["severity"]
                })

        if matched_types:
            ip_match = IP_REGEX.search(line)
            ip = ip_match.group() if ip_match else "N/A"

            results.append({
                "line": line.strip(),
                "ip": ip,
                "matches": matched_types
            })

    return results
