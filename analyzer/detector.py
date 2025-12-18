import re

IP_REGEX = re.compile(r"(\d{1,3}\.){3}\d{1,3}")

PATTERNS = [
    {
        "type": "SQL_INJECTION",
        "severity": "HIGH",
        "regex": re.compile(r"(union\s+select|or\s+1=1|--)", re.IGNORECASE)
    },
    {
        "type": "PATH_TRAVERSAL",
        "severity": "HIGH",
        "regex": re.compile(r"(\.\./|\.\.\\)+")
    },
    {
        "type": "BRUTE_FORCE",
        "severity": "MEDIUM",
        "regex": re.compile(r"(failed|unauthorized|invalid password)", re.IGNORECASE)
    }
]

def extract_ip(line):
    match = IP_REGEX.search(line)
    return match.group(0) if match else "N/A"

def detect_suspicious(lines):
    results = []

    for line in lines:
        for pattern in PATTERNS:
            if pattern["regex"].search(line):
                results.append({
                    "type": pattern["type"],
                    "severity": pattern["severity"],
                    "ip": extract_ip(line),
                    "line": line.strip()
                })
                break

    return results
