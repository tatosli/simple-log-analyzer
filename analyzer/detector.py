SUSPICIOUS_KEYWORDS = [
    "error",
    "unauthorized",
    "failed",
    "suspicious"
]

def detect_suspicious(lines):
    suspicious = []

    for line in lines:
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword.lower() in line.lower():
                suspicious.append(line)
                break

    return suspicious
