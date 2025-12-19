def aggregate_by_ip(suspicious):
    data = {}

    for item in suspicious:
        ip = item["ip"]

        if ip not in data:
            data[ip] = {
                "total_score": 0,
                "count": 0,
                "attacks": {}
            }

        data[ip]["total_score"] += item["score"]
        data[ip]["count"] += 1

        attack = item["type"]
        data[ip]["attacks"][attack] = data[ip]["attacks"].get(attack, 0) + 1

    return data

def calculate_risk_level(score):
    if score >= 15:
        return "CRITICAL"
    elif score >= 8:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    return "LOW"
