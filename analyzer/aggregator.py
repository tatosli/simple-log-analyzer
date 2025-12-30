def score_events(suspicious):
    """Her event'e risk skoru ekle"""
    for event in suspicious:
        # Event türüne göre skor ata
        event_type = event.get("type", "").lower()
        
        if "sql" in event_type or "command" in event_type:
            event["score"] = 10
        elif "xxe" in event_type:
            event["score"] = 9
        elif "path_traversal" in event_type or "ldap" in event_type or "upload" in event_type:
            event["score"] = 9
        elif "xss" in event_type:
            event["score"] = 8
        elif "brute_force" in event_type or "ssh" in event_type:
            event["score"] = 7
        elif "agent" in event_type or "directory" in event_type:
            event["score"] = 6
        else:
            event["score"] = 5
    
    return suspicious


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