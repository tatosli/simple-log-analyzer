import os


def write_blacklist(suspicious, min_score, filename="blacklist.txt"):
    existing_ips = set()

    if os.path.exists(filename):
        with open(filename, "r") as f:
            existing_ips = {line.strip() for line in f}

    new_ips = []

    for item in suspicious:
        ip = item.get("ip")
        score = item.get("score", 0)

        if score >= min_score and ip not in existing_ips:
            new_ips.append(ip)

    if not new_ips:
        return []

    with open(filename, "a") as f:
        for ip in new_ips:
            f.write(ip + "\n")

    return new_ips
