import re
from datetime import datetime, timedelta

SSH_FAILED_REGEX = re.compile(
    r'Failed password .* from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)

SSH_TIME_REGEX = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)'
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

def parse_ssh_time(line):
    match = SSH_TIME_REGEX.search(line)
    if not match:
        return None

    now = datetime.now()
    month = MONTHS.get(match.group("month"), now.month)
    day = int(match.group("day"))
    time_part = match.group("time")

    dt_str = f"{now.year}-{month:02d}-{day:02d} {time_part}"
    return datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")


def detect_suspicious(lines, ssh_threshold=5, ssh_window=60):
    suspicious = []
    ssh_attempts = {}

    for line in lines:
        ssh_match = SSH_FAILED_REGEX.search(line)
        if ssh_match:
            ip = ssh_match.group("ip")
            ts = parse_ssh_time(line)
            if not ts:
                continue

            ssh_attempts.setdefault(ip, []).append(ts)

    # threshold kontrolü
    for ip, times in ssh_attempts.items():
        times.sort()
        for i in range(len(times)):
            window_start = times[i]
            window_end = window_start + timedelta(seconds=ssh_window)

            count = sum(1 for t in times if window_start <= t <= window_end)
            if count >= ssh_threshold:
                suspicious.append({
                    "type": "SSH_BRUTE_FORCE",
                    "severity": "HIGH",
                    "ip": ip,   
                    "score": count * 10,  # risk skoru
                    "line": f"{count} failed SSH logins within {ssh_window}s"
                })

                break

    return suspicious
