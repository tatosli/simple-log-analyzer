"""
Enhanced security threat detector with expanded attack detection
"""
import re
from datetime import datetime, timedelta

# ========== REGEX PATTERNS ==========

# SSH Brute Force
SSH_FAILED_REGEX = re.compile(
    r'Failed password .* from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)

SSH_TIME_REGEX = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)'
)

# Web Log IP extraction
WEB_LOG_REGEX = re.compile(
    r'^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+-'
)

# SQL Injection
SQL_INJECTION_REGEX = re.compile(
    r'(UNION\s+SELECT|SELECT.*FROM|DROP\s+TABLE|INSERT\s+INTO|UPDATE.*SET|DELETE\s+FROM|'
    r'OR\s+1\s*=\s*1|\'.*OR.*\'|--\s|;--|\'\s+OR|\)\s+OR|EXEC\s*\(|EXECUTE\s*\()',
    re.IGNORECASE
)

# XSS (Cross-Site Scripting)
XSS_REGEX = re.compile(
    r'<script|javascript:|onerror=|onload=|alert\(|prompt\(|confirm\(|'
    r'<iframe|<embed|<object|eval\(|document\.cookie|document\.write',
    re.IGNORECASE
)

# Path Traversal
PATH_TRAVERSAL_REGEX = re.compile(
    r'\.\.\/|\.\.\\|\/etc\/passwd|\/etc\/shadow|\.\.%2F|\.\.%5C|'
    r'%2e%2e%2f|%2e%2e\/|\.\.%252F',
    re.IGNORECASE
)

# Command Injection (NEW - Tier 1)
COMMAND_INJECTION_REGEX = re.compile(
    r'(;|\||&|&&|\|\||`|\$\(|\$\{)\s*(ls|cat|wget|curl|nc|netcat|bash|sh|'
    r'python|perl|ruby|php|cmd|powershell|whoami|id|uname|hostname|ifconfig|'
    r'ping|nslookup|dig|chmod|chown|rm|mv|cp|kill|pkill)',
    re.IGNORECASE
)

# XXE (XML External Entity) (NEW - Tier 1)
XXE_REGEX = re.compile(
    r'<!ENTITY|<!DOCTYPE|SYSTEM\s+["\']|PUBLIC\s+["\']|'
    r'<\?xml|xmlns:|file://|php://|data://|expect://',
    re.IGNORECASE
)

# LDAP Injection (NEW - Tier 1)
LDAP_INJECTION_REGEX = re.compile(
    r'\*\)|\(\*|\)\(|\(\||&\(|\|\(|,\s*cn=|,\s*ou=|,\s*dc=|'
    r'\*\)\(\||null\)|\(\&\(',
    re.IGNORECASE
)

# File Upload Attacks (NEW - Tier 1)
MALICIOUS_UPLOAD_REGEX = re.compile(
    r'\.php\d?[\?%]|\.aspx?[\?%]|\.jsp[\?%]|\.jspx[\?%]|'
    r'\.py[\?%]|\.sh[\?%]|\.exe[\?%]|\.bat[\?%]|\.cmd[\?%]|'
    r'\.pl[\?%]|\.cgi[\?%]|\.war[\?%]|\.jar[\?%]|'
    r'%00\.|\x00\.|\.php%00|\.asp%00|null\.php|shell\.php',
    re.IGNORECASE
)

# Directory Listing (NEW - Tier 1)
DIRECTORY_LISTING_REGEX = re.compile(
    r'Index\s+of\s+/|Directory\s+listing\s+for|'
    r'\[To\s+Parent\s+Directory\]|<title>Index of',
    re.IGNORECASE
)

# Suspicious User-Agent (Scanners/Bots)
SUSPICIOUS_AGENT_REGEX = re.compile(
    r'(sqlmap|nikto|nmap|masscan|acunetix|nessus|burp|w3af|metasploit|'
    r'dirbuster|wpscan|skipfish|arachni|vega|grabber|webscarab)',
    re.IGNORECASE
)

# HTTP Status codes
STATUS_401_REGEX = re.compile(r'\s401\s')
STATUS_403_REGEX = re.compile(r'\s403\s')
STATUS_500_REGEX = re.compile(r'\s500\s')

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}


# ========== HELPER FUNCTIONS ==========

def parse_ssh_time(line):
    """Parse SSH log timestamp"""
    match = SSH_TIME_REGEX.search(line)
    if not match:
        return None

    now = datetime.now()
    month = MONTHS.get(match.group("month"), now.month)
    day = int(match.group("day"))
    time_part = match.group("time")

    dt_str = f"{now.year}-{month:02d}-{day:02d} {time_part}"
    return datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")


def extract_web_ip(line):
    """Extract IP address from web log"""
    match = WEB_LOG_REGEX.search(line)
    if match:
        return match.group("ip")
    return None


# ========== MAIN DETECTION FUNCTION ==========

def detect_suspicious(lines, ssh_threshold=3, ssh_window=60):
    """
    Detect suspicious activities in log lines
    
    Args:
        lines: List of log lines to analyze
        ssh_threshold: Number of failed SSH attempts to trigger alert
        ssh_window: Time window in seconds for SSH brute force detection
    
    Returns:
        List of suspicious events with details
    """
    suspicious = []
    ssh_attempts = {}
    login_attempts = {}

    for line in lines:
        line = line.strip()
        
        # 1. SSH Brute Force Detection
        ssh_match = SSH_FAILED_REGEX.search(line)
        if ssh_match:
            ip = ssh_match.group("ip")
            ts = parse_ssh_time(line)
            if ts:
                ssh_attempts.setdefault(ip, []).append(ts)
            continue

        # Extract IP from web logs
        ip = extract_web_ip(line)
        if not ip:
            continue

        # 2. SQL Injection Detection
        if SQL_INJECTION_REGEX.search(line):
            suspicious.append({
                "type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "ip": ip,
                "score": 100,
                "line": line
            })
            continue

        # 3. Command Injection Detection (NEW)
        if COMMAND_INJECTION_REGEX.search(line):
            suspicious.append({
                "type": "COMMAND_INJECTION",
                "severity": "CRITICAL",
                "ip": ip,
                "score": 100,
                "line": line
            })
            continue

        # 4. XXE Detection (NEW)
        if XXE_REGEX.search(line):
            suspicious.append({
                "type": "XXE",
                "severity": "CRITICAL",
                "ip": ip,
                "score": 95,
                "line": line
            })
            continue

        # 5. XSS Detection
        if XSS_REGEX.search(line):
            suspicious.append({
                "type": "XSS",
                "severity": "HIGH",
                "ip": ip,
                "score": 80,
                "line": line
            })
            continue

        # 6. Path Traversal Detection
        if PATH_TRAVERSAL_REGEX.search(line):
            suspicious.append({
                "type": "PATH_TRAVERSAL",
                "severity": "HIGH",
                "ip": ip,
                "score": 90,
                "line": line
            })
            continue

        # 7. LDAP Injection Detection (NEW)
        if LDAP_INJECTION_REGEX.search(line):
            suspicious.append({
                "type": "LDAP_INJECTION",
                "severity": "HIGH",
                "ip": ip,
                "score": 85,
                "line": line
            })
            continue

        # 8. File Upload Attack Detection (NEW)
        if MALICIOUS_UPLOAD_REGEX.search(line):
            suspicious.append({
                "type": "MALICIOUS_UPLOAD",
                "severity": "HIGH",
                "ip": ip,
                "score": 85,
                "line": line
            })
            continue

        # 9. Directory Listing Detection (NEW)
        if DIRECTORY_LISTING_REGEX.search(line):
            suspicious.append({
                "type": "DIRECTORY_LISTING",
                "severity": "MEDIUM",
                "ip": ip,
                "score": 60,
                "line": line
            })
            continue

        # 10. Suspicious User-Agent Detection
        if SUSPICIOUS_AGENT_REGEX.search(line):
            suspicious.append({
                "type": "SUSPICIOUS_AGENT",
                "severity": "MEDIUM",
                "ip": ip,
                "score": 70,
                "line": line
            })
            continue

        # 11. Failed Login Attempts (401)
        if STATUS_401_REGEX.search(line):
            login_attempts.setdefault(ip, []).append(line)

    # Process SSH Brute Force
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
                    "score": count * 20,
                    "line": f"{count} failed SSH logins within {ssh_window}s"
                })
                break

    # Process Web Login Brute Force
    for ip, attempts in login_attempts.items():
        if len(attempts) >= 3:
            suspicious.append({
                "type": "WEB_BRUTE_FORCE",
                "severity": "MEDIUM",
                "ip": ip,
                "score": len(attempts) * 15,
                "line": f"{len(attempts)} failed login attempts"
            })

    return suspicious