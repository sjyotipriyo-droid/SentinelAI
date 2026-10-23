import re
import json
import requests
from collections import defaultdict

# 1. Regex rules for parsing Apache/Nginx log format
LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>.*?)\] "(?P<method>\w+) (?P<url>.*?) HTTP/.*?" (?P<status>\d+) (?P<size>\d+)'
)

# 2. Threat Signatures mapped with MITRE ATT&CK IDs
THREAT_RULES = {
    "SQL Injection (SQLi)": {
        "pattern": re.compile(r"(\bUNION\b|\bSELECT\b|\bOR\b.*=.*|--|')", re.IGNORECASE),
        "mitre_id": "T1190 (Exploit Public-Facing Application)"
    },
    "Directory Traversal (LFI)": {
        "pattern": re.compile(r"(\.\./|\.\.\\|/etc/passwd|/windows/win\.ini)", re.IGNORECASE),
        "mitre_id": "T1083 (File and Directory Discovery)"
    },
    "Cross-Site Scripting (XSS)": {
        "pattern": re.compile(r"(<script>|javascript:|onerror=|onload=)", re.IGNORECASE),
        "mitre_id": "T1059.007 (Command and Scripting Interpreter: JavaScript)"
    },
}

# Cache for IP OSINT so we don't query the same IP twice
ip_osint_cache = {}

def get_ip_osint(ip):
    if ip in ip_osint_cache:
        return ip_osint_cache[ip]
    
    # Ignore local/private IPs
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127."):
        osint_data = {"country": "Internal LAN", "isp": "Local Network", "asn": "N/A"}
        ip_osint_cache[ip] = osint_data
        return osint_data

    try:
        res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,as", timeout=3)
        data = res.json()
        if data.get("status") == "success":
            osint_data = {
                "country": f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}",
                "isp": data.get("isp", "Unknown ISP"),
                "asn": data.get("as", "Unknown ASN")
            }
        else:
            osint_data = {"country": "Unknown", "isp": "Unknown", "asn": "Unknown"}
    except Exception:
        osint_data = {"country": "Lookup Failed", "isp": "Unknown", "asn": "Unknown"}

    ip_osint_cache[ip] = osint_data
    return osint_data

def analyze_logs(log_file_path):
    incidents = []
    failed_logins = defaultdict(int)

    with open(log_file_path, "r") as file:
        for line_num, line in enumerate(file, 1):
            match = LOG_PATTERN.search(line)
            if not match:
                continue

            data = match.groupdict()
            ip = data["ip"]
            url = data["url"]
            status = data["status"]
            timestamp = data["timestamp"]

            # Check for Signature-based Attacks
            for threat_name, rule in THREAT_RULES.items():
                if rule["pattern"].search(url):
                    osint = get_ip_osint(ip)
                    incidents.append({
                        "line": line_num,
                        "timestamp": timestamp,
                        "ip": ip,
                        "osint": osint,
                        "threat_type": threat_name,
                        "mitre_attack": rule["mitre_id"],
                        "payload": url,
                        "status_code": status,
                        "severity": "CRITICAL" if status == "200" else "MEDIUM"
                    })

            # Track Failed Logins for Brute-Force Detection
            if "login" in url.lower() and status in ["401", "403"]:
                failed_logins[ip] += 1

    # Check Brute-Force threshold
    for ip, count in failed_logins.items():
        if count >= 4:
            osint = get_ip_osint(ip)
            incidents.append({
                "line": "Multiple",
                "timestamp": "Recent Window",
                "ip": ip,
                "osint": osint,
                "threat_type": "Brute-Force Attack",
                "mitre_attack": "T1110 (Brute Force / Credential Stuffing)",
                "payload": f"{count} failed login attempts detected",
                "status_code": "401",
                "severity": "HIGH"
            })

    return incidents

if __name__ == "__main__":
    print("[*] Starting SentinelAI OSINT & Threat Hunter...\n")
    detected_incidents = analyze_logs("access.log")
    print(json.dumps(detected_incidents, indent=4))