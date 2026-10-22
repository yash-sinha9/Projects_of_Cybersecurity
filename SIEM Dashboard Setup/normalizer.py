import re
from datetime import datetime

# Simulated GeoIP lookup mapping for realistic SOC demonstration
GEOIP_MAP = {
    "185.220.101.5": "Russia",
    "194.26.29.112": "China",
    "45.154.255.87": "Iran",
    "103.235.46.10": "North Korea",
    "89.248.165.74": "Netherlands",
    "198.51.100.42": "United States",
    "192.0.2.14": "Germany",
    "193.56.28.18": "Ukraine",
    "91.240.118.23": "Romania",
    "203.0.113.88": "Brazil"
}

def resolve_country(ip):
    if not ip:
        return "Internal"
    if ip.startswith(("10.", "192.168.", "172.16.", "127.")):
        return "Internal/LAN"
    return GEOIP_MAP.get(ip, "External (Global)")

class LogNormalizer:
    @staticmethod
    def normalize(raw_log: str, source_hint: str = None) -> dict:
        raw = raw_log.strip()
        now_iso = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 1. Linux SSH / Auth.log formats
        # e.g.: "Oct 06 14:22:10 soc-svr sshd[2841]: Failed password for invalid user admin from 185.220.101.5 port 55123 ssh2"
        # e.g.: "Oct 06 14:22:10 soc-svr sshd[2841]: Accepted password for root from 192.168.1.15 port 55123 ssh2"
        if "sshd" in raw or "Failed password" in raw or "Accepted password" in raw or "Accepted publickey" in raw:
            return LogNormalizer._parse_linux_ssh(raw, now_iso)

        # 2. Linux Sudo / Privilege Escalation
        # e.g.: "Oct 06 14:25:01 soc-svr sudo: jsmith : TTY=pts/0 ; PWD=/home/jsmith ; USER=root ; COMMAND=/bin/bash"
        if "sudo:" in raw:
            return LogNormalizer._parse_linux_sudo(raw, now_iso)

        # 3. Windows Security Event Log
        # e.g.: "EventID=4625 Category=Logon Status=0xC000006D TargetUserName=Administrator Workstation=DESKTOP-19 SourceIP=194.26.29.112"
        # e.g.: "EventID=4624 Category=Logon Status=0x0 TargetUserName=Alice Workstation=WS-FINANCE SourceIP=10.0.0.45"
        if "EventID=" in raw or "EventId=" in raw:
            return LogNormalizer._parse_windows_event(raw, now_iso)

        # 4. Web Server Logs (Nginx / Apache Common / Combined Format with SQLi/XSS)
        # e.g.: '185.220.101.5 - - [06/Oct/2026:14:30:12] "GET /api/users?id=1 UNION SELECT null,password FROM users HTTP/1.1" 500 412'
        if re.search(r'"(GET|POST|PUT|DELETE|HEAD)\s', raw):
            return LogNormalizer._parse_web_log(raw, now_iso)

        # 5. Firewall / IPTables Logs
        # e.g.: "kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.154.255.87 DST=10.0.0.5 LEN=40 PROTO=TCP SPT=41221 DPT=3389"
        if "BLOCK" in raw or "DROP" in raw or "SRC=" in raw:
            return LogNormalizer._parse_firewall_log(raw, now_iso)

        # 6. Fallback generic log parsing
        return LogNormalizer._parse_generic(raw, now_iso, source_hint)

    @staticmethod
    def _parse_linux_ssh(raw: str, default_time: str) -> dict:
        is_failed = "Failed password" in raw or "authentication failure" in raw or "Invalid user" in raw
        is_success = "Accepted password" in raw or "Accepted publickey" in raw
        
        # Extract IP
        ip_match = re.search(r'from\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', raw)
        src_ip = ip_match.group(1) if ip_match else "127.0.0.1"

        # Extract user
        user_match = re.search(r'(?:for\s+(?:invalid\s+user\s+)?|user\s+)([a-zA-Z0-9_\-\.]+)', raw)
        username = user_match.group(1) if user_match else "unknown"

        event_type = "LOGIN_FAILED" if is_failed else ("LOGIN_SUCCESS" if is_success else "AUTH_ATTEMPT")
        status = "FAILED" if is_failed else ("SUCCESS" if is_success else "INFO")
        severity = "HIGH" if (is_failed and username in ['root', 'admin']) else ("MEDIUM" if is_failed else "INFO")

        return {
            "timestamp": default_time,
            "source_type": "SSH-Auth",
            "source_ip": src_ip,
            "destination_ip": "10.0.0.10",
            "username": username,
            "event_type": event_type,
            "status": status,
            "severity": severity,
            "raw_message": raw,
            "country": resolve_country(src_ip)
        }

    @staticmethod
    def _parse_linux_sudo(raw: str, default_time: str) -> dict:
        user_match = re.search(r'sudo:\s+([a-zA-Z0-9_\-]+)', raw)
        target_match = re.search(r'USER=([a-zA-Z0-9_\-]+)', raw)
        cmd_match = re.search(r'COMMAND=(.+)', raw)

        username = user_match.group(1) if user_match else "unknown"
        target = target_match.group(1) if target_match else "root"
        cmd = cmd_match.group(1) if cmd_match else "unknown"

        is_suspicious = any(x in cmd for x in ["/bin/bash", "/bin/sh", "chmod 777", "passwd", "shadow", "nmap"])

        return {
            "timestamp": default_time,
            "source_type": "Linux-Audit",
            "source_ip": "10.0.0.15",
            "destination_ip": "10.0.0.15",
            "username": username,
            "event_type": "PRIV_ESC" if is_suspicious else "PRIVILEGED_COMMAND",
            "status": "WARNING" if is_suspicious else "SUCCESS",
            "severity": "CRITICAL" if is_suspicious else "LOW",
            "raw_message": raw,
            "country": "Internal/LAN"
        }

    @staticmethod
    def _parse_windows_event(raw: str, default_time: str) -> dict:
        event_match = re.search(r'EventID=(\d+)', raw, re.IGNORECASE)
        event_id = event_match.group(1) if event_match else "0"

        user_match = re.search(r'TargetUserName=([^\s]+)', raw)
        username = user_match.group(1) if user_match else "Administrator"

        ip_match = re.search(r'SourceIP=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', raw)
        src_ip = ip_match.group(1) if ip_match else "10.0.0.22"

        if event_id == "4625":
            return {
                "timestamp": default_time,
                "source_type": "Windows-Security",
                "source_ip": src_ip,
                "destination_ip": "10.0.0.20",
                "username": username,
                "event_type": "LOGIN_FAILED",
                "status": "FAILED",
                "severity": "HIGH",
                "raw_message": raw,
                "country": resolve_country(src_ip)
            }
        elif event_id == "4624":
            return {
                "timestamp": default_time,
                "source_type": "Windows-Security",
                "source_ip": src_ip,
                "destination_ip": "10.0.0.20",
                "username": username,
                "event_type": "LOGIN_SUCCESS",
                "status": "SUCCESS",
                "severity": "INFO",
                "raw_message": raw,
                "country": resolve_country(src_ip)
            }
        else:
            return {
                "timestamp": default_time,
                "source_type": "Windows-Security",
                "source_ip": src_ip,
                "destination_ip": "10.0.0.20",
                "username": username,
                "event_type": f"WIN_EVENT_{event_id}",
                "status": "INFO",
                "severity": "LOW",
                "raw_message": raw,
                "country": resolve_country(src_ip)
            }

    @staticmethod
    def _parse_web_log(raw: str, default_time: str) -> dict:
        ip_match = re.search(r'^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', raw)
        src_ip = ip_match.group(1) if ip_match else "127.0.0.1"

        is_sqli = any(kw in raw.upper() for kw in ["UNION SELECT", "' OR '1'='1", "SLEEP(", "--", "BENCHMARK"])
        is_xss = any(kw in raw.lower() for kw in ["<script>", "alert(", "document.cookie", "onerror="])
        is_traversal = "../" in raw or "..%2F" in raw

        if is_sqli or is_xss or is_traversal:
            event_type = "WEB_ATTACK"
            severity = "HIGH"
            status = "BLOCKED"
        elif " 401 " in raw or " 403 " in raw:
            event_type = "ACCESS_DENIED"
            severity = "MEDIUM"
            status = "FAILED"
        elif " 500 " in raw:
            event_type = "SERVER_ERROR"
            severity = "MEDIUM"
            status = "FAILED"
        else:
            event_type = "HTTP_ACCESS"
            severity = "INFO"
            status = "SUCCESS"

        return {
            "timestamp": default_time,
            "source_type": "Web-Access",
            "source_ip": src_ip,
            "destination_ip": "10.0.0.80",
            "username": "www-data",
            "event_type": event_type,
            "status": status,
            "severity": severity,
            "raw_message": raw,
            "country": resolve_country(src_ip)
        }

    @staticmethod
    def _parse_firewall_log(raw: str, default_time: str) -> dict:
        src_match = re.search(r'SRC=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', raw)
        dst_match = re.search(r'DST=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', raw)
        dpt_match = re.search(r'DPT=(\d+)', raw)

        src_ip = src_match.group(1) if src_match else "198.51.100.1"
        dst_ip = dst_match.group(1) if dst_match else "10.0.0.1"
        dpt = dpt_match.group(1) if dpt_match else "0"

        return {
            "timestamp": default_time,
            "source_type": "Firewall",
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "username": "N/A",
            "event_type": "FIREWALL_DROP" if ("DROP" in raw or "BLOCK" in raw) else "PORT_SCAN",
            "status": "BLOCKED",
            "severity": "LOW" if dpt not in ["22", "3389", "445"] else "MEDIUM",
            "raw_message": raw,
            "country": resolve_country(src_ip)
        }

    @staticmethod
    def _parse_generic(raw: str, default_time: str, source_hint: str) -> dict:
        ip_match = re.search(r'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', raw)
        src_ip = ip_match.group(1) if ip_match else "127.0.0.1"

        return {
            "timestamp": default_time,
            "source_type": source_hint or "Syslog",
            "source_ip": src_ip,
            "destination_ip": "10.0.0.1",
            "username": "system",
            "event_type": "SYSTEM_EVENT",
            "status": "INFO",
            "severity": "INFO",
            "raw_message": raw,
            "country": resolve_country(src_ip)
        }
