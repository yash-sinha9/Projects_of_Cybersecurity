"""
Threat and Anomaly Detection Engine
Analyzes packets for suspicious ports, port scanning, flood attacks, and plaintext exposure.
"""
from collections import defaultdict
import time

# Known suspicious / Trojan / backdoor / unencrypted legacy ports
SUSPICIOUS_PORTS = {
    21: "FTP (Plaintext Credentials Risk)",
    23: "TELNET (Insecure Plaintext Remote Shell)",
    69: "TFTP (Trivial File Transfer - No Auth)",
    135: "RPC (Often targeted by MS03-026 / Blaster)",
    139: "NetBIOS (SMB Information Disclosure)",
    445: "SMB (Targeted by EternalBlue / WannaCry)",
    1433: "MSSQL (Database Exposure)",
    1521: "Oracle DB (Database Exposure)",
    3306: "MySQL (Public Database Exposure)",
    3389: "RDP (Remote Desktop - Brute Force / BlueKeep Target)",
    4444: "Metasploit Default Listener / Reverse Shell",
    5555: "Freeciv / ADB Remote Debugging Exposure",
    6667: "IRC (Common C2 Botnet Communication)",
    8080: "HTTP Alternate / Proxy",
    31337: "Back Orifice Trojan / Elite Port",
}

class AnomalyDetector:
    def __init__(self, scan_threshold=15, time_window=5.0):
        # Scan threshold: distinct destination ports per source IP in window
        self.scan_threshold = scan_threshold
        self.time_window = time_window
        
        # Tracking states
        self.port_scan_tracker = defaultdict(lambda: {"ports": set(), "first_seen": time.time()})
        self.syn_flood_tracker = defaultdict(lambda: {"count": 0, "first_seen": time.time()})
        self.alerts = []

    def log_alert(self, level, category, description, src_ip, dst_ip, details=None):
        alert = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "level": level,  # INFO, LOW, MEDIUM, HIGH, CRITICAL
            "category": category,
            "description": description,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "details": details or {}
        }
        self.alerts.append(alert)
        return alert

    def inspect_packet(self, packet_info):
        """
        Inspect parsed packet info dictionary.
        Returns list of newly generated alerts for this packet.
        """
        new_alerts = []
        src = packet_info.get("src_ip", "")
        dst = packet_info.get("dst_ip", "")
        proto = packet_info.get("protocol", "")
        dst_port = packet_info.get("dst_port")
        src_port = packet_info.get("src_port")
        flags = packet_info.get("tcp_flags", "")
        now = time.time()

        # 1. Suspicious Port Detection
        for port in [dst_port, src_port]:
            if port in SUSPICIOUS_PORTS:
                severity = "HIGH" if port in [4444, 31337, 6667] else "MEDIUM"
                alert = self.log_alert(
                    level=severity,
                    category="Suspicious Port Activity",
                    description=f"Traffic observed on port {port}: {SUSPICIOUS_PORTS[port]}",
                    src_ip=src,
                    dst_ip=dst,
                    details={"port": port, "service_name": SUSPICIOUS_PORTS[port]}
                )
                new_alerts.append(alert)

        # 2. Port Scan Detection (Reconnaissance)
        if proto == "TCP" and dst_port:
            tracker = self.port_scan_tracker[src]
            if now - tracker["first_seen"] > self.time_window:
                tracker["ports"] = set()
                tracker["first_seen"] = now
            
            tracker["ports"].add(dst_port)
            if len(tracker["ports"]) >= self.scan_threshold:
                alert = self.log_alert(
                    level="HIGH",
                    category="Port Scanning Detected",
                    description=f"Host {src} connected to {len(tracker['ports'])} unique ports within {self.time_window}s (Reconnaissance)",
                    src_ip=src,
                    dst_ip=dst,
                    details={"probed_ports": list(tracker["ports"])[:10]}
                )
                new_alerts.append(alert)
                # Reset to avoid flooding alerts
                tracker["ports"] = set()

        # 3. SYN Flood / DoS Indicator
        if proto == "TCP" and "S" in flags and "A" not in flags:
            flood_tracker = self.syn_flood_tracker[src]
            if now - flood_tracker["first_seen"] > 2.0:
                flood_tracker["count"] = 0
                flood_tracker["first_seen"] = now
            flood_tracker["count"] += 1
            if flood_tracker["count"] > 30:  # >30 SYN packets in 2 sec
                alert = self.log_alert(
                    level="CRITICAL",
                    category="Potential SYN Flood Attack",
                    description=f"Abnormal burst of TCP SYN packets ({flood_tracker['count']} in 2s) from {src}",
                    src_ip=src,
                    dst_ip=dst,
                    details={"syn_rate_per_sec": flood_tracker["count"] / 2.0}
                )
                new_alerts.append(alert)
                flood_tracker["count"] = 0

        # 4. Cleartext Protocol & Plaintext Keyword Sniffing
        payload = packet_info.get("payload_summary", "")
        sensitive_keywords = ["USER ", "PASS ", "password=", "admin=", "Bearer "]
        for kw in sensitive_keywords:
            if kw.lower() in payload.lower():
                alert = self.log_alert(
                    level="CRITICAL",
                    category="Cleartext Sensitive Data Leak",
                    description=f"Potential unencrypted credentials or authorization token detected in payload",
                    src_ip=src,
                    dst_ip=dst,
                    details={"matched_token": kw.strip(), "sample_payload": payload[:80]}
                )
                new_alerts.append(alert)

        # 5. DNS Tunneling Heuristics (Unusually long queries)
        dns_query = packet_info.get("dns_query")
        if dns_query and len(dns_query) > 55:
            alert = self.log_alert(
                level="HIGH",
                category="Suspicious DNS Tunneling / Exfiltration",
                description=f"Abnormally long DNS query domain detected ({len(dns_query)} chars): {dns_query}",
                src_ip=src,
                dst_ip=dst,
                details={"query": dns_query, "length": len(dns_query)}
            )
            new_alerts.append(alert)

        return new_alerts
