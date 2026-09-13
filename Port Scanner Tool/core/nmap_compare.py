"""
Nmap Comparison & Benchmark Analysis Module
Demonstrates why industry & recruiters value custom port scanners over just running Nmap.
Provides in-depth architectural comparisons and performance metrics.
"""

from typing import Dict, Any, List


COMPARISON_MATRIX = [
    {
        "criterion": "Scanning Technique",
        "custom_scanner": "Full TCP 3-Way Handshake (SYN -> SYN-ACK -> ACK)",
        "nmap_default": "TCP SYN Stealth Scan (-sS, Half-Open)",
        "industry_takeaway": "Builds fundamental mastery of TCP state machines and socket APIs."
    },
    {
        "criterion": "Privilege Level",
        "custom_scanner": "Userland (No Admin / Root required)",
        "nmap_default": "Administrator / Root required (for raw sockets / pcap)",
        "industry_takeaway": "Runs safely in restricted enterprise environments and sandboxes."
    },
    {
        "criterion": "Socket Mechanics",
        "custom_scanner": "OS BSD Socket API (socket.connect_ex)",
        "nmap_default": "Raw Ethernet/IP/TCP frame construction via libpcap/Npcap",
        "industry_takeaway": "Understands OS network stack abstraction vs hardware layer packets."
    },
    {
        "criterion": "Logging & Evasion",
        "custom_scanner": "Logged by target application (connection completed)",
        "nmap_default": "Often bypassed application-layer logs (connection aborted)",
        "industry_takeaway": "Understands IDS/IPS detection vectors and SIEM alert generation."
    },
    {
        "criterion": "Port State Logic",
        "custom_scanner": "0 = Open, ECONNREFUSED = Closed, ETIMEDOUT = Filtered",
        "nmap_default": "SYN/ACK = Open, RST = Closed, ICMP unreachable / No reply = Filtered",
        "industry_takeaway": "Shows exact translation of kernel error codes to network states."
    },
    {
        "criterion": "Concurrency Model",
        "custom_scanner": "Multi-threading (ThreadPoolExecutor / non-blocking I/O)",
        "nmap_default": "Ultra-optimized C++ event-loop and parallel packet dispatch",
        "industry_takeaway": "Demonstrates concurrent programming, thread pooling, and resource safety."
    },
    {
        "criterion": "Service Fingerprinting",
        "custom_scanner": "Custom Application probes & banner extraction (HTTP, SSH, FTP)",
        "nmap_default": "Extensive regex database (nmap-service-probes, 10,000+ signatures)",
        "industry_takeaway": "Shows protocol-level comprehension of application handshakes."
    }
]


def get_nmap_comparison_report(scan_summary: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generates a technical comparison report comparing the scan run
    against professional tools like Nmap.
    """
    target = scan_summary.get("target", "localhost")
    ports_scanned = scan_summary.get("total_ports_scanned", 0)
    duration = scan_summary.get("scan_duration_sec", 0.0)
    ports_per_sec = scan_summary.get("ports_per_sec", 0)
    open_ports = scan_summary.get("open_ports_count", 0)
    
    # Estimate equivalent Nmap performance (T4 template)
    nmap_estimated_duration = round(max(ports_scanned / 2500.0, 0.15), 2)
    
    return {
        "title": "Custom Port Scanner vs Nmap Benchmark & Analysis",
        "target": target,
        "metrics": {
            "custom_scanner": {
                "scan_type": "TCP Connect Scan (Full Handshake)",
                "ports_scanned": ports_scanned,
                "open_detected": open_ports,
                "duration_seconds": duration,
                "throughput_ports_per_sec": ports_per_sec,
                "admin_rights_needed": False,
                "packet_capture_driver": "None (Standard Python Standard Library)"
            },
            "nmap_equivalent": {
                "scan_type": "SYN Stealth Scan (-sS)",
                "ports_scanned": ports_scanned,
                "open_detected": open_ports,
                "estimated_duration_seconds": nmap_estimated_duration,
                "throughput_ports_per_sec": 2500,
                "admin_rights_needed": True,
                "packet_capture_driver": "Npcap / WinPcap required"
            }
        },
        "comparison_matrix": COMPARISON_MATRIX,
        "recruiter_key_points": [
            "1. Deep comprehension of TCP 3-way handshake and RFC 793 network specifications.",
            "2. Practical understanding of OS socket error codes (WSAECONNREFUSED, WSAETIMEDOUT).",
            "3. Ability to construct multi-threaded client-server tools from scratch without relying on black-box utilities.",
            "4. Protocol analysis skills demonstrated through custom banner grabbing and service detection."
        ]
    }
