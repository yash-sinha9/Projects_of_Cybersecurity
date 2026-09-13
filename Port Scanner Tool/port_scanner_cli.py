"""
Custom Port Scanner - High Performance CLI Interface
Demonstrates Python socket programming, TCP/UDP scanning, banner grabbing,
and comparative network analysis against Nmap.
"""

import os
import sys
import time
import json
import argparse
from typing import List

# Ensure core package can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.scanner import PortScanner, ScanResult
from core.service_db import PORT_SETS
from core.nmap_compare import get_nmap_comparison_report

# ANSI Color Codes for high-impact terminal styling
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"
DIM = "\033[2m"


def parse_ports(port_arg: str) -> List[int]:
    """Parses port string such as '80', '20-100', '22,80,443', 'quick', or 'top50'."""
    arg = port_arg.strip().lower()
    if arg in PORT_SETS:
        return PORT_SETS[arg]
    
    ports = set()
    parts = arg.split(",")
    for part in parts:
        part = part.strip()
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start, end = int(start_str.strip()), int(end_str.strip())
            for p in range(max(1, start), min(65535, end) + 1):
                ports.add(p)
        elif part.isdigit():
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(list(ports))


def print_banner():
    banner = f"""
{CYAN}{BOLD}======================================================================
  ____             _     ____                                  
 |  _ \\ ___  _ __ | |_  / ___|  ___ __ _ _ __  _ __   ___ _ __ 
 | |_) / _ \\| '__|| __| \\___ \\ / __/ _` | '_ \\| '_ \\ / _ \\ '__|
 |  __/ (_) | |   | |_   ___) | (_| (_| | | | | | | |  __/ |   
 |_|   \\___/|_|    \\__| |____/ \\___\\__,_|_| |_|_| |_|\\___|_|   
                                                               
  Network Security & Socket Programming Portfolio Project
  Author: Built from scratch | TCP/UDP | Banner Grabbing | Nmap Benchmark
======================================================================{RESET}
"""
    print(banner)


def run_cli():
    # Enable ANSI escape sequences on Windows consoles
    if sys.platform == "win32":
        os.system("color")

    parser = argparse.ArgumentParser(
        description="Custom Multi-threaded Network Port Scanner & Service Fingerprinter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python port_scanner_cli.py -t 127.0.0.1 -p 80,443,8080,3000
  python port_scanner_cli.py -t scanme.nmap.org -p quick --threads 100
  python port_scanner_cli.py -t 192.168.1.1 -p 1-1024 -sT -sV
  python port_scanner_cli.py -t 127.0.0.1 -p top50 --compare-nmap -o results.json
        """
    )
    parser.add_argument("-t", "--target", default="127.0.0.1", help="Target IP address or domain (default: 127.0.0.1)")
    parser.add_argument("-p", "--ports", default="quick", help="Ports to scan: 'quick', 'top50', 'well_known', '80,443', or '1-1024' (default: quick)")
    parser.add_argument("-sT", "--tcp", action="store_true", default=True, help="Perform TCP Connect 3-way Handshake scan (default: True)")
    parser.add_argument("-sU", "--udp", action="store_true", default=False, help="Perform UDP Datagram Probe scan")
    parser.add_argument("-sV", "--banners", action="store_true", default=True, help="Enable Application Banner Grabbing & Service Detection")
    parser.add_argument("--threads", type=int, default=75, help="Number of concurrent worker threads (default: 75)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("-o", "--output", help="Save scan results to JSON file")
    parser.add_argument("--compare-nmap", action="store_true", help="Display architectural benchmark comparison vs Nmap")

    args = parser.parse_args()
    print_banner()

    ports = parse_ports(args.ports)
    if not ports:
        print(f"{RED}[-] Error: No valid ports specified.{RESET}")
        return

    scan_type = "UDP" if args.udp else "TCP"

    print(f"{BOLD}[*] Initializing Scanner Engine...{RESET}")
    print(f"    Target     : {CYAN}{args.target}{RESET}")
    print(f"    Scan Type  : {YELLOW}{scan_type} Connect Handshake{RESET}")
    print(f"    Port Range : {len(ports)} ports selected")
    print(f"    Threads    : {args.threads} workers | Timeout: {args.timeout}s")
    print(f"    Banners    : {'Enabled (-sV)' if args.banners else 'Disabled'}")
    print("-" * 70)

    scanner = PortScanner(
        target=args.target,
        ports=ports,
        timeout=args.timeout,
        threads=args.threads,
        grab_banners=args.banners,
        scan_type=scan_type
    )

    resolved, msg = scanner.resolve_target()
    if not resolved:
        print(f"{RED}[!] Host Resolution Failure: {msg}{RESET}")
        return
    print(f"{GREEN}[+] {msg}{RESET}")
    print(f"{CYAN}[*] Scanning in progress... Please wait.{RESET}\n")

    # Progress tracking
    open_count = 0
    closed_count = 0
    filtered_count = 0

    def on_progress(completed: int, total: int, res: ScanResult):
        nonlocal open_count, closed_count, filtered_count
        if res.state in ("OPEN", "OPEN|FILTERED"):
            open_count += 1
            print(f"    {GREEN}[OPEN]{RESET} Port {res.port:<5}/{res.proto} -> {res.service:<12} ({res.latency_ms} ms)")
        elif res.state == "CLOSED":
            closed_count += 1
        elif res.state == "FILTERED":
            filtered_count += 1

    t0 = time.time()
    results = scanner.run_scan(progress_callback=on_progress)
    duration = time.time() - t0

    summary = scanner.get_summary()

    # Pretty print summary table
    print("\n" + "=" * 70)
    print(f"{BOLD}SCAN RESULTS SUMMARY FOR {CYAN}{scanner.target_ip}{RESET} ({scanner.hostname})")
    print("=" * 70)
    print(f"{'PORT':<8} {'STATE':<10} {'SERVICE':<14} {'LATENCY':<10} {'RISK':<8} {'BANNER / DETAILS'}")
    print("-" * 70)

    open_results = [r for r in results if r.state in ("OPEN", "OPEN|FILTERED")]
    if open_results:
        for r in open_results:
            state_colored = f"{GREEN}{r.state:<10}{RESET}"
            risk_colored = (f"{RED}{r.risk:<8}{RESET}" if r.risk == "High" or r.risk == "Critical"
                            else f"{YELLOW}{r.risk:<8}{RESET}" if r.risk == "Medium"
                            else f"{DIM}{r.risk:<8}{RESET}")
            banner_display = (r.banner[:35] + "...") if len(r.banner) > 35 else (r.banner or r.description)
            print(f"{r.port:<8} {state_colored} {r.service:<14} {r.latency_ms:<10.2f} {risk_colored} {banner_display}")
    else:
        print(f"{YELLOW}[i] No open ports discovered in the selected range.{RESET}")

    print("-" * 70)
    print(f"Scanned: {len(results)} ports | {GREEN}Open: {open_count}{RESET} | {RED}Closed: {closed_count}{RESET} | {YELLOW}Filtered: {filtered_count}{RESET}")
    print(f"Total Duration: {duration:.2f} seconds | Average Throughput: {summary['ports_per_sec']} ports/sec")
    print("=" * 70)

    # Output file export
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        print(f"{GREEN}[+] Complete scan report saved to: {args.output}{RESET}")

    # Nmap Comparison Analysis
    if args.compare_nmap:
        print("\n" + "=" * 70)
        print(f"{MAGENTA}{BOLD}INDUSTRY & RECRUITER COMPARISON: CUSTOM SCANNER VS NMAP{RESET}")
        print("=" * 70)
        report = get_nmap_comparison_report(summary)
        for item in report["comparison_matrix"]:
            print(f"\n{BOLD}{CYAN}Criterion:{RESET} {item['criterion']}")
            print(f"  * Custom Scanner: {item['custom_scanner']}")
            print(f"  * Nmap Default  : {item['nmap_default']}")
            print(f"  * {YELLOW}Interview Key : {item['industry_takeaway']}{RESET}")
        
        print("\n" + "-" * 70)
        print(f"{BOLD}WHY RECRUITERS VALUE THIS PROJECT:{RESET}")
        for pt in report["recruiter_key_points"]:
            print(f"  {pt}")
        print("=" * 70)


if __name__ == "__main__":
    run_cli()
