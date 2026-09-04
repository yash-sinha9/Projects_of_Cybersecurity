"""
Network Traffic Analyzer - Main CLI Interface
Demonstrates live packet capture, protocol dissection, suspicious port analysis, and reporting.
"""
import argparse
import sys
import os
from analyzer import NetworkAnalyzer
from reporter import generate_json_report, generate_html_report

BANNER = r"""
================================================================================
   _  __     __                      __      __                  ______           ________         
  / |/ /__  / /__    _____  _______ / /__   / /________ _       / __/ /____ _____/_  __/ /  _____   
 /    / -_)/ __/ |/|/ / _ \/ __/ // /  '_/  / __/ __/ _ `/ _   / _// __/ _ `/ __/ / / / _ \/ _ \   
/_/|_/\__/ \__/|__,__/\___/_/  \_,_/_/\_\   \__/_/  \_,_/ (_) /___/\__/\_,_/_/   /_/ /_//_/\___/   
                                                                                                   
         SOC & Network Security Engineering Project | Anomaly & Threat Detection
================================================================================
"""

def print_summary_table(stats, alerts):
    print("\n" + "=" * 75)
    print("                      CAPTURE & DETECTION SUMMARY")
    print("=" * 75)
    print(f" Total Packets Captured : {stats['total_packets']}")
    print(f" Total Bytes Analyzed   : {stats['total_bytes']:,} Bytes ({round(stats['total_bytes']/1024, 2)} KB)")
    print(f" Unique Communicating IP: {len(stats['ip_talkers'])}")
    print(f" Security Alerts Raised : {len(alerts)}")
    print("-" * 75)
    
    print("\n[+] PROTOCOL DISTRIBUTION:")
    for proto, cnt in stats["protocols"].most_common():
        pct = (cnt / max(1, stats["total_packets"])) * 100
        bar = "#" * int(pct / 4)
        print(f"  {proto:<8} : {cnt:>5} pkts ({pct:>5.1f}%)  |{bar:<25}|")

    print("\n[+] TOP 5 COMMUNICATING HOSTS:")
    for ip, cnt in stats["ip_talkers"].most_common(5):
        print(f"  {ip:<20} : {cnt:>5} packets")

    print("\n[+] SECURITY ANOMALIES DETECTED:")
    if not alerts:
        print("  None. Network baseline appears normal.")
    else:
        for idx, a in enumerate(alerts, 1):
            print(f"  [{idx}] [{a['level']}] {a['category']}")
            print(f"      Host: {a['src_ip']} -> {a['dst_ip']}")
            print(f"      Note: {a['description']}")
    print("=" * 75 + "\n")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="Network Traffic Analyzer - Packet Inspection, Threat Detection, and SOC Reporting"
    )
    parser.add_argument(
        "-m", "--mode",
        choices=["live", "pcap", "simulate"],
        default="simulate",
        help="Operating mode: 'live' (sniff interface), 'pcap' (analyze file), or 'simulate' (demo traffic)"
    )
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (e.g. eth0, Wi-Fi)")
    parser.add_argument("-f", "--file", help="Path to PCAP file (required for 'pcap' mode)")
    parser.add_argument("-c", "--count", type=int, default=80, help="Number of packets to capture/simulate (0 = infinite)")
    parser.add_argument("--bpf", help="Berkeley Packet Filter string (e.g. 'tcp port 80')")
    parser.add_argument("--html", default="traffic_report.html", help="HTML report output filename")
    parser.add_argument("--json", default="traffic_report.json", help="JSON report output filename")

    args = parser.parse_args()

    analyzer = NetworkAnalyzer(interface=args.interface)

    try:
        if args.mode == "simulate":
            print(f"[*] Starting simulated traffic scenario generator ({args.count} packets)...")
            analyzer.run_simulation(count=args.count)
        elif args.mode == "pcap":
            if not args.file or not os.path.exists(args.file):
                print(f"[!] Error: PCAP file not found: {args.file}")
                sys.exit(1)
            analyzer.analyze_pcap(args.file)
        elif args.mode == "live":
            analyzer.start_live_capture(packet_count=args.count, filter_exp=args.bpf)
    except KeyboardInterrupt:
        print("\n[*] Capture interrupted by user. Finalizing report...")

    # Display Terminal Summary
    print_summary_table(analyzer.stats, analyzer.detector.alerts)

    # Export Reports
    html_path = generate_html_report(analyzer.stats, analyzer.detector.alerts, analyzer.packet_log, args.html)
    json_path = generate_json_report(analyzer.stats, analyzer.detector.alerts, analyzer.packet_log, args.json)

    print(f"[+] Security Dashboard (HTML) exported to: {html_path}")
    print(f"[+] Structured Data Log (JSON) exported to : {json_path}")
    print("[*] Open the HTML file in your web browser to review the visual dashboard.")

if __name__ == "__main__":
    main()
