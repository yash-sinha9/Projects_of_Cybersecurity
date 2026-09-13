"""
ApexPort Network Scanner - Unified Application Launcher
Supports CLI, Desktop GUI, Web Dashboard, and Nmap Comparative Benchmarking.
"""

import sys
import argparse


def main():
    parser = argparse.ArgumentParser(
        description="ApexPort Network Security Suite - Low-Level Socket Scanner & Nmap Benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage Modes:
  python main.py --cli              Run high-performance terminal CLI scanner
  python main.py --gui              Launch high-tech desktop GUI application
  python main.py --web              Launch interactive Cyber Security Web Dashboard
  python main.py --benchmark        Run architectural comparison benchmark vs Nmap
        """
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--cli", action="store_true", help="Launch interactive CLI scanner mode (default)")
    group.add_argument("--gui", action="store_true", help="Launch desktop GUI scanner (Tkinter)")
    group.add_argument("--web", action="store_true", help="Launch web dashboard & local API server")
    group.add_argument("--benchmark", action="store_true", help="Run automated comparative benchmark against Nmap")

    # Forward any CLI arguments
    parser.add_argument("-t", "--target", default="127.0.0.1", help="Target host / IP for CLI mode")
    parser.add_argument("-p", "--ports", default="quick", help="Port range for CLI mode")

    args, unknown = parser.parse_known_args()

    if args.gui:
        import port_scanner_gui
        port_scanner_gui.main()
    elif args.web:
        import web_server
        web_server.start_server(open_browser=True)
    elif args.benchmark:
        from core.scanner import PortScanner
        from core.service_db import PORT_SETS
        from core.nmap_compare import get_nmap_comparison_report
        import json

        print("\n[*] Running Automated Nmap Comparative Benchmark against 127.0.0.1...")
        scanner = PortScanner(target="127.0.0.1", ports=PORT_SETS["quick"], timeout=0.8, threads=50)
        scanner.resolve_target()
        scanner.run_scan()
        summary = scanner.get_summary()
        report = get_nmap_comparison_report(summary)
        print("\n" + json.dumps(report, indent=2))
    else:
        # Default to CLI
        import port_scanner_cli
        # Pass remaining arguments to CLI runner
        port_scanner_cli.run_cli()


if __name__ == "__main__":
    main()
