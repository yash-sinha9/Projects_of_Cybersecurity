"""
Lightweight Python HTTP Server & Real-time Scan API
Connects web frontend dashboard to the Python socket scanning engine.
"""

import os
import sys
import json
import webbrowser
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse

# Ensure core package can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.scanner import PortScanner

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web_dashboard")
PORT = 8888


class ScannerRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ready", "engine": "Python 3.12 Socket Engine"}).encode("utf-8"))
            return
        
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/scan":
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len)
            
            try:
                data = json.loads(post_body.decode("utf-8"))
                target = data.get("target", "127.0.0.1")
                ports = data.get("ports", [80, 443])
                scan_mode = data.get("scan_mode", "TCP")
                threads = int(data.get("threads", 75))

                scanner = PortScanner(
                    target=target,
                    ports=ports,
                    timeout=1.0,
                    threads=threads,
                    grab_banners=True,
                    scan_type=scan_mode
                )
                
                resolved, msg = scanner.resolve_target()
                if not resolved:
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": msg}).encode("utf-8"))
                    return

                scanner.run_scan()
                summary = scanner.get_summary()

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps(summary).encode("utf-8"))
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


def start_server(open_browser=True):
    server = HTTPServer(("127.0.0.1", PORT), ScannerRequestHandler)
    url = f"http://127.0.0.1:{PORT}"
    print(f"\n[+] ApexPort Web Dashboard active at: {url}")
    print("[*] Press Ctrl+C in terminal to stop server.\n")
    
    if open_browser:
        webbrowser.open(url)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server shutdown.")


if __name__ == "__main__":
    start_server()
