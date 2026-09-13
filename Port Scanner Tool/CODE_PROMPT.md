# 📋 Master Engineering Prompt: Building a Production-Grade Port Scanner Tool from Scratch

Use the prompt below to generate, extend, or prompt an AI / engineering team to rebuild this complete software suite:

```markdown
You are an expert network security software engineer. Design and implement a production-grade, multi-threaded Port Scanner Tool from scratch in Python that demonstrates core network engineering principles without third-party dependencies.

The tool must address all elements of the following industry specification:
1. Low-Level Python Socket Programming:
   - Use the Python standard library (`socket`, `struct`, `concurrent.futures`, `time`).
   - Implement TCP Connect scanning using `socket.connect_ex` and evaluate low-level OS error codes (WSAECONNREFUSED / ECONNREFUSED vs WSAETIMEDOUT) to classify ports into OPEN, CLOSED, and FILTERED states.
   - Implement UDP datagram probing with protocol-specific payloads (e.g. DNS port 53, NTP port 123, SNMP port 161) and handle connectionless OPEN|FILTERED ambiguities.
   - Implement Application-Layer Banner Grabbing (-sV) that sends non-destructive probes (HTTP HEAD/GET, SSH handshake, SMTP HELO, Redis PING) to extract software versions and system signatures.
   - Provide precise Round-Trip Time (RTT) latency measurements in milliseconds for every open port.

2. Concurrency & Performance:
   - Implement thread-pool worker pooling (`ThreadPoolExecutor`) with customizable concurrency (10 to 300 threads).
   - Ensure clean resource management (always closing sockets, avoiding thread starvation, clean cancellation/abort handling).

3. Professional Tool Comparison (Nmap):
   - Provide an integrated comparative benchmark module comparing this custom tool with Nmap.
   - Contrast userland TCP connect scans vs kernel-level raw packet SYN stealth scans (-sS via libpcap/Npcap).
   - Explain privilege requirements (unprivileged userland vs root/Administrator), application logging footprints, and detection vectors.

4. Multi-Interface Accessibility:
   - CLI Interface: High-impact terminal UI with ANSI colors, port range parsing ('quick', 'top50', '1-1024', 'custom'), real-time progress callbacks, structured summary tables, and JSON/CSV export.
   - Desktop GUI: Tkinter-based dark cybersecurity GUI with real-time treeview, color-coded badges, live metric cards (Scanned, Open, Filtered, Closed, Speed p/s), banner inspector pane, and one-click file export.
   - Web Dashboard: Glassmorphic dark cyberpunk web application with an interactive 1000-port visual topology matrix, real-time telemetry strip, search/filter controls, and modal inspector.
   - Lightweight Web Bridge Server: A zero-dependency Python HTTP server that serves the frontend and exposes REST API endpoints for scanning.

5. Code Quality:
   - Zero external pip package requirements.
   - Robust host resolution with IPv4 and DNS fallback.
   - Comprehensive error handling and clean modular architecture (`core/scanner.py`, `core/service_db.py`, `core/nmap_compare.py`, `main.py`).
```
