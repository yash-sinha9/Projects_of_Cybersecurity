# ⚡ ApexPort — Network Security Port Scanner & Analysis Suite

> **"Building a tool from scratch is always more impressive than just using one."**  
> *Recruiters and industry engineering leaders value developers and security engineers who can build low-level networking tools, not just execute pre-packaged utilities.*

---

## 🎯 Project Overview & Recruiter Value Proposition

**ApexPort** is a modular, high-performance network security port scanner built entirely in **pure Python** using the native BSD socket API (`socket`), concurrent multi-threading (`concurrent.futures`), and low-level protocol handshakes.

### Key Skills Demonstrated:
1. **Python Socket Programming Fundamentals:** Direct manipulation of TCP sockets, connection timeouts, socket option flags, and non-blocking I/O concepts.
2. **Understanding of TCP/UDP & Port States:**
   - **OPEN:** Complete 3-way TCP handshake (`SYN` → `SYN/ACK` → `ACK`).
   - **CLOSED:** Detection of active host rejection (`RST` packets / `WSAECONNREFUSED` / error `10061` / `111`).
   - **FILTERED / STEALTH:** Identification of dropped packets and stateful firewall timeouts (`WSAETIMEDOUT` / error `10060`).
   - **OPEN|FILTERED:** Accurate handling of UDP connectionless protocol ambiguity.
3. **Application Banner Grabbing & Service Detection (-sV):** Active protocol interrogation for HTTP/HTTPS, SSH, SMTP, FTP, MySQL, and Redis services.
4. **Direct Architectural Comparison with Nmap:** Comprehensive analysis of why userland socket scanning differs from raw packet injection (`libpcap`/`Npcap`).

---

## 🏗️ Architecture & Component Layout

```
Port Scanner Tool/
├── core/
│   ├── scanner.py          # Multithreaded socket scanning engine & banner grabber
│   ├── service_db.py       # Knowledge base of 200+ ports, services, and risk ratings
│   └── nmap_compare.py     # Comparative performance & architectural benchmark logic
├── web_dashboard/
│   ├── index.html          # Cyberpunk glassmorphic web dashboard
│   ├── style.css           # Modern neon dark-mode UI stylesheet
│   └── app.js              # Interactive 1000-port matrix & client-side telemetry
├── port_scanner_cli.py     # Rich terminal CLI with ANSI tables and JSON export
├── port_scanner_gui.py     # Sleek dark-mode desktop GUI built with Tkinter
├── web_server.py           # Zero-dependency Python HTTP API server for the web app
├── main.py                 # Unified launcher (CLI, GUI, Web, Benchmark)
└── README.md               # Technical portfolio documentation & interview guide
```

---

## 🚀 Quickstart Guide

### Prerequisites
- Python 3.8+ (No third-party `pip` dependencies required! Runs on standard library).

### Launch Options

#### 1. Launch Desktop GUI (Recommended for Visual Demos)
```bash
python main.py --gui
```
*Opens a dark-mode desktop interface with real-time port matrix, banner inspector, and export controls.*

#### 2. Launch Cyber Security Web Dashboard
```bash
python main.py --web
```
*Starts local HTTP server on `http://127.0.0.1:8888` and opens the web application.*

#### 3. Run High-Performance CLI Scanner
```bash
# Quick scan top 20 ports on localhost
python main.py --cli -t 127.0.0.1 -p quick

# Scan common services with Nmap comparison output
python main.py --cli -t 127.0.0.1 -p top50 --compare-nmap -o scan_report.json

# Custom port range with 100 worker threads
python port_scanner_cli.py -t 127.0.0.1 -p 21,22,80,443,3000-3010 --threads 100
```

#### 4. Run Automated Benchmark
```bash
python main.py --benchmark
```

---

## ⚖️ Custom Socket Scanner vs Nmap: Architectural Comparison

| Evaluation Metric | ApexPort (Our Custom Python Tool) | Nmap Default Engine (`-sS`) | Recruiter / Industry Takeaway |
| :--- | :--- | :--- | :--- |
| **Scanning Technique** | Full TCP 3-Way Handshake (`SYN` → `SYN/ACK` → `ACK`) | TCP SYN Stealth Scan (`SYN` → `SYN/ACK` → `RST`) | Deep comprehension of RFC 793 connection states and BSD socket APIs. |
| **Privilege Level** | **Userland** (No Admin / Root required) | **Administrator / Root required** (Raw sockets) | Runs safely in restricted enterprise environments and sandboxes without elevation. |
| **Socket Mechanics** | OS BSD Socket API (`socket.connect_ex`) | Raw Ethernet/IP/TCP frame construction via `libpcap`/`Npcap` | Demonstrates ability to work across OS abstraction layers. |
| **Logging & SIEM** | Logged by target application (connection completed) | Bypasses simple application connection logs | Understands network detection vectors and defensive SOC monitoring. |
| **Error Code Logic** | `0` = Open, `ECONNREFUSED` = Closed, `ETIMEDOUT` = Filtered | Packet flags (`SYN/ACK`, `RST`, ICMP unreachable) | Shows exact translation of kernel socket exceptions to network topology. |
| **Concurrency Model** | `concurrent.futures.ThreadPoolExecutor` | Custom C++ asynchronous event loop | Proves mastery of multithreading, thread safety, and resource cleanup. |

---

## 🎓 Technical Interview Defense & Key Questions

### Q1: How does your tool determine if a port is Filtered vs Closed?
> **Answer:**  
> When connecting to a closed port, the destination host's TCP stack sends an active `RST` (Reset) packet. On Windows, this immediately triggers Winsock error `10061` (`WSAECONNREFUSED`), and on POSIX systems error `111` (`ECONNREFUSED`).  
> Conversely, when a firewall or security group silently drops the incoming `SYN` packet, no reply is returned. The socket reaches the timeout threshold, returning error `10060` (`WSAETIMEDOUT`). Our scanner captures these distinct OS signals to categorize the state accurately.

### Q2: Why did you implement a TCP Connect scan rather than a SYN Stealth scan?
> **Answer:**  
> A TCP Connect scan relies on standard user-space OS socket APIs (`connect()` / `connect_ex()`), meaning it requires **zero administrative or root privileges** to run on Windows, macOS, or Linux. SYN stealth scans require raw socket access (`SOCK_RAW`) or kernel packet drivers (`Npcap`/`libpcap`) which are locked down on enterprise machines and cloud containers.

### Q3: How do you prevent thread starvation when scanning thousands of ports?
> **Answer:**  
> Instead of spawning an unbounded number of threads (which would exhaust OS thread handles and cause excessive context switching), we utilize `ThreadPoolExecutor` with a bounded worker pool (typically 50–100 threads) and an adaptive socket timeout. Non-blocking sockets ensure that worker threads release immediately upon socket failure or timeout.
