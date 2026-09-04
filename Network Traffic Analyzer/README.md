# 🛡️ Network Traffic Analyzer (SOC & Security Engineering Project)

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Security](https://img.shields.io/badge/Domain-Network%20Security%20%2F%20SOC-red.svg)](#)
[![Scapy](https://img.shields.io/badge/Packet%20Engine-Scapy-green.svg)](https://scapy.net/)

> **"Why Industry Likes This Project: Network Traffic Analyzer"**
> This project demonstrates the ability to work with live network data — a skill that is at the core of every SOC analyst and network security engineer role.

---

## 🎯 Key Capabilities Demonstrated

- **Packet Capture & Protocol Analysis:** Real-time decoding of Ethernet, IPv4, TCP, UDP, ICMP, DNS, and application payloads.
- **Suspicious Ports & Anomaly Detection:** Identifies risky ports (e.g., Metasploit port 4444, Back Orifice 31337, Telnet 23, IRC 6667), TCP SYN scanning reconnaissance, SYN flooding, and DNS exfiltration heuristics.
- **Cleartext Credential Sniffing:** Flags unencrypted sensitive transmission (FTP/HTTP credentials, authorization tokens).
- **Interactive SOC Reporting:** Generates human-readable terminal dashboards, machine-readable JSON logs, and an executive-ready HTML dashboard with live Chart.js visualizations.

---

## 📂 Project Structure

```
Network Traffic Analyzer/
│
├── analyzer.py       # Core packet capture engine & parser (Scapy / PCAP / Simulation)
├── detector.py       # Anomaly detection & threat identification engine
├── reporter.py       # Terminal output formatter, JSON exporter, and HTML dashboard generator
├── main.py           # CLI entry point with argument parsing
├── requirements.txt  # Project dependencies
└── README.md         # Comprehensive documentation & setup instructions
```

---

## 🚀 Quickstart Guide

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```
*(On Windows, ensure [Npcap](https://npcap.com/) is installed with "WinPcap API-compatible Mode" enabled for live raw packet capture).*

### 2. Run in Simulation Mode (No Root/Npcap Required)
Test all threat detection scenarios immediately:
```bash
python main.py --mode simulate --count 80
```

### 3. Run Live Packet Capture (Administrator / Root)
Capture 100 packets live on your default network card:
```bash
python main.py --mode live --count 100
```
Capture with a specific Berkeley Packet Filter (BPF):
```bash
python main.py --mode live --bpf "tcp port 80 or tcp port 443"
```

### 4. Analyze an Offline PCAP File
```bash
python main.py --mode pcap --file capture_sample.pcap
```

---

## 📊 Sample Visual Report
When executed, the tool generates:
1. **`traffic_report.html`**: Open in any browser for an interactive dashboard with protocol distribution charts, top talkers, and categorized threat alerts.
2. **`traffic_report.json`**: For ingestion into SIEM systems (Elasticsearch, Splunk, Graylog).
