# 🛡️ CyberGuard SOC: SIEM Dashboard Setup

> **The SIEM (Security Information & Event Management) is the command center of every Security Operations Center (SOC).**  
> Built from scratch to demonstrate industry-standard SOC Analyst workflows: log ingestion, normalization, failed authentication & top threat IP tracking, and real-time alert triage.

---

## 📌 Project Objectives & Capabilities (Slide Requirements Covered)

This project directly fulfills all 4 key pillars expected in SOC Analyst & Cyber Defense engineering roles:

1. **Log Ingestion and Normalization:**
   - Multi-source parser supporting **Linux SSH/Auth logs**, **Windows Security Events (EventID 4624/4625)**, **Nginx/Apache Web access logs (SQLi/XSS)**, **UFW/IPTables Firewalls**, and generic Syslog.
   - Converts raw, disparate log formats into a **Unified Common Information Model (CIM)** schema (`timestamp`, `source_type`, `source_ip`, `destination_ip`, `username`, `event_type`, `status`, `severity`, `raw_message`, `country`).

2. **Dashboard Creation for Security Monitoring:**
   - High-impact Cyber SOC Command Center UI with dark mode, glassmorphism panels, and telemetry beacons.
   - Dynamic KPI stat cards (Total Ingested Logs, Failed Logins %, Active Incidents, Top Adversary IP).
   - Time-series sliding window charts displaying failed vs. successful authentications over time.
   - MITRE ATT&CK event category distribution doughnut charts.

3. **Failed Login and Top IP Tracking:**
   - Automated threat scoring algorithm combining frequency of failed authentications and web attacks.
   - Top 10 Attacking IPs Matrix with geolocation country mapping, event totals, and quick firewall null-route action.
   - Most targeted user accounts breakdown (`root`, `admin`, `oracle`, `administrator`).

4. **Real-Time Alert Configuration:**
   - Sliding-window correlation engine (`alert_engine.py`) detecting:
     - **SSH / Auth Brute Force** ($\ge 5$ failed attempts within 60 seconds from same IP).
     - **Web Application Attack** (SQL Injection, Cross-Site Scripting patterns).
     - **Privilege Escalation** (Unauthorized `sudo /bin/bash` or root token manipulation).
     - **Port Scan & Reconnaissance** (Rapid connection bursts).
   - Active Incident Triage Console with status lifecycle (`OPEN` &rarr; `INVESTIGATING` &rarr; `RESOLVED`).

---

## 🏗️ Architecture Overview

```
                      RAW LOG SOURCES
   [Linux SSH/Auth]  [Windows 4625/4624]  [Web Server]  [Firewall]
          │                 │                  │            │
          └─────────────────┴────────┬─────────┴────────────┘
                                     ▼
                    ┌─────────────────────────────────┐
                    │       Log Normalizer (CIM)      │
                    │         (normalizer.py)         │
                    └────────────────┬────────────────┘
                                     ▼
                    ┌─────────────────────────────────┐
                    │   Alert Correlation Engine      │
                    │        (alert_engine.py)        │
                    │   - Sliding time window check   │
                    │   - Threshold rule evaluation   │
                    │   - Deduplication & Severity    │
                    └────────────────┬────────────────┘
                                     ▼
                    ┌─────────────────────────────────┐
                    │      SQLite Database Engine     │
                    │  [logs]   [alerts]   [rules]    │
                    └────────────────┬────────────────┘
                                     ▼
                    ┌─────────────────────────────────┐
                    │       Flask REST API Server     │
                    │             (app.py)            │
                    └────────────────┬────────────────┘
                                     ▼
                    ┌─────────────────────────────────┐
                    │     Real-Time SOC Dashboard     │
                    │  (HTML5 + Vanilla CSS + ChartJS)│
                    └─────────────────────────────────┘
```

---

## 🚀 Quickstart Guide

### 1. Requirements
- Python 3.9+ (Python 3.12 verified)
- Web browser (Chrome, Edge, Firefox)

### 2. Installation
Open terminal or PowerShell in the project directory:
```bash
pip install -r requirements.txt
```

### 3. Run the Dashboard
Execute the Python server:
```bash
python app.py
```
Or double-click `run.bat` on Windows.

Open your browser at: **`http://127.0.0.1:5000`**

---

## 📡 REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/metrics` | High-level metrics, KPI counters, time-series data, and event breakdowns |
| `GET` | `/api/logs` | Searchable & filterable log feed with pagination |
| `GET` | `/api/top-ips` | Top attacking source IPs with threat scores (0-100%) and country origin |
| `GET` | `/api/failed-logins` | Targeted username statistics and attacker IP analysis |
| `GET` | `/api/alerts` | Active and historical security incident queue |
| `POST` | `/api/alerts/<id>/status` | Update alert triage status (`OPEN`, `INVESTIGATING`, `RESOLVED`) |
| `GET` / `POST` | `/api/rules` | Inspect or configure real-time detection threshold rules |
| `POST` | `/api/ingest` | Ingest and normalize an arbitrary raw log payload |
| `POST` | `/api/simulator/generate-attack` | Trigger an immediate 6-packet brute-force attack burst |
| `POST` | `/api/simulator/toggle` | Pause or resume background telemetry streaming |

---

## 🧪 Testing & Demonstration Workflows

### Scenario A: Instant Brute Force Detection
1. Click the **"⚡ Trigger Attack Burst"** button in the header.
2. The server fires 6 rapid failed logins from attacker IP `185.220.101.5` targeting user `root`.
3. Within milliseconds, the **Alert Engine** triggers:
   - Alert Title: **"SSH / Auth Brute Force Detection"**
   - Severity: **CRITICAL**
   - Status: **OPEN**
4. An immediate audio/visual alert toast appears, the Active Alerts KPI increments, and the incident enters the triage queue.

### Scenario B: Custom Log Ingestion & Parsing
1. Click **"➕ Ingest Raw Log"** in the top navigation.
2. Choose one of the preset buttons (e.g. *Web SQL Injection* or *Windows Event 4625*) or paste your own raw log string.
3. Click **"Ingest & Normalize"**.
4. The dashboard displays the extracted JSON schema and indicates whether a threshold alert was fired.

### Scenario C: Incident Triage Lifecycle
1. Under **Real-Time Security Incident Queue**, locate an open alert.
2. Click **"Triage / Resolve"**.
3. The alert status transitions to `RESOLVED`, assigned to `Lead SOC Analyst`, updating metrics in real-time.

---

## 🎓 SOC Analyst Interview Talking Points

- **Why Normalization Matters:** Disparate log formats (Syslog, JSON, Windows XML, W3C) cannot be easily correlated together. Converting them to a standardized Common Information Model allows writing single detection rules that apply across multi-cloud and on-prem assets.
- **Sliding-Window Correlation:** Rather than static single-event triggers, threshold correlation analyzes events across rolling temporal windows (e.g. $\ge 5$ failures in 60 seconds), drastically minimizing false positives while catching automated brute-force scripts.
- **Threat Scoring & Triage:** Combining frequency with high-risk target variables (e.g. attempts against `root` vs non-privileged users, external non-RFC1918 IPs) helps tier alerts so SOC Tier-1 analysts prioritize critical intrusions first.
