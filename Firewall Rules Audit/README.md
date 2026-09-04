# 🛡️ Firewall Rules Audit & Perimeter Defense Studio

An enterprise-grade Network Security suite for auditing, analyzing, and simulating Linux `iptables` and network perimeter defenses. 

Built directly to fulfill the four foundational industry pillars:
1. **Linux iptables Configuration from Scratch**
2. **Allow / Deny Rule Logic and Policy Thinking (Shadow & Redundancy Detection)**
3. **Security Documentation and Gap Analysis (CIS Benchmark 3.4 / PCI-DSS 1.2 / NIST SP 800-41)**
4. **Network Perimeter Defense & Interactive Packet Traversal Simulation**

*Reference Project: Sujal Kowshik chowdhary*

---

## 🌟 Key Capabilities

- **Interactive Rule Matrix**: Reorder, add, edit, or delete rules live with automatic first-match-wins re-indexing.
- **Automated Shadow Rule Detection**: Instantly flags dead rules where an earlier broad `ACCEPT` rule completely shadows a later restrictive `DROP` rule.
- **Overly Permissive Access Auditor**: Detects unrestricted `0.0.0.0/0` exposure on administrative and database ports (SSH 22, Telnet 23, RDP 3389, MySQL 3306, Redis 6379, MongoDB 27017).
- **Interactive Packet Tracer Sandbox**: Construct custom packets (Source IP, Destination IP, Protocol, Port, Chain) and trace their step-by-step traversal through the chain to view the exact matching rule or default policy fallback.
- **Security Health Score (0 - 100)**: Real-time SVG circular gauge with letter grading (A+ to F) and CIS Linux Benchmark compliance meters.
- **Production Hardening Generator**: Generates clean, idempotent, CIS-compliant Bash scripts (`firewall-harden.sh`) tailored to Web, Bastion, or Database profiles.
- **Standalone Python CLI Tool (`firewall_audit.py`)**: Runs directly in the terminal to parse and audit raw `iptables-save` dumps with JSON export support.

---

## 🚀 Quick Start

### 1. Launching the Web Application
Simply open `index.html` in any modern web browser:
```powershell
# In PowerShell or Windows Terminal:
Start-Process "c:\Users\asdmin\OneDrive\Desktop\Firewall Rules Audit\index.html"
```
Or double-click `index.html` in File Explorer. No Node.js or backend server is required!

### 2. Running the Python CLI Auditor
```bash
python firewall_audit.py sample_rules/vulnerable_iptables.rules
```
To test an individual packet via CLI:
```bash
python firewall_audit.py sample_rules/vulnerable_iptables.rules --test-packet 198.51.100.50 10.0.0.5 tcp 22
```
To export JSON results:
```bash
python firewall_audit.py sample_rules/vulnerable_iptables.rules --json > audit_results.json
```

---

## 📁 Repository Structure

```
Firewall Rules Audit/
│
├── index.html                      # Modern cyber-defense single-page web app
├── styles.css                      # Cyber dark-theme styling, glassmorphism & badges
├── app.js                          # Parsing engine, gap auditor & packet simulator
├── firewall_audit.py               # Companion Python CLI tool for terminal auditing
│
├── sample_rules/                   # Industrial sample firewall dumps
│   ├── vulnerable_iptables.rules   # Vulnerable misconfigured server dump
│   ├── hardened_iptables.rules     # CIS-compliant hardened bastion dump
│   └── corporate_dmz.rules         # Dual-homed corporate DMZ perimeter dump
│
└── README.md                       # Documentation, architecture & interview guide
```

---

## 🛡️ Technical Deep-Dive & Interview Defense

### 1. The Hazard of Shadowed Rules
A **shadowed rule** is a rule that can never be triggered because an earlier rule in the sequence matches all or a superset of its network traffic criteria.
- **Example in Audit**:
  - Rule #3: `-A INPUT -p tcp --dport 22 -j ACCEPT`
  - Rule #9: `-A INPUT -s 198.51.100.50 -p tcp --dport 22 -j DROP`
- **Impact**: The firewall kernel evaluates rules top-to-bottom on a **first-match-wins** basis. When attacker `198.51.100.50` connects, Rule #3 matches and grants access immediately. Rule #9 is dead code.
- **Remediation**: Specific drop rules must ALWAYS be placed before broader general allow rules using `iptables -I`.

### 2. Stateful Inspection & Connection Tracking
Placing `-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT` at the top of the chain allows return traffic for established outbound requests without keeping high-numbered ports open to inbound attack.

### 3. Egress Filtering
Allowing unrestricted outbound egress (`OUTPUT ACCEPT`) leaves systems vulnerable to reverse shell command-and-control (C2) beaconing and data exfiltration. Hardened perimeters restrict outbound egress to strictly required destinations (DNS on port 53, NTP on port 123, HTTPS on port 443).
