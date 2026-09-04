# Metasploit Lab on DVWA | Ethical Hacking & Penetration Testing

> **Project Reference Image**: *"Why Industry Likes This Project: Metasploit Lab on DVWA"*  
> **Topic**: Real exploit execution, post-exploitation techniques, understanding attacker methodology, and documenting steps for legal reporting.  
> **Contributors**: Umma Jubaiya, Kowshik, Sahjada Abdullah, Satyam Paliya.

---

## 📖 1. Full Code Prompt

```text
Build a professional, interactive cybersecurity web application and lab simulator based on the presentation topic:
"Why Industry Likes This Project: Metasploit Lab on DVWA (Ethical Hacking & Penetration Testing)".

Key Requirements:
1. Interactive Metasploit Console (msfconsole terminal emulator):
   - Supports realistic msfconsole banners, prompt states (msf6 >, msf6 exploit(...) >, meterpreter >, and bash shell).
   - Interactive command parser supporting: 'help', 'search', 'use', 'set', 'options', 'exploit/run', 'sessions -l', 'sessions -i 1', 'sysinfo', 'getuid', 'hashdump', 'shell', 'clear', and arrow key command history.
   - Quick workflow automation buttons: Nmap Scan, Set Exploit & Payload, Fire Exploit 🚀, and Run Meterpreter Shell.

2. Simulated DVWA (Damn Vulnerable Web Application) Target:
   - Live visual card mimicking DVWA web endpoints (Command Execution, File Upload, SQL Injection, Recon Audit).
   - Security level toggle (Low, Medium, High, Impossible) with real-time target feedback and defense behavior.
   - Side-by-side Code Defense Inspector: compares vulnerable PHP code vs. remediated/patched code.

3. Attack Lifecycle & Methodology Suite:
   - 6-stage interactive MITRE ATT&CK / NIST SP 800-115 lifecycle stepper:
     1. Reconnaissance & Discovery (Nmap, portscan)
     2. Vulnerability Identification (OWASP Top 10 Injection)
     3. Weaponization & Payload Generation (msfvenom, php/meterpreter)
     4. Exploitation & Callback (multi/handler reverse TCP socket)
     5. Post-Exploitation & Persistence (meterpreter, hashdump, privesc)
     6. Remediation & Legal Reporting (PTES standards, CVSS v3.1)
   - Animated walkthrough mode and Attacker Mindset vs Ethical Hacker comparative table.

4. Post-Exploitation & Defense Suite:
   - Interactive post-exploitation cards for 'sysinfo', 'getuid', 'hashdump', 'shell', 'persistence', and 'privilege escalation'.
   - Dedicated Inspector Log displaying detailed audit evidence and risk evaluation.

5. Penetration Testing Legal & Compliance Report Generator:
   - Formats formal audit reports aligned with PTES (Penetration Testing Execution Standard) and OWASP.
   - Customizable scope, lead auditor signatures, CVSS scoring table, technical PoC logs, and mitigation roadmaps.
   - Live export capabilities: Print-to-PDF and Copy Markdown to clipboard.

6. Industry Value & Contributors Section:
   - Detailed analysis of why cybersecurity hiring teams prioritize hands-on Metasploit experience.
   - Featured credits for project authors: Umma Jubaiya, Kowshik, Sahjada Abdullah, Satyam Paliya.

7. Aesthetics & Tech Stack:
   - Dark cybersecurity theme: deep obsidian background (#090c10), emerald neon (#00ff9d), threat crimson (#ff4a6e), electric cyan (#38bdf8), and glowing accents.
   - Modern typography: Fira Code and Inter.
   - Zero external build dependencies (standalone HTML5, CSS3, ES6+ JS).
```

---

## 💻 2. Full Code Architecture

The application is structured into 3 modular files:

| File | Path | Size | Description |
|---|---|---|---|
| **Markup** | [`index.html`](file:///c:/Users/asdmin/OneDrive/Desktop/Metasploit1/index.html) | ~33 KB | Semantic layout with split workspace, msfconsole terminal, DVWA preview, tab systems, modals, and report canvas. |
| **Styles** | [`styles.css`](file:///c:/Users/asdmin/OneDrive/Desktop/Metasploit1/styles.css) | ~30 KB | Cyberpunk/cybersecurity dark theme, glassmorphism, responsive grid, terminal styling, and print CSS for PDF export. |
| **Engine** | [`app.js`](file:///c:/Users/asdmin/OneDrive/Desktop/Metasploit1/app.js) | ~36 KB | State machine, terminal parser, DVWA security response logic, Meterpreter session manager, and PTES report compiler. |

---

## 🚀 3. How to Run Locally

Because the application is built with vanilla HTML5, CSS3, and modern JavaScript, it runs instantly in any browser with **no installations or build steps required**:

### Option A: Direct Browser Launch
Simply double click or open [`index.html`](file:///c:/Users/asdmin/OneDrive/Desktop/Metasploit1/index.html) in your browser:
```powershell
Start-Process "c:\Users\asdmin\OneDrive\Desktop\Metasploit1\index.html"
```

### Option B: Local Web Server (Python / Node / Live Server)
```powershell
cd "c:\Users\asdmin\OneDrive\Desktop\Metasploit1"
python -m http.server 8080
# Open http://localhost:8080 in your browser
```

---

## 🎯 4. Final Result & Features

### 1. Interactive Metasploit Framework Console (`msfconsole`)
- **Realistic Banner**: Metasploit v6.4 banner with ASCII art and module counters.
- **Dynamic Prompt Engine**: Adapts dynamically between `msf6 >`, `msf6 exploit(...) >`, `meterpreter >`, and `www-data@dvwa-target:/var/www/html$ `.
- **Command Support**: Supports `help`, `search dvwa`, `use exploit/multi/handler`, `set RHOSTS`, `set LHOST`, `exploit`, `sessions -l`, `sessions -i 1`, `sysinfo`, `getuid`, `hashdump`, `shell`, and `clear`.
- **Keyboard Navigation**: Command history recall via `ArrowUp` / `ArrowDown`.

### 2. Live DVWA Target & Security Filter Testing
- **Security Levels**: Low (direct injection), Medium (blacklisting `;`), High (pipe sanitization), and Impossible (strict `filter_var(..., FILTER_VALIDATE_IP)`).
- **Code Inspector**: Immediate side-by-side toggle between the vulnerable PHP script and the enterprise-grade secure code patch.

### 3. MITRE ATT&CK Lifecycle Stepper
- 6-phase visual progression showing how a penetration tester systematically moves from Reconnaissance to Weaponization, Exploitation, Post-Exploitation, and Hardening.
- One-click animated walkthrough button.

### 4. PTES Legal Compliance Report Generator
- Fully formatted audit report with CVSS v3.1 matrix (e.g., CVSS 9.8 Remote OS Command Injection).
- Technical Proof-of-Concept logs.
- One-click **Print / Save as PDF** and **Copy to Markdown** for easy portfolio presentation.

---

## 🏆 5. Final Conclusion of the Given Image

The image highlights a profound reality in modern cybersecurity hiring:

> *"Ethical hackers who have used Metasploit hands-on are far more credible to hiring teams."*

### Key Takeaways from the 4 Core Industry Pillars:

1. **Real Exploit Execution in a Lab Setup**:
   Hiring managers look for candidates who understand that exploits are not theoretical. Demonstrating socket creation, reverse listeners (`multi/handler`), stage transmission, and payload stability on legal targets like DVWA proves operational readiness.

2. **Post-Exploitation Techniques & Persistence**:
   Initial access alone does not demonstrate risk. Industry penetration testers must articulate business impact: can an attacker extract credentials (`hashdump`), determine effective rights (`getuid`), maintain persistent access across reboots, or pivot deeper into internal subnets?

3. **Understanding Attacker Mindset and Methodology**:
   True defense is built on understanding offense. By mapping exploitation steps against the Cyber Kill Chain and MITRE ATT&CK framework, ethical hackers can anticipate adversary behavior and design resilient defense-in-depth controls.

4. **Documenting Steps for Legal Reporting**:
   Technical skill without clear documentation is ineffective. Industry leaders require audit-ready reports containing executive summaries for leadership, CVSS severity ratings for risk teams, reproducible proof-of-concepts for developers, and actionable remediation steps.

### Project Team Recognition:
- **Umma Jubaiya**: Lead Security Researcher & Exploit Architecture
- **Kowshik**: Exploit Engineer & Payload Configuration
- **Sahjada Abdullah (2nd)**: Security Analyst & Target Hardening
- **Satyam Paliya**: Documentation Lead & Legal Compliance Reporting
