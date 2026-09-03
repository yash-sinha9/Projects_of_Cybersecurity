# Portfolio Showcase: Security Code Review & Remediation Project

This project demonstrates the core competencies required to bridge the gap between development and security teams by "shifting security left" in the software development lifecycle (SDLC). 

As outlined in our project criteria, this submission shows:
1. **Static Analysis with Professional Tools** (Custom YAML rule sets).
2. **Manual Identification of Injection and Auth Flaws** (DOM XSS, Stored XSS, Broken Access Control).
3. **Producing a Professional Code Audit Report** (Risk levels, PoCs, and remediations).
4. **Developer-Friendly Remediation Communication** (Empathy-driven secure coding guide).

---

## 📋 Table of Contents
1. [Original Coding Prompt](#1-original-coding-prompt)
2. [Manual Vulnerability Identification](#2-manual-vulnerability-identification)
3. [Static Analysis Integration](#3-static-analysis-integration)
4. [Remediation & Secure Implementations](#4-remediation--secure-implementations)
5. [Key Deliverables](#5-key-deliverables)
6. [Conclusion: Shifting Security Left](#6-conclusion-shifting-security-left)

---

## 1. Original Coding Prompt

The audited application was originally generated using the following specifications:

```markdown
### Prompt Title: Phishing Awareness Simulation Platform

**Objective:**
Build a local web application that serves as a Phishing Awareness Simulation tool. The application must allow an administrator to configure simulation campaigns, enforce and manage informed consent, generate harmless phishing emails and landing pages, track user interactions (clicks, submissions) in real-time, present an interactive educational page showing security "red flags," and auto-generate a comprehensive project report.

**Technical Stack:**
Node.js Express backend, Vanilla HTML5, CSS3, and JavaScript frontend. Charts via Chart.js CDN.
```
*For the complete detailed specifications document, see [coding_prompt.md](file:///c:/Users/asdmin/OneDrive/Desktop/Phishing/coding_prompt.md).*

---

## 2. Manual Vulnerability Identification

A manual line-by-line inspection of the codebase revealed several high-risk vulnerabilities:

### A. Broken Access Control (Critical)
*   **Location:** `index.html` / `dashboard.js`
*   **Vulnerability:** The Admin Control Panel lacks any form of session validation or authentication. Anyone can access whitelisted user details and clear the database by navigating directly to `index.html`.

### B. DOM-Based XSS (High)
*   **Location:** `email_preview.html`
*   **Vulnerability:** Unsanitized URL parameters are directly interpolated into an HTML template string and rendered using `element.innerHTML`, enabling arbitrary script execution.
*   **Vulnerable Snippet:**
    ```javascript
    const finalEmail = targetEmail || campaign.targetEmail;
    document.getElementById("email-body").innerHTML = `<p>Associated with ${finalEmail}</p>`;
    ```

### C. Stored XSS (High)
*   **Location:** `app.js` / `dashboard.js`
*   **Vulnerability:** Whitelist registration names are saved directly to `localStorage` without input filtering. When the administrator views the dashboard logs or whitelists, these names are loaded and printed to the DOM using `tr.innerHTML = ...`, triggering script injection inside the admin session.

### D. Redirection Bypass / Incomplete Execution Flow (Medium)
*   **Location:** `email_preview.html`
*   **Vulnerability:** When a user is not whitelisted, the browser is instructed to redirect. However, because script execution is not explicitly terminated, the remaining scripts on the page run anyway.

---

## 3. Static Analysis Integration

To enforce security checks automatically during developer builds, we created a custom static analysis configuration. The rules detect unsafe HTML injection patterns and redirection errors.

### Semgrep Configuration Rule Set (`semgrep_rules.yaml`):
```yaml
rules:
  - id: dom-xss-innerhtml
    pattern-either:
      - pattern: $ELEMENT.innerHTML = $VAR
      - pattern: $ELEMENT.innerHTML = `...${$VAR}...`
    message: "DOM-based Cross-Site Scripting (XSS) detected via unsanitized innerHTML assignment."
    languages: [javascript]
    severity: WARNING

  - id: redirect-without-exit
    patterns:
      - pattern: |
          window.location.href = $URL;
          ...
      - pattern-not: |
          window.location.href = $URL;
          return;
    message: "Redirection occurs without immediate execution termination."
    languages: [javascript]
    severity: WARNING
```
*Review the full rules file in [semgrep_rules.yaml](file:///c:/Users/asdmin/OneDrive/Desktop/Security-Code-Review/semgrep_rules.yaml).*

---

## 4. Remediation & Secure Implementations

Secure variants of the application code were built to show developers the target state:

1.  **Input Escaping:** Implemented an `escapeHTML` helper in [secure_app.js](file:///c:/Users/asdmin/OneDrive/Desktop/Security-Code-Review/secure_app.js) to clean name and email inputs prior to logging or storing them.
2.  **Safe DOM APIs:** Refactored [secure_dashboard.js](file:///c:/Users/asdmin/OneDrive/Desktop/Security-Code-Review/secure_dashboard.js) to use safe DOM manipulation methods (`.textContent` and `document.createElement`) to completely prevent XSS.
3.  **Halted Execution:** Modified [secure_email_preview.html](file:///c:/Users/asdmin/OneDrive/Desktop/Security-Code-Review/secure_email_preview.html) to throw an error immediately following redirection requests, preventing further script execution.
4.  **JWT Authentication Middleware:** Authored [secure_admin_auth.js](file:///c:/Users/asdmin/OneDrive/Desktop/Security-Code-Review/secure_admin_auth.js) introducing Node.js JWT tokens transmitted via `HttpOnly` secure cookies to safeguard the admin control panel.

---

## 5. Key Deliverables

To communicate these findings effectively to project stakeholders, we prepared two core documents:

*   **For Leadership / Security Teams:** The [Security Audit Report](file:///c:/Users/asdmin/OneDrive/Desktop/Security-Code-Review/security_audit_report.md) provides an executive overview, vulnerability tables, threat severity matrix, and proof-of-concept scenarios.
*   **For Developers:** The [Developer Remediation Guide](file:///c:/Users/asdmin/OneDrive/Desktop/Security-Code-Review/developer_remediation_communication.md) explains the vulnerabilities constructively, offering positive feedback, clear code comparisons, diffs, and best practices.

---

## 6. Conclusion: Shifting Security Left

This security code review highlights that **securing web applications requires proactive design rather than reactive filtering.** 

By manually analyzing control flow issues (such as redirects without exit) and template rendering patterns (such as `.innerHTML`), we can block complex attack vectors that simple automated scanners might miss. Furthermore, equipping developers with custom static analysis configurations (e.g. Semgrep rules) and constructive remediation communications helps build a collaborative security culture. 

Bridging the gap between security and engineering reduces code churn, secures whitelists and databases from stored threats, and ensures administrative modules are locked down prior to deployment.
