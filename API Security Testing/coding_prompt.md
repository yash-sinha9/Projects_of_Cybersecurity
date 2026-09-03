# API Security Testing Simulator - Coding Prompt

This document describes the instructions and specifications to build an interactive, frontend-only simulator for learning API Security Testing.

## Core Concepts to Demonstrate

1. **Broken Object Level Authorization (BOLA)**
   - **Vulnerable Scenario**: Users can query `/api/v1/orders?id=101` to view order details.
   - **Exploit**: Changing the `id` parameter to `102` or `103` reveals other users' orders because the backend fails to validate if the authenticated user owns the object.
   - **Remediation**: Validating object ownership before serving data.

2. **Mass Assignment / Parameter Tampering**
   - **Vulnerable Scenario**: Users update their profile using `PUT /api/v1/profile` with JSON `{"name": "Alice"}`.
   - **Exploit**: Injecting `{"role": "admin"}` or `{"is_premium": true}` into the JSON body updates administrative properties that should not be client-editable.
   - **Remediation**: Utilizing allow-lists or strict DTOs (Data Transfer Objects) for updating fields.

3. **Rate Limiting & API Key Exposure**
   - **Vulnerable Scenario**: `/api/v1/coupon-check` validates discount codes.
   - **Exploit 1 (Rate Limiting)**: Sending hundreds of automated requests to guess valid coupon codes because there is no rate limiting.
   - **Exploit 2 (API Key Exposure)**: The JavaScript console or static resources reveal a hardcoded high-privilege API key (e.g., `x-api-key: super-secret-admin-key-9988`) which grants bypass access.
   - **Remediation**: Rate limiting (IP/Token bucket) and moving secrets to environment configurations/backend.

4. **Simulated Security Tools (Postman & Burp Suite)**
   - A mock tool interface inside the web application showing:
     - **Request Composer**: Edit HTTP Method (GET, POST, PUT, DELETE), URL, Headers, and Request Body.
     - **Interception/Repeater mode**: Modify payloads mid-flight.
     - **Console Log**: Highlighting vulnerability discovery.

---

## UI/UX Specifications

- **Theme**: Sleek terminal/cybersecurity dashboard (deep dark space backgrounds, neon green/cyan borders, glowing alerts).
- **Navigation**: Sidebar listing the 4 challenges.
- **Workspace Panel**:
  - **Left Section**: Guided text explaining the vulnerability, instructions, and target objective.
  - **Middle Section**: Simulated HTTP Request Builder (Method, URL, Headers, JSON body) + Send Button.
  - **Right Section**: Real-time simulated Response Panel (Status Code, JSON output) + interactive database view showing what is happening inside the database.
- **Challenge Progress**: Automatic validation highlighting when the student successfully exploits or mitigates a vulnerability.
