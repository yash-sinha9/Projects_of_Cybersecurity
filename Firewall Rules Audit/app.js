/**
 * Firewall Rules Audit & Perimeter Defense Studio
 * Core Engine & Interactive UI Controller
 */

// Global App State
const state = {
  defaultPolicies: { INPUT: 'ACCEPT', FORWARD: 'ACCEPT', OUTPUT: 'ACCEPT' },
  rules: [],
  findings: [],
  shadowedRules: [],
  redundantRules: [],
  score: 45,
  grade: 'D',
  activeTab: 'tab-rules'
};

// Common sensitive ports database
const SENSITIVE_PORTS = {
  21: { name: 'FTP', risk: 'Unencrypted file transfer', severity: 'HIGH' },
  22: { name: 'SSH', risk: 'Remote shell administration', severity: 'CRITICAL' },
  23: { name: 'Telnet', risk: 'Plaintext remote terminal (credentials in cleartext)', severity: 'CRITICAL' },
  69: { name: 'TFTP', risk: 'Unauthenticated file transfer', severity: 'HIGH' },
  135: { name: 'RPC', risk: 'Windows RPC endpoint mapper', severity: 'HIGH' },
  139: { name: 'NetBIOS', risk: 'Legacy Windows file sharing', severity: 'HIGH' },
  445: { name: 'SMB', risk: 'Server Message Block (WannaCry / EternalBlue vector)', severity: 'CRITICAL' },
  1433: { name: 'MSSQL', risk: 'Microsoft SQL Server database', severity: 'CRITICAL' },
  1521: { name: 'Oracle', risk: 'Oracle Database Listener', severity: 'HIGH' },
  3306: { name: 'MySQL', risk: 'MySQL / MariaDB database exposed publicly', severity: 'CRITICAL' },
  3389: { name: 'RDP', risk: 'Windows Remote Desktop Protocol', severity: 'CRITICAL' },
  5432: { name: 'PostgreSQL', risk: 'PostgreSQL database exposed', severity: 'CRITICAL' },
  5900: { name: 'VNC', risk: 'Virtual Network Computing remote desktop', severity: 'HIGH' },
  6379: { name: 'Redis', risk: 'Redis in-memory cache (often unauthenticated)', severity: 'CRITICAL' },
  8080: { name: 'HTTP-Alt', risk: 'Alternate web / development console', severity: 'MEDIUM' },
  9200: { name: 'Elasticsearch', risk: 'Elasticsearch cluster API', severity: 'HIGH' },
  27017: { name: 'MongoDB', risk: 'MongoDB NoSQL database', severity: 'CRITICAL' }
};

// Preset Scenarios
const PRESETS = {
  vulnerable: {
    name: "Vulnerable Server",
    policies: { INPUT: 'ACCEPT', FORWARD: 'ACCEPT', OUTPUT: 'ACCEPT' },
    rules: [
      { chain: 'INPUT', action: 'ACCEPT', proto: 'all', src: '0.0.0.0/0', dst: '0.0.0.0/0', port: 'any', state: 'any', iface: 'lo', comment: 'Loopback' },
      { chain: 'INPUT', action: 'ACCEPT', proto: 'all', src: '0.0.0.0/0', dst: '0.0.0.0/0', port: 'any', state: 'RELATED,ESTABLISHED', iface: 'any', comment: 'Stateful' },
      { chain: 'INPUT', action: 'ACCEPT', proto: 'tcp', src: '0.0.0.0/0', dst: '0.0.0.0/0', port: '22', state: 'any', iface: 'any', comment: 'SSH wide open' },
      { chain: 'INPUT', action: 'ACCEPT', proto: 'tcp', src: '0.0.0.0/0', dst: '0.0.0.0/0', port: '23', state: 'any', iface: 'any', comment: 'Telnet cleartext open' },
      { chain: 'INPUT', action: 'ACCEPT', proto: 'tcp', src: '0.0.0.0/0', dst: '0.0.0.0/0', port: '80', state: 'any', iface: 'any', comment: 'HTTP Web' },
      { chain: 'INPUT', action: 'ACCEPT', proto: 'tcp', src: '0.0.0.0/0', dst: '0.0.0.0/0', port: '443', state: 'any', iface: 'any', comment: 'HTTPS Web' },
      { chain: 'INPUT', action: 'ACCEPT', proto: 'tcp', src: '0.0.0.0/0', dst: '0.0.0.0/0', port: '3306', state: 'any', iface: 'any', comment: 'MySQL DB exposed' },
      { chain: 'INPUT', action: 'ACCEPT', proto: 'tcp', src: '0.0.0.0/0', dst: '0.0.0.0/0', port: '6379', state: 'any', iface: 'any', comment: 'Redis exposed' },
      { chain: 'INPUT', action: 'DROP', proto: 'tcp', src: '198.51.100.50/32', dst: '0.0.0.0/0', port: '22', state: 'any', iface: 'any', comment: 'SHADOWED drop rule' },
      { chain: 'INPUT', action: 'ACCEPT', proto: 'tcp', src: '0.0.0.0/0', dst: '0.0.0.0/0', port: '80', state: 'any', iface: 'any', comment: 'REDUNDANT duplicate' },
      { chain: 'OUTPUT', action: 'ACCEPT', proto: 'all', src: '0.0.0.0/0', dst: '0.0.0.0/0', port: 'any', state: 'any', iface: 'any', comment: 'Unrestricted egress' }
    ]
  },
  hardened: {
    name: "CIS Hardened Bastion",
    policies: { INPUT: 'DROP', FORWARD: 'DROP', OUTPUT: 'DROP' },
    rules: [
      { chain: 'INPUT', action: 'ACCEPT', proto: 'all', src: '0.0.0.0/0', dst: '0.0.0.0/0', port: 'any', state: 'any', iface: 'lo', comment: 'Loopback allow' },
      { chain: 'OUTPUT', action: 'ACCEPT', proto: 'all', src: '0.0.0.0/0', dst: '0.0.0.0/0', port: 'any', state: 'any', iface: 'lo', comment: 'Loopback allow' },
      { chain: 'INPUT', action: 'ACCEPT', proto: 'all', src: '0.0.0.0/0', dst: '0.0.0.0/0', port: 'any', state: 'RELATED,ESTABLISHED', iface: 'any', comment: 'Stateful tracking' },
      { chain: 'OUTPUT', action: 'ACCEPT', proto: 'all', src: '0.0.0.0/0', dst: '0.0.0.0/0', port: 'any', state: 'RELATED,ESTABLISHED', iface: 'any', comment: 'Stateful tracking' },
      { chain: 'INPUT', action: 'DROP', proto: 'all', src: '0.0.0.0/0', dst: '0.0.0.0/0', port: 'any', state: 'INVALID', iface: 'any', comment: 'Drop invalid state' },
      { chain: 'INPUT', action: 'DROP', proto: 'all', src: '10.0.0.0/8', dst: '0.0.0.0/0', port: 'any', state: 'any', iface: 'eth0', comment: 'Anti-spoof RFC1918' },
      { chain: 'INPUT', action: 'DROP', proto: 'all', src: '192.168.0.0/16', dst: '0.0.0.0/0', port: 'any', state: 'any', iface: 'eth0', comment: 'Anti-spoof RFC1918' },
      { chain: 'INPUT', action: 'ACCEPT', proto: 'tcp', src: '10.200.10.0/24', dst: '0.0.0.0/0', port: '22', state: 'NEW', iface: 'any', comment: 'Restricted SSH bastion' },
      { chain: 'INPUT', action: 'ACCEPT', proto: 'tcp', src: '0.0.0.0/0', dst: '0.0.0.0/0', port: '443', state: 'NEW', iface: 'any', comment: 'Encrypted HTTPS' },
      { chain: 'OUTPUT', action: 'ACCEPT', proto: 'udp', src: '0.0.0.0/0', dst: '0.0.0.0/0', port: '53', state: 'any', iface: 'any', comment: 'Essential DNS egress' },
      { chain: 'OUTPUT', action: 'ACCEPT', proto: 'udp', src: '0.0.0.0/0', dst: '0.0.0.0/0', port: '123', state: 'any', iface: 'any', comment: 'Essential NTP egress' },
      { chain: 'INPUT', action: 'LOG', proto: 'all', src: '0.0.0.0/0', dst: '0.0.0.0/0', port: 'any', state: 'any', iface: 'any', comment: 'Log dropped packets' },
      { chain: 'INPUT', action: 'DROP', proto: 'all', src: '0.0.0.0/0', dst: '0.0.0.0/0', port: 'any', state: 'any', iface: 'any', comment: 'Explicit catch-all drop' }
    ]
  },
  dmz: {
    name: "Corporate DMZ",
    policies: { INPUT: 'DROP', FORWARD: 'DROP', OUTPUT: 'DROP' },
    rules: [
      { chain: 'INPUT', action: 'ACCEPT', proto: 'all', src: '0.0.0.0/0', dst: '0.0.0.0/0', port: 'any', state: 'any', iface: 'lo', comment: 'Loopback' },
      { chain: 'INPUT', action: 'ACCEPT', proto: 'all', src: '0.0.0.0/0', dst: '0.0.0.0/0', port: 'any', state: 'RELATED,ESTABLISHED', iface: 'any', comment: 'Stateful' },
      { chain: 'FORWARD', action: 'ACCEPT', proto: 'all', src: '0.0.0.0/0', dst: '0.0.0.0/0', port: 'any', state: 'RELATED,ESTABLISHED', iface: 'any', comment: 'Forward stateful' },
      { chain: 'FORWARD', action: 'ACCEPT', proto: 'tcp', src: '0.0.0.0/0', dst: '172.16.1.10/32', port: '443', state: 'any', iface: 'eth0', comment: 'WAN to DMZ Web' },
      { chain: 'FORWARD', action: 'ACCEPT', proto: 'tcp', src: '172.16.1.10/32', dst: '10.10.50.20/32', port: '8443', state: 'any', iface: 'eth1', comment: 'DMZ to App Tier' },
      { chain: 'INPUT', action: 'ACCEPT', proto: 'tcp', src: '10.10.1.5/32', dst: '0.0.0.0/0', port: '22', state: 'any', iface: 'eth2', comment: 'Jumpbox management' },
      { chain: 'OUTPUT', action: 'ACCEPT', proto: 'udp', src: '0.0.0.0/0', dst: '8.8.8.8/32', port: '53', state: 'any', iface: 'any', comment: 'Google DNS' }
    ]
  },
  blank: {
    name: "Empty / Custom",
    policies: { INPUT: 'ACCEPT', FORWARD: 'ACCEPT', OUTPUT: 'ACCEPT' },
    rules: []
  }
};

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
  setupEventListeners();
  loadScenario('vulnerable');
  generateScript();
});

// Setup DOM Event Listeners
function setupEventListeners() {
  // Tab Switching
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      switchTab(targetTab);
    });
  });

  // Scenario Selector
  const scenarioSelect = document.getElementById('scenarioSelect');
  if (scenarioSelect) {
    scenarioSelect.addEventListener('change', (e) => {
      loadScenario(e.target.value);
    });
  }

  // Action Buttons
  document.getElementById('btnRunAudit')?.addEventListener('click', () => {
    runSecurityAudit();
    showToast('Security audit re-evaluated successfully');
  });

  document.getElementById('btnImport')?.addEventListener('click', () => {
    openModal('importModal');
  });

  document.getElementById('btnSubmitImport')?.addEventListener('click', handleImportRules);

  document.getElementById('btnAddRule')?.addEventListener('click', () => {
    document.getElementById('ruleModalTitle').textContent = 'Add New Firewall Rule';
    document.getElementById('editRuleIndex').value = '-1';
    document.getElementById('ruleForm').reset();
    document.getElementById('ruleSrc').value = '0.0.0.0/0';
    document.getElementById('ruleDst').value = '0.0.0.0/0';
    openModal('ruleModal');
  });

  document.getElementById('btnSaveRule')?.addEventListener('click', handleSaveRule);

  // Filters
  document.getElementById('filterChain')?.addEventListener('change', renderRulesTable);
  document.getElementById('filterAction')?.addEventListener('change', renderRulesTable);

  // Packet Simulator Form
  document.getElementById('packetForm')?.addEventListener('submit', (e) => {
    e.preventDefault();
    simulatePacket();
  });

  // Auto-Fix Shadow Rule button
  document.getElementById('btnAutoFixShadow')?.addEventListener('click', autoFixShadowRules);

  // Script Generator Controls
  document.getElementById('btnGenerateScript')?.addEventListener('click', generateScript);
  document.getElementById('genProfile')?.addEventListener('change', generateScript);
  document.getElementById('btnCopyScript')?.addEventListener('click', copyScriptToClipboard);
  document.getElementById('btnDownloadScript')?.addEventListener('click', downloadScriptFile);

  // Export Buttons
  document.getElementById('btnExportJson')?.addEventListener('click', exportJsonReport);
  document.getElementById('btnExportMarkdown')?.addEventListener('click', exportMarkdownReport);
  document.getElementById('btnPrintReport')?.addEventListener('click', () => window.print());
}

// Tab Switching Helper
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

  const activeBtn = document.querySelector(`.tab-btn[data-tab="${tabId}"]`);
  const activePane = document.getElementById(tabId);

  if (activeBtn) activeBtn.classList.add('active');
  if (activePane) activePane.classList.add('active');
  state.activeTab = tabId;
}

// Load Scenario
function loadScenario(presetKey) {
  const preset = PRESETS[presetKey] || PRESETS.vulnerable;
  state.defaultPolicies = { ...preset.policies };
  state.rules = JSON.parse(JSON.stringify(preset.rules));
  runSecurityAudit();
  generateScript();
  showToast(`Loaded scenario: ${preset.name}`);
}

// Parse Raw iptables Input
function handleImportRules() {
  const text = document.getElementById('importTextarea').value;
  if (!text.trim()) {
    showToast('Please paste valid iptables rules');
    return;
  }

  const lines = text.split('\n');
  const newRules = [];
  const policies = { INPUT: 'ACCEPT', FORWARD: 'ACCEPT', OUTPUT: 'ACCEPT' };

  lines.forEach((line) => {
    const clean = line.trim();
    if (!clean || clean.startsWith('#')) return;

    // Default policy :INPUT DROP [0:0]
    if (clean.startsWith(':')) {
      const parts = clean.split(/\s+/);
      const chain = parts[0].substring(1).toUpperCase();
      const pol = parts[1].toUpperCase();
      if (policies[chain] !== undefined) {
        policies[chain] = pol;
      }
      return;
    }

    // iptables -A ... or -A ...
    if (clean.includes('-A ') || clean.includes('--append ')) {
      const rule = parseIptablesLine(clean);
      if (rule) newRules.push(rule);
    }
  });

  state.defaultPolicies = policies;
  state.rules = newRules;
  closeModal('importModal');
  runSecurityAudit();
  generateScript();
  showToast(`Successfully parsed ${newRules.length} rules!`);
}

// Parse single iptables line into normalized rule object
function parseIptablesLine(line) {
  const tokens = line.split(/\s+/);
  const rule = {
    chain: 'INPUT',
    action: 'ACCEPT',
    proto: 'all',
    src: '0.0.0.0/0',
    dst: '0.0.0.0/0',
    port: 'any',
    state: 'any',
    iface: 'any',
    comment: ''
  };

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if ((t === '-A' || t === '--append') && tokens[i + 1]) {
      rule.chain = tokens[i + 1].toUpperCase();
      i++;
    } else if ((t === '-j' || t === '--jump') && tokens[i + 1]) {
      rule.action = tokens[i + 1].toUpperCase();
      i++;
    } else if ((t === '-p' || t === '--protocol') && tokens[i + 1]) {
      rule.proto = tokens[i + 1].toLowerCase();
      i++;
    } else if ((t === '-s' || t === '--source') && tokens[i + 1]) {
      rule.src = tokens[i + 1];
      if (!rule.src.includes('/') && rule.src !== '0.0.0.0/0') rule.src += '/32';
      i++;
    } else if ((t === '-d' || t === '--destination') && tokens[i + 1]) {
      rule.dst = tokens[i + 1];
      if (!rule.dst.includes('/') && rule.dst !== '0.0.0.0/0') rule.dst += '/32';
      i++;
    } else if ((t === '--dport' || t === '--destination-port') && tokens[i + 1]) {
      rule.port = tokens[i + 1];
      i++;
    } else if ((t === '-i' || t === '--in-interface') && tokens[i + 1]) {
      rule.iface = tokens[i + 1];
      i++;
    } else if ((t === '--ctstate' || t === '--state') && tokens[i + 1]) {
      rule.state = tokens[i + 1].toUpperCase();
      i++;
    }
  }

  return rule;
}

// Add or Edit Rule Save
function handleSaveRule(e) {
  e.preventDefault();
  const editIdx = parseInt(document.getElementById('editRuleIndex').value, 10);
  const chain = document.getElementById('ruleChain').value;
  const action = document.getElementById('ruleAction').value;
  const proto = document.getElementById('ruleProto').value;
  const port = document.getElementById('rulePort').value.trim() || 'any';
  let src = document.getElementById('ruleSrc').value.trim() || '0.0.0.0/0';
  let dst = document.getElementById('ruleDst').value.trim() || '0.0.0.0/0';
  const stateVal = document.getElementById('ruleState').value;
  const iface = document.getElementById('ruleInterface').value.trim() || 'any';

  if (!src.includes('/') && src !== '0.0.0.0/0') src += '/32';
  if (!dst.includes('/') && dst !== '0.0.0.0/0') dst += '/32';

  const newRule = {
    chain,
    action,
    proto,
    port,
    src,
    dst,
    state: stateVal,
    iface,
    comment: 'Custom configured rule'
  };

  if (editIdx >= 0 && editIdx < state.rules.length) {
    state.rules[editIdx] = newRule;
    showToast(`Rule #${editIdx + 1} updated`);
  } else {
    state.rules.push(newRule);
    showToast('New rule added to chain');
  }

  closeModal('ruleModal');
  runSecurityAudit();
}

// Move Rule Up or Down
function moveRule(index, direction) {
  const target = index + direction;
  if (target < 0 || target >= state.rules.length) return;
  const temp = state.rules[index];
  state.rules[index] = state.rules[target];
  state.rules[target] = temp;
  runSecurityAudit();
  showToast(`Reordered Rule #${index + 1} with Rule #${target + 1}`);
}

// Delete Rule
function deleteRule(index) {
  if (confirm(`Are you sure you want to delete Rule #${index + 1}?`)) {
    state.rules.splice(index, 1);
    runSecurityAudit();
    showToast(`Rule deleted`);
  }
}

// Edit Rule (open modal with data)
function openEditRule(index) {
  const r = state.rules[index];
  if (!r) return;
  document.getElementById('ruleModalTitle').textContent = `Edit Rule #${index + 1}`;
  document.getElementById('editRuleIndex').value = index;
  document.getElementById('ruleChain').value = r.chain;
  document.getElementById('ruleAction').value = r.action;
  document.getElementById('ruleProto').value = r.proto;
  document.getElementById('rulePort').value = r.port === 'any' ? '' : r.port;
  document.getElementById('ruleSrc').value = r.src;
  document.getElementById('ruleDst').value = r.dst;
  document.getElementById('ruleState').value = r.state;
  document.getElementById('ruleInterface').value = r.iface === 'any' ? '' : r.iface;
  openModal('ruleModal');
}

// ==========================================================================
// CORE AUDIT & GAP ANALYSIS ENGINE
// ==========================================================================
function runSecurityAudit() {
  state.findings = [];
  state.shadowedRules = [];
  state.redundantRules = [];
  let score = 100;

  // 1. Audit Default Policies
  for (const [chain, pol] of Object.entries(state.defaultPolicies)) {
    if (pol === 'ACCEPT') {
      const isIngress = chain === 'INPUT' || chain === 'FORWARD';
      const penalty = isIngress ? 20 : 10;
      score -= penalty;
      state.findings.push({
        id: `DEF-POL-${chain}`,
        severity: isIngress ? 'CRITICAL' : 'MEDIUM',
        title: `Insecure Default Policy on ${chain} Chain`,
        detail: `The default policy for chain ${chain} is set to ACCEPT. If no specific rule matches incoming packets, they are admitted by default, violating Zero-Trust perimeter design.`,
        remediation: `iptables -P ${chain} DROP`,
        framework: 'CIS Benchmark 3.4.1 / PCI-DSS 1.2'
      });
    }
  }

  // 2. Audit Loopback Interface
  const hasLoopback = state.rules.some(r =>
    r.chain === 'INPUT' && (r.iface === 'lo' || r.src === '127.0.0.1/32') && r.action === 'ACCEPT'
  );
  if (!hasLoopback && state.defaultPolicies.INPUT === 'DROP') {
    score -= 10;
    state.findings.push({
      id: 'SYS-LOOPBACK-MISSING',
      severity: 'HIGH',
      title: 'Missing Local Loopback (lo) Acceptance',
      detail: 'No rule permits localhost loopback traffic. If default policy is DROP, internal Linux daemons, systemd-resolved, and IPC sockets will fail.',
      remediation: 'iptables -A INPUT -i lo -j ACCEPT && iptables -A OUTPUT -o lo -j ACCEPT',
      framework: 'CIS Benchmark 3.4.2'
    });
  }

  // 3. Audit Stateful Connection Tracking
  const hasStateful = state.rules.some(r =>
    r.state && r.state.includes('ESTABLISHED') && r.action === 'ACCEPT'
  );
  if (!hasStateful) {
    score -= 15;
    state.findings.push({
      id: 'NET-STATEFUL-MISSING',
      severity: 'HIGH',
      title: 'Missing Stateful Connection Tracking (conntrack)',
      detail: 'No stateful inspection rule (ctstate RELATED,ESTABLISHED) was detected. Outbound request return packets may be unexpectedly dropped.',
      remediation: 'iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
      framework: 'NIST SP 800-41 Rev 2'
    });
  }

  // 4. Audit Unrestricted Egress
  if (state.defaultPolicies.OUTPUT === 'ACCEPT') {
    const hasOutboundDrops = state.rules.some(r => r.chain === 'OUTPUT' && (r.action === 'DROP' || r.action === 'REJECT'));
    if (!hasOutboundDrops) {
      score -= 10;
      state.findings.push({
        id: 'NET-LOOSE-EGRESS',
        severity: 'MEDIUM',
        title: 'Unrestricted Outbound Egress Traffic',
        detail: 'The OUTPUT chain allows arbitrary egress to any destination on any port. If an adversary compromises a web service, reverse shells and data exfiltration cannot be restrained.',
        remediation: 'Set OUTPUT policy to DROP and explicitly whitelist ports 53 (DNS), 123 (NTP), and 443 (HTTPS).',
        framework: 'MITRE ATT&CK T1071 / PCI-DSS 1.3'
      });
    }
  }

  // 5. Per-Rule Analysis & Shadow Detection
  state.rules.forEach((rule, idx) => {
    // Check for exposed sensitive ports to 0.0.0.0/0
    if (rule.action === 'ACCEPT' && (rule.src === '0.0.0.0/0' || rule.src === 'any')) {
      const portNum = parseInt(rule.port, 10);
      if (SENSITIVE_PORTS[portNum]) {
        const info = SENSITIVE_PORTS[portNum];
        const penalty = info.severity === 'CRITICAL' ? 15 : 8;
        score -= penalty;
        state.findings.push({
          id: `EXP-PORT-${portNum}-R${idx + 1}`,
          severity: info.severity,
          title: `Overly Permissive Access to ${info.name} (Port ${portNum})`,
          detail: `Rule #${idx + 1} allows unrestricted ingress from 0.0.0.0/0 (the entire Internet) to port ${portNum} (${info.risk}).`,
          remediation: `iptables -R ${rule.chain} ${idx + 1} -s <TRUSTED_MANAGEMENT_SUBNET> -p ${rule.proto} --dport ${portNum} -j ACCEPT`,
          framework: 'NIST SP 800-41 / OWASP Top 10'
        });
      }

      // Cleartext protocols alert
      if (portNum === 23) {
        score -= 10;
        state.findings.push({
          id: `CLEARTEXT-TELNET-R${idx + 1}`,
          severity: 'CRITICAL',
          title: 'Unencrypted Telnet (Port 23) Permitted',
          detail: `Rule #${idx + 1} permits Telnet access. Telnet transmits usernames, passwords, and shell sessions across the network in cleartext without encryption.`,
          remediation: 'Disable Telnet immediately and migrate strictly to OpenSSH with Ed25519 public keys.',
          framework: 'PCI-DSS Req 4.1'
        });
      }
    }

    // Shadow & Redundancy Detection
    for (let pIdx = 0; pIdx < idx; pIdx++) {
      const prior = state.rules[pIdx];
      if (isRuleSubsumed(rule, prior)) {
        if (prior.action === rule.action) {
          // Redundant / duplicate rule
          state.redundantRules.push({
            ruleIndex: idx,
            priorIndex: pIdx,
            detail: `Rule #${idx + 1} is redundant with Rule #${pIdx + 1}`
          });
        } else {
          // SHADOWED rule! First-match-wins order error
          score -= 12;
          const shadowObj = {
            shadowedIndex: idx,
            priorIndex: pIdx,
            rule,
            prior,
            detail: `Rule #${idx + 1} (${rule.action} from ${rule.src}) is SHADOWED by Rule #${pIdx + 1} (${prior.action} from ${prior.src} on port ${prior.port}) and will NEVER execute!`
          };
          state.shadowedRules.push(shadowObj);
          state.findings.push({
            id: `SHADOW-R${idx + 1}`,
            severity: 'HIGH',
            title: `Shadowed / Dead Rule Detected (Rule #${idx + 1})`,
            detail: shadowObj.detail,
            remediation: `Move the specific rule #${idx + 1} ABOVE rule #${pIdx + 1} using iptables -I.`,
            framework: 'Firewall Policy Optimization / NIST SP 800-41'
          });
        }
        break;
      }
    }
  });

  state.score = Math.max(0, Math.min(100, score));
  state.grade = calculateGrade(state.score);

  // Update UI Displays
  updateDashboardUI();
  renderRulesTable();
  renderFindingsList();
}

// IP & Subnet Subsumption Check
function isIpSubsumed(subIp, superIp) {
  if (superIp === '0.0.0.0/0' || superIp === 'any') return true;
  if (subIp === '0.0.0.0/0' || subIp === 'any') return false;
  if (subIp === superIp) return true;

  // Simple CIDR logic
  const [subAddr, subMask] = subIp.includes('/') ? subIp.split('/') : [subIp, '32'];
  const [superAddr, superMask] = superIp.includes('/') ? superIp.split('/') : [superIp, '32'];

  if (parseInt(subMask, 10) < parseInt(superMask, 10)) return false;

  // Check prefix match
  const subBin = ipToBinary(subAddr);
  const superBin = ipToBinary(superAddr);
  if (subBin && superBin) {
    return subBin.startsWith(superBin.substring(0, parseInt(superMask, 10)));
  }
  return false;
}

function ipToBinary(ip) {
  try {
    const octets = ip.split('.').map(Number);
    if (octets.length !== 4 || octets.some(o => isNaN(o) || o < 0 || o > 255)) return null;
    return octets.map(o => o.toString(2).padStart(8, '0')).join('');
  } catch (e) {
    return null;
  }
}

// Rule Subsumption Logic
function isRuleSubsumed(candidate, earlier) {
  if (candidate.chain !== earlier.chain) return false;
  if (earlier.proto !== 'all' && earlier.proto !== candidate.proto) return false;
  if (earlier.iface !== 'any' && earlier.iface !== candidate.iface) return false;
  if (!isIpSubsumed(candidate.src, earlier.src)) return false;
  if (!isIpSubsumed(candidate.dst, earlier.dst)) return false;
  if (earlier.port !== 'any' && earlier.port !== candidate.port) return false;
  if (earlier.state !== 'any' && earlier.state !== candidate.state) return false;
  return true;
}

function calculateGrade(score) {
  if (score >= 95) return 'A+';
  if (score >= 85) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 45) return 'D';
  return 'F';
}

// ==========================================================================
// UI RENDERING FUNCTIONS
// ==========================================================================

function updateDashboardUI() {
  // Score Ring
  const scoreVal = document.getElementById('scoreValue');
  const scoreGrade = document.getElementById('scoreGrade');
  const scoreHeadline = document.getElementById('scoreStatusHeadline');
  const scoreDesc = document.getElementById('scoreStatusDesc');
  const ringProgress = document.getElementById('scoreRingProgress');

  if (scoreVal) scoreVal.textContent = state.score;
  if (scoreGrade) {
    scoreGrade.textContent = `Grade: ${state.grade}`;
    scoreGrade.className = `badge ${state.score >= 80 ? 'badge-success' : state.score >= 60 ? 'badge-warning' : 'badge-critical'}`;
  }

  if (ringProgress) {
    const circumference = 2 * Math.PI * 50; // ~314.16
    const offset = circumference - (state.score / 100) * circumference;
    ringProgress.style.strokeDashoffset = offset;
    ringProgress.style.stroke = state.score >= 80 ? 'var(--color-success)' : state.score >= 60 ? 'var(--color-warning)' : 'var(--color-critical)';
  }

  if (scoreHeadline) {
    if (state.score >= 85) {
      scoreHeadline.textContent = 'Hardened Perimeter Posture';
      scoreDesc.textContent = 'Strong zero-trust ruleset with default drops & stateful protection.';
    } else if (state.score >= 65) {
      scoreHeadline.textContent = 'Moderate Security Posture';
      scoreDesc.textContent = 'Perimeter active but some permissive ports or policies detected.';
    } else {
      scoreHeadline.textContent = 'High Perimeter Risk Detected';
      scoreDesc.textContent = 'Overly permissive rules or shadowed allow/deny conflicts present.';
    }
  }

  // Default Policies Chips
  const polContainer = document.getElementById('defaultPoliciesDisplay');
  if (polContainer) {
    polContainer.innerHTML = Object.entries(state.defaultPolicies).map(([chain, pol]) => {
      const cls = pol === 'DROP' ? 'chip-success' : 'chip-danger';
      return `<div class="policy-chip ${cls}"><span class="chip-name">${chain}:</span> <b>${pol}</b></div>`;
    }).join('');
  }

  // Findings Counter
  const critCount = state.findings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = state.findings.filter(f => f.severity === 'HIGH').length;
  const medCount = state.findings.filter(f => f.severity === 'MEDIUM').length;

  document.getElementById('statCriticalFindings').textContent = state.findings.length;
  document.getElementById('statCritSub').textContent = `${critCount} Critical`;
  document.getElementById('statHighSub').textContent = `${highCount} High`;
  document.getElementById('statMedSub').textContent = `${medCount} Medium`;

  // Shadow Counter
  document.getElementById('statShadowCount').textContent = state.shadowedRules.length;
  document.getElementById('statShadowSub').textContent = `${state.shadowedRules.length} Shadowed`;
  document.getElementById('statRedundantSub').textContent = `${state.redundantRules.length} Duplicate`;

  // Badges in Tabs
  document.getElementById('ruleCountBadge').textContent = state.rules.length;
  document.getElementById('findingsCountBadge').textContent = state.findings.length;

  // Shadow Alert in Tab 2
  const shadowBox = document.getElementById('shadowAlertBox');
  const shadowText = document.getElementById('shadowAlertText');
  if (state.shadowedRules.length > 0) {
    shadowBox.style.display = 'flex';
    shadowText.textContent = state.shadowedRules[0].detail;
  } else {
    shadowBox.style.display = 'none';
  }

  // Compliance Progress Bar
  const cisPassPct = Math.round((Math.max(0, state.score - 20) / 80) * 100);
  const cisBar = document.getElementById('cisProgressBar');
  const cisBadge = document.getElementById('cisStatusBadge');
  if (cisBar) {
    cisBar.style.width = `${cisPassPct}%`;
    cisBar.className = `progress-bar ${cisPassPct >= 80 ? 'bg-success' : cisPassPct >= 50 ? 'bg-warning' : 'bg-critical'}`;
  }
  if (cisBadge) {
    cisBadge.textContent = `${cisPassPct}% Pass`;
    cisBadge.className = `badge ${cisPassPct >= 80 ? 'badge-success' : cisPassPct >= 50 ? 'badge-warning' : 'badge-critical'}`;
  }
}

// Render Tab 1 Rules Table
function renderRulesTable() {
  const tbody = document.getElementById('rulesTableBody');
  if (!tbody) return;

  const chainFilter = document.getElementById('filterChain')?.value || 'ALL';
  const actionFilter = document.getElementById('filterAction')?.value || 'ALL';

  tbody.innerHTML = '';

  state.rules.forEach((rule, idx) => {
    if (chainFilter !== 'ALL' && rule.chain !== chainFilter) return;
    if (actionFilter !== 'ALL' && rule.action !== actionFilter) return;

    const isShadowed = state.shadowedRules.some(s => s.shadowedIndex === idx);
    const isRedundant = state.redundantRules.some(r => r.ruleIndex === idx);

    const tr = document.createElement('tr');
    if (isShadowed) tr.className = 'row-shadowed';
    if (isRedundant) tr.className = 'row-redundant';

    let statusHtml = '<span class="badge badge-subtle">Active</span>';
    if (isShadowed) {
      statusHtml = '<span class="badge badge-critical" title="Rule never executes">SHADOWED</span>';
    } else if (isRedundant) {
      statusHtml = '<span class="badge badge-warning" title="Duplicate rule">REDUNDANT</span>';
    }

    const actionClass = rule.action === 'ACCEPT' ? 'action-accept' : (rule.action === 'DROP' ? 'action-drop' : (rule.action === 'REJECT' ? 'action-reject' : 'action-log'));

    tr.innerHTML = `
      <td class="font-mono text-muted">${idx + 1}</td>
      <td><span class="badge badge-subtle font-mono">${rule.chain}</span></td>
      <td><span class="action-badge ${actionClass}">${rule.action}</span></td>
      <td class="font-mono text-xs uppercase">${rule.proto}</td>
      <td class="font-mono text-xs">${rule.src}</td>
      <td class="font-mono text-xs">${rule.dst}</td>
      <td class="font-mono text-xs">${rule.port === 'any' ? '<span class="text-subtle">any</span>' : `<b>${rule.port}</b>`}</td>
      <td class="font-mono text-xs text-subtle">${rule.state === 'any' ? '-' : rule.state}</td>
      <td>${statusHtml}</td>
      <td class="text-right">
        <div class="rule-controls">
          <button class="btn-icon" title="Move Up" onclick="moveRule(${idx}, -1)" ${idx === 0 ? 'disabled' : ''}>▲</button>
          <button class="btn-icon" title="Move Down" onclick="moveRule(${idx}, 1)" ${idx === state.rules.length - 1 ? 'disabled' : ''}>▼</button>
          <button class="btn-icon" title="Edit Rule" onclick="openEditRule(${idx})">✎</button>
          <button class="btn-icon danger" title="Delete Rule" onclick="deleteRule(${idx})">🗑</button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

// Render Tab 2 Findings List
function renderFindingsList() {
  const container = document.getElementById('findingsContainer');
  if (!container) return;

  const countEl = document.getElementById('findingStatsText');
  if (countEl) countEl.textContent = `Showing ${state.findings.length} findings`;

  if (state.findings.length === 0) {
    container.innerHTML = `
      <div class="finding-card text-center" style="padding: 40px;">
        <span style="font-size: 2rem;">🛡️</span>
        <h3 class="text-success mt-4">Clean Firewall Perimeter!</h3>
        <p class="text-muted text-sm">No critical gaps, shadowed rules, or compliance violations detected.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = state.findings.map(f => {
    const badgeClass = f.severity === 'CRITICAL' ? 'badge-critical' : (f.severity === 'HIGH' ? 'badge-warning' : 'badge-accent');
    return `
      <div class="finding-card">
        <div class="finding-header">
          <div class="finding-title-group">
            <span class="badge ${badgeClass}">${f.severity}</span>
            <h4 class="finding-title">${f.title}</h4>
          </div>
          <span class="finding-meta">${f.framework}</span>
        </div>
        <p class="finding-desc">${f.detail}</p>
        <div class="remediation-box">
          <div class="remediation-label">Remediation Command / Guidance</div>
          <code class="remediation-code">${f.remediation}</code>
        </div>
      </div>
    `;
  }).join('');
}

// Auto-fix shadowed rules by reordering
function autoFixShadowRules() {
  if (state.shadowedRules.length === 0) {
    showToast('No shadowed rules to fix');
    return;
  }

  state.shadowedRules.forEach(sh => {
    const shadowIdx = sh.shadowedIndex;
    const priorIdx = sh.priorIndex;
    if (shadowIdx > priorIdx) {
      const shadowedRule = state.rules.splice(shadowIdx, 1)[0];
      state.rules.splice(priorIdx, 0, shadowedRule);
    }
  });

  runSecurityAudit();
  renderRulesTable();
  showToast('Reordered rules! Shadowed drop rules moved ahead of broad allow rules.');
}

// ==========================================================================
// TAB 3: PACKET TRACER SIMULATOR
// ==========================================================================

function setPacketPort(port, proto) {
  document.getElementById('pktPort').value = port;
  document.getElementById('pktProto').value = proto;
}

function setPacketField(fieldId, value) {
  const el = document.getElementById(fieldId);
  if (el) el.value = value;
}

function simulatePacket() {
  const chain = document.getElementById('pktChain').value;
  const srcIp = document.getElementById('pktSrcIp').value.trim() || '198.51.100.50';
  const dstIp = document.getElementById('pktDstIp').value.trim() || '10.0.0.5';
  const proto = document.getElementById('pktProto').value.toLowerCase();
  const port = parseInt(document.getElementById('pktPort').value.trim() || '80', 10);

  const traceSteps = [];
  let verdict = state.defaultPolicies[chain] || 'DROP';
  let matchedRule = null;
  let matchedStepIndex = -1;

  for (let idx = 0; idx < state.rules.length; idx++) {
    const r = state.rules[idx];
    if (r.chain !== chain) continue;

    let match = true;
    const missReasons = [];

    // Protocol check
    if (r.proto !== 'all' && r.proto !== proto) {
      match = false;
      missReasons.push(`Protocol mismatch (${proto} != ${r.proto})`);
    }

    // Port check
    if (match && r.port !== 'any') {
      const rPort = parseInt(r.port, 10);
      if (rPort !== port) {
        match = false;
        missReasons.push(`Port mismatch (${port} != ${r.port})`);
      }
    }

    // Source IP match
    if (match && r.src !== '0.0.0.0/0' && r.src !== 'any') {
      if (!isIpSubsumed(srcIp + '/32', r.src)) {
        match = false;
        missReasons.push(`Source IP ${srcIp} not in ${r.src}`);
      }
    }

    // Destination IP match
    if (match && r.dst !== '0.0.0.0/0' && r.dst !== 'any') {
      if (!isIpSubsumed(dstIp + '/32', r.dst)) {
        match = false;
        missReasons.push(`Destination IP ${dstIp} not in ${r.dst}`);
      }
    }

    const step = {
      ruleNum: idx + 1,
      rule: r,
      match,
      reason: match ? 'All packet header criteria satisfied' : missReasons.join('; ')
    };
    traceSteps.push(step);

    if (match) {
      verdict = r.action;
      matchedRule = r;
      matchedStepIndex = traceSteps.length - 1;
      break; // First-match-wins! Stop evaluating further rules!
    }
  }

  // Render Verdict Banner
  const banner = document.getElementById('simVerdictBanner');
  const headline = document.getElementById('verdictHeadline');
  const subtext = document.getElementById('verdictSubtext');

  const isAccept = verdict === 'ACCEPT';
  banner.className = `verdict-banner ${isAccept ? 'verdict-accept' : 'verdict-drop'}`;
  banner.querySelector('.verdict-icon').textContent = isAccept ? '✔' : '✖';
  headline.textContent = isAccept ? `TRAFFIC ALLOWED (${verdict})` : `TRAFFIC BLOCKED (${verdict})`;

  if (matchedRule) {
    subtext.textContent = `Packet matched Rule #${traceSteps[matchedStepIndex].ruleNum} on ${chain} chain. First-match-wins terminated traversal.`;
  } else {
    subtext.textContent = `Packet traversed all rules without a match. Fallback to Chain Default Policy: [${verdict}].`;
  }

  // Render Trace Steps
  const traceContainer = document.getElementById('traceStepsContainer');
  traceContainer.innerHTML = traceSteps.map((step, idx) => {
    const isHit = step.match;
    const badgeClass = isHit ? 'step-hit-badge' : 'step-miss-badge';
    return `
      <div class="trace-step ${isHit ? 'hit' : 'miss'}">
        <span class="step-badge ${badgeClass}">${isHit ? 'MATCH' : 'SKIP'}</span>
        <div class="step-content">
          <div class="step-rule-code">
            Rule #${step.ruleNum} [${step.rule.chain}]: -p ${step.rule.proto} -s ${step.rule.src} -d ${step.rule.dst} --dport ${step.rule.port} -j ${step.rule.action}
          </div>
          <div class="step-reason">${step.reason}</div>
        </div>
      </div>
    `;
  }).join('');
}

// ==========================================================================
// TAB 4: SCRIPT GENERATOR
// ==========================================================================

function generateScript() {
  const profile = document.getElementById('genProfile')?.value || 'hardened_bastion';
  const adminSubnet = document.getElementById('genAdminSubnet')?.value.trim() || '10.200.10.0/24';
  const chkRateLimit = document.getElementById('chkRateLimit')?.checked ?? true;
  const chkAntiSpoof = document.getElementById('chkAntiSpoof')?.checked ?? true;
  const chkLogDrops = document.getElementById('chkLogDrops')?.checked ?? true;
  const chkDefaultDrop = document.getElementById('chkDefaultDrop')?.checked ?? true;

  let script = `#!/bin/bash
# ==============================================================================
# Linux iptables Hardened Perimeter Configuration
# Generated by Firewall Rules Audit & Perimeter Defense Studio
# Standard: CIS Linux Benchmark 3.4 / PCI-DSS Req 1.2 / NIST SP 800-41
# Generated Date: ${new Date().toISOString()}
# ==============================================================================

set -euo pipefail

echo "[*] Initializing Firewall Hardening..."

# 1. Flush existing rules and delete user-defined chains
iptables -F
iptables -X
iptables -t nat -F || true
iptables -t mangle -F || true

`;

  if (chkDefaultDrop) {
    script += `# 2. Enforce Zero-Trust Default Policies (Drop all by default)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP
echo "[+] Default DROP policies applied."

`;
  } else {
    script += `# 2. Default Policies
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

`;
  }

  script += `# 3. Allow Loopback (Localhost IPC and system daemons)
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# 4. Stateful Inspection: Allow established and related return traffic
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# 5. Drop Invalid Connection States
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

`;

  if (chkAntiSpoof) {
    script += `# 6. Anti-Spoofing: Drop private RFC1918 addresses on external interface (eth0)
iptables -A INPUT -i eth0 -s 10.0.0.0/8 -j DROP
iptables -A INPUT -i eth0 -s 172.16.0.0/12 -j DROP
iptables -A INPUT -i eth0 -s 192.168.0.0/16 -j DROP
iptables -A INPUT -i eth0 -s 127.0.0.0/8 -j DROP
echo "[+] Bogon & anti-spoofing filters active."

`;
  }

  if (chkRateLimit) {
    script += `# 7. Rate Limiting: Mitigate SYN Floods and Ping Floods
iptables -A INPUT -p tcp --syn -m limit --limit 25/s --limit-burst 50 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 4 -j ACCEPT
iptables -A INPUT -p icmp -j DROP
echo "[+] DoS / SYN flood rate limiting active."

`;
  }

  if (profile === 'hardened_bastion') {
    script += `# 8. Restricted Administrative SSH (Port 22) - Whitelist Only
iptables -A INPUT -s ${adminSubnet} -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
echo "[+] SSH restricted exclusively to management subnet ${adminSubnet}"

# 9. Outbound DNS & NTP for time synchronization & package updates
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

`;
  } else if (profile === 'secure_web') {
    script += `# 8. Inbound Web Services (HTTP/HTTPS)
iptables -A INPUT -p tcp -m tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# Restrict SSH to Admin Subnet
iptables -A INPUT -s ${adminSubnet} -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT

# Outbound DNS & Package Updates
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

`;
  } else if (profile === 'isolated_db') {
    script += `# 8. Isolated Database Port: Whitelist Internal App Servers Only
iptables -A INPUT -s ${adminSubnet} -p tcp -m tcp --dport 3306 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -s ${adminSubnet} -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT

`;
  }

  if (chkLogDrops) {
    script += `# 10. Audit Logging: Log dropped packets with rate limit before final drop
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "FW_INPUT_DROP: " --log-level 4
iptables -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "FW_FORWARD_DROP: " --log-level 4
`;
  }

  script += `
echo "[✔] Firewall hardening applied successfully."
# Save rules persistently
# Debian/Ubuntu: netfilter-persistent save
# RHEL/CentOS: iptables-save > /etc/sysconfig/iptables
`;

  const codeEl = document.getElementById('generatedScriptBlock');
  if (codeEl) codeEl.textContent = script;
}

function copyScriptToClipboard() {
  const code = document.getElementById('generatedScriptBlock')?.textContent;
  if (code) {
    navigator.clipboard.writeText(code).then(() => {
      showToast('Hardening script copied to clipboard!');
    });
  }
}

function downloadScriptFile() {
  const code = document.getElementById('generatedScriptBlock')?.textContent;
  if (!code) return;
  const blob = new Blob([code], { type: 'text/x-sh' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'firewall-harden.sh';
  a.click();
  URL.revokeObjectURL(url);
}

// ==========================================================================
// EXPORT REPORTS
// ==========================================================================

function exportJsonReport() {
  const report = {
    generatedAt: new Date().toISOString(),
    securityScore: state.score,
    grade: state.grade,
    defaultPolicies: state.defaultPolicies,
    findingsCount: state.findings.length,
    shadowedRulesCount: state.shadowedRules.length,
    redundantRulesCount: state.redundantRules.length,
    findings: state.findings,
    shadowedRules: state.shadowedRules,
    rules: state.rules
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'firewall-audit-report.json';
  a.click();
  URL.revokeObjectURL(url);
}

function exportMarkdownReport() {
  let md = `# Network Security: Firewall Rules Audit Report

**Date:** ${new Date().toLocaleString()}  
**Security Posture Score:** ${state.score}/100 (Grade: ${state.grade})  
**Auditor Frameworks:** CIS Linux Benchmark 3.4, PCI-DSS Req 1.2, NIST SP 800-41  

---

## 1. Executive Summary
- **Total Rules Analyzed:** ${state.rules.length}
- **Default Policies:** INPUT=${state.defaultPolicies.INPUT}, FORWARD=${state.defaultPolicies.FORWARD}, OUTPUT=${state.defaultPolicies.OUTPUT}
- **Total Vulnerabilities / Gaps Found:** ${state.findings.length}
- **Shadowed / Dead Rules:** ${state.shadowedRules.length}

---

## 2. Identified Security Gaps & Findings

`;

  state.findings.forEach((f, idx) => {
    md += `### ${idx + 1}. [${f.severity}] ${f.title}
- **Reference:** ${f.framework}
- **Description:** ${f.detail}
- **Remediation:** \`${f.remediation}\`

`;
  });

  if (state.shadowedRules.length > 0) {
    md += `## 3. Shadowed Rules Analysis (Dead Code)

`;
    state.shadowedRules.forEach(s => {
      md += `- ⚠️ ${s.detail}\n`;
    });
    md += '\n';
  }

  md += `## 4. Current Rule Matrix

| # | Chain | Action | Proto | Source | Destination | Port | State |
|---|-------|--------|-------|--------|-------------|------|-------|
`;

  state.rules.forEach((r, idx) => {
    md += `| ${idx + 1} | ${r.chain} | ${r.action} | ${r.proto} | ${r.src} | ${r.dst} | ${r.port} | ${r.state} |\n`;
  });

  const blob = new Blob([md], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'firewall-audit-report.md';
  a.click();
  URL.revokeObjectURL(url);
}

// Modal and Toast Helpers
function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) modal.classList.add('open');
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) modal.classList.remove('open');
}

function showToast(msg) {
  const toast = document.getElementById('toast');
  if (!toast) return;
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => {
    toast.classList.remove('show');
  }, 2800);
}
