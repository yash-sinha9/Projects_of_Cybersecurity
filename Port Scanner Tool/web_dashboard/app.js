/**
 * ApexPort Cyber Security Dashboard - Frontend Logic
 * Supports both Live Python Backend API and Standalone Browser Demonstration Mode.
 */

// Port Database for Realistic Fingerprinting & Standalone Mode
const PORT_SERVICE_MAP = {
  20: { service: "FTP-DATA", proto: "TCP", desc: "File Transfer Protocol (Data)", risk: "Medium", banner: "" },
  21: { service: "FTP", proto: "TCP", desc: "File Transfer Protocol (Command)", risk: "High", banner: "220 vsftpd 3.0.3 ready" },
  22: { service: "SSH", proto: "TCP", desc: "Secure Shell Remote Terminal", risk: "Medium", banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" },
  23: { service: "Telnet", proto: "TCP", desc: "Unencrypted Plaintext Remote Console", risk: "Critical", banner: "Welcome to Linux Telnet Gateway\r\nlogin: " },
  25: { service: "SMTP", proto: "TCP", desc: "Simple Mail Transfer Protocol", risk: "Medium", banner: "220 mail.internal ESMTP Postfix" },
  53: { service: "DNS", proto: "UDP", desc: "Domain Name System", risk: "Low", banner: "BIND 9.18.1-1ubuntu1.2-Ubuntu" },
  80: { service: "HTTP", proto: "TCP", desc: "Hypertext Transfer Protocol (Web)", risk: "Medium", banner: "nginx/1.22.0 (Ubuntu)" },
  110: { service: "POP3", proto: "TCP", desc: "Post Office Protocol v3", risk: "High", banner: "+OK Dovecot ready" },
  135: { service: "MSRPC", proto: "TCP", desc: "Windows RPC Endpoint Mapper", risk: "High", banner: "Microsoft Windows RPC Server" },
  139: { service: "NetBIOS-SSN", proto: "TCP", desc: "NetBIOS Session Service", risk: "High", banner: "Windows NetBIOS Session" },
  143: { service: "IMAP", proto: "TCP", desc: "Internet Message Access Protocol", risk: "Medium", banner: "* OK [CAPABILITY IMAP4rev1] Dovecot ready" },
  443: { service: "HTTPS", proto: "TCP", desc: "HTTP over TLS/SSL (Secure Web)", risk: "Low", banner: "Apache/2.4.52 (Ubuntu) OpenSSL/3.0.2" },
  445: { service: "SMB", proto: "TCP", desc: "Server Message Block (File Sharing)", risk: "Critical", banner: "Windows Server 2022 Standard SMBv3" },
  1433: { service: "MSSQL", proto: "TCP", desc: "Microsoft SQL Server Database Engine", risk: "High", banner: "Microsoft SQL Server 2019 (RTM)" },
  3000: { service: "Dev-Web", proto: "TCP", desc: "Node/React/Grafana Dev Server", risk: "Low", banner: "Express/4.18.2 Node.js" },
  3306: { service: "MySQL", proto: "TCP", desc: "MySQL Relational Database Server", risk: "High", banner: "8.0.35-0ubuntu0.22.04.1 (MySQL Community Server)" },
  3389: { service: "RDP", proto: "TCP", desc: "Microsoft Remote Desktop Protocol", risk: "High", banner: "Remote Desktop Protocol TLS" },
  5432: { service: "PostgreSQL", proto: "TCP", desc: "PostgreSQL Database Server", risk: "High", banner: "PostgreSQL 15.3 on x86_64" },
  6379: { service: "Redis", proto: "TCP", desc: "Redis In-Memory Key-Value Store", risk: "High", banner: "+PONG (redis_version: 7.0.12)" },
  8080: { service: "HTTP-Proxy", proto: "TCP", desc: "Apache Tomcat / Web Alternate", risk: "Medium", banner: "Apache-Coyote/1.1 (Tomcat 10.1)" },
  8443: { service: "HTTPS-Alt", proto: "TCP", desc: "HTTPS Management Interface", risk: "Low", banner: "TLS/1.3 Enterprise Gateway" },
  27017: { service: "MongoDB", proto: "TCP", desc: "MongoDB NoSQL Database Server", risk: "High", banner: "MongoDB Server v6.0.8" }
};

const COMPARISON_DATA = [
  {
    criterion: "Scanning Technique",
    custom: "Full TCP 3-Way Handshake (SYN → SYN/ACK → ACK)",
    nmap: "TCP SYN Stealth Scan (-sS, Half-Open)",
    takeaway: "Mastery of RFC 793 connection states and BSD socket APIs."
  },
  {
    criterion: "Privilege Level Required",
    custom: "Unprivileged Userland (No Admin / Root required)",
    nmap: "Administrator / Root required (for raw sockets / pcap)",
    takeaway: "Runs safely in restricted production environments and locked-down endpoints."
  },
  {
    criterion: "Operating System Layer",
    custom: "Kernel Socket Layer (socket.connect_ex)",
    nmap: "Network Frame Injection (WinPcap / Npcap / libpcap)",
    takeaway: "Distinguishes between standard application programming and driver-level packet forging."
  },
  {
    criterion: "IDS / Firewall Evasion",
    custom: "Application-level logging triggered (connection established)",
    nmap: "Bypasses naive application connection logs (session aborted)",
    takeaway: "Understands SOC / SIEM detection rules and IDS telemetry."
  },
  {
    criterion: "Error Code Translation",
    custom: "WSAECONNREFUSED (Closed), WSAETIMEDOUT (Filtered)",
    nmap: "TCP RST (Closed), ICMP Unreachable / Drop (Filtered)",
    takeaway: "Shows deep comprehension of kernel network exception handling."
  },
  {
    criterion: "Service Fingerprinting",
    custom: "Custom HTTP/SSH/DB probe handshakes with banner parsing",
    nmap: "Signature database match against 10,000+ regex patterns",
    takeaway: "Demonstrates protocol reverse-engineering and application handshake skills."
  }
];

// State variables
let isScanning = false;
let abortRequested = false;
let currentResults = [];
let scanTimer = null;
let scanStartTime = 0;

// DOM Elements
const targetInput = document.getElementById("targetInput");
const portPresetSelect = document.getElementById("portPresetSelect");
const customPortsWrapper = document.getElementById("customPortsWrapper");
const customPortsInput = document.getElementById("customPortsInput");
const scanModeSelect = document.getElementById("scanModeSelect");
const threadSlider = document.getElementById("threadSlider");
const threadCountDisplay = document.getElementById("threadCountDisplay");
const startScanBtn = document.getElementById("startScanBtn");
const stopScanBtn = document.getElementById("stopScanBtn");
const systemStatusBadge = document.getElementById("systemStatusBadge");

// Metric Elements
const metricTotal = document.getElementById("metricTotal");
const metricPortRange = document.getElementById("metricPortRange");
const metricOpen = document.getElementById("metricOpen");
const metricFiltered = document.getElementById("metricFiltered");
const metricClosed = document.getElementById("metricClosed");
const metricSpeed = document.getElementById("metricSpeed");
const metricLatency = document.getElementById("metricLatency");
const progressBarFill = document.getElementById("progressBarFill");
const scanStatusText = document.getElementById("scanStatusText");
const scanPercentText = document.getElementById("scanPercentText");

// Views & Tables
const portGridContainer = document.getElementById("portGridContainer");
const resultsTableBody = document.getElementById("resultsTableBody");
const tableFilterInput = document.getElementById("tableFilterInput");
const comparisonTableBody = document.getElementById("comparisonTableBody");

// Modal
const portModal = document.getElementById("portModal");
const modalPortTitle = document.getElementById("modalPortTitle");
const modalPortBody = document.getElementById("modalPortBody");
const modalCloseBtn = document.getElementById("modalCloseBtn");

// Initialize on Load
document.addEventListener("DOMContentLoaded", () => {
  initPortGrid();
  initComparisonTable();
  setupEventListeners();
  checkBackendAPI();
});

// Build 1000-port visual matrix
function initPortGrid() {
  portGridContainer.innerHTML = "";
  const fragment = document.createDocumentFragment();
  for (let p = 1; p <= 1000; p++) {
    const node = document.createElement("div");
    node.className = "port-node";
    node.id = `port-node-${p}`;
    node.textContent = p;
    node.title = `Port ${p}`;
    node.addEventListener("click", () => inspectPort(p));
    fragment.appendChild(node);
  }
  portGridContainer.appendChild(fragment);
}

// Build Nmap Comparison Table
function initComparisonTable() {
  comparisonTableBody.innerHTML = "";
  COMPARISON_DATA.forEach(row => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><strong>${row.criterion}</strong></td>
      <td style="color: var(--cyan-primary);">${row.custom}</td>
      <td style="color: var(--purple-accent);">${row.nmap}</td>
      <td style="color: var(--emerald-open); font-family: var(--font-sans);">${row.takeaway}</td>
    `;
    comparisonTableBody.appendChild(tr);
  });
}

function setupEventListeners() {
  threadSlider.addEventListener("input", (e) => {
    threadCountDisplay.textContent = e.target.value;
  });

  portPresetSelect.addEventListener("change", (e) => {
    if (e.target.value === "custom") {
      customPortsWrapper.style.display = "flex";
    } else {
      customPortsWrapper.style.display = "none";
    }
  });

  startScanBtn.addEventListener("click", startScan);
  stopScanBtn.addEventListener("click", stopScan);

  modalCloseBtn.addEventListener("click", () => portModal.classList.remove("active"));
  portModal.addEventListener("click", (e) => {
    if (e.target === portModal) portModal.classList.remove("active");
  });

  tableFilterInput.addEventListener("input", filterTable);

  document.getElementById("exportJsonBtn").addEventListener("click", exportJSON);
  document.getElementById("exportCsvBtn").addEventListener("click", exportCSV);
}

async function checkBackendAPI() {
  try {
    const res = await fetch("/api/status");
    if (res.ok) {
      systemStatusBadge.textContent = "● LIVE PYTHON ENGINE CONNECTED";
      systemStatusBadge.style.color = "var(--emerald-open)";
    }
  } catch (e) {
    systemStatusBadge.textContent = "● STANDALONE DEMO ENGINE READY";
  }
}

// Tab Switching
function switchMainTab(tabName) {
  document.querySelectorAll(".tab-view").forEach(el => el.classList.remove("active"));
  document.querySelectorAll(".panel-actions .btn-ghost").forEach(el => el.classList.remove("active"));

  if (tabName === "matrix") {
    document.getElementById("viewMatrix").classList.add("active");
    document.getElementById("tabBtnMatrix").classList.add("active");
  } else if (tabName === "table") {
    document.getElementById("viewTable").classList.add("active");
    document.getElementById("tabBtnTable").classList.add("active");
  } else if (tabName === "nmap") {
    document.getElementById("viewNmap").classList.add("active");
    document.getElementById("tabBtnNmap").classList.add("active");
  } else if (tabName === "interview") {
    document.getElementById("viewInterview").classList.add("active");
    document.getElementById("tabBtnInterview").classList.add("active");
  }
}

// Port Range Generator
function getSelectedPorts() {
  const preset = portPresetSelect.value;
  if (preset === "quick") {
    return [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 27017];
  } else if (preset === "top50") {
    return [
      20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139, 143, 161,
      179, 389, 443, 445, 465, 500, 514, 587, 636, 873, 993, 995, 1080, 1194, 1433, 1521, 1723,
      2049, 2375, 3000, 3306, 3389, 5000, 5432, 5900, 6379, 8000, 8080, 8443, 27017
    ];
  } else if (preset === "well_known") {
    const list = [];
    for (let i = 1; i <= 1024; i++) list.push(i);
    return list;
  } else {
    const raw = customPortsInput.value;
    const set = new Set();
    raw.split(",").forEach(part => {
      part = part.trim();
      if (part.includes("-")) {
        const [s, e] = part.split("-").map(n => parseInt(n.trim()));
        for (let p = s; p <= e; p++) if (p >= 1 && p <= 65535) set.add(p);
      } else if (!isNaN(parseInt(part))) {
        set.add(parseInt(part));
      }
    });
    return Array.from(set).sort((a, b) => a - b);
  }
}

// Start Scan Execution
async function startScan() {
  const target = targetInput.value.trim() || "127.0.0.1";
  const ports = getSelectedPorts();
  const scanMode = scanModeSelect.value;
  const threads = parseInt(threadSlider.value);

  if (ports.length === 0) {
    alert("Please select or enter valid ports to scan.");
    return;
  }

  // Reset UI
  isScanning = true;
  abortRequested = false;
  currentResults = [];
  startScanBtn.disabled = true;
  stopScanBtn.disabled = false;
  resultsTableBody.innerHTML = "";

  metricTotal.textContent = "0";
  metricOpen.textContent = "0";
  metricFiltered.textContent = "0";
  metricClosed.textContent = "0";
  metricSpeed.innerHTML = `0 <span class="unit">p/s</span>`;
  metricPortRange.textContent = `0 / ${ports.length} Completed`;
  progressBarFill.style.width = "0%";
  scanPercentText.textContent = "0%";
  scanStatusText.textContent = `Target: ${target} | Probing ${ports.length} ports via ${scanMode}...`;

  // Reset grid highlights
  document.querySelectorAll(".port-node").forEach(node => {
    node.className = "port-node";
  });

  scanStartTime = performance.now();

  // Try calling Python backend if server exists
  let backendHandled = false;
  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, ports, scan_mode: scanMode, threads })
    });
    if (res.ok) {
      backendHandled = true;
      const data = await res.json();
      handleBackendResults(data);
      return;
    }
  } catch (e) {
    // Backend not running; fallback gracefully to simulated interactive scan
  }

  if (!backendHandled) {
    runInteractiveScan(target, ports, scanMode, threads);
  }
}

function handleBackendResults(data) {
  currentResults = data.all_results || [];
  let openCount = 0;
  let filteredCount = 0;
  let closedCount = 0;

  currentResults.forEach(r => {
    updatePortUI(r);
    if (r.state === "OPEN" || r.state === "OPEN|FILTERED") openCount++;
    else if (r.state === "FILTERED") filteredCount++;
    else closedCount++;
  });

  finishScan(currentResults.length, openCount, filteredCount, closedCount);
}

// Interactive Real-Time Scanning Engine
function runInteractiveScan(target, ports, scanMode, threads) {
  let completed = 0;
  let openCount = 0;
  let filteredCount = 0;
  let closedCount = 0;
  const total = ports.length;
  let latencies = [];

  // Determine realistic open ports for this target demo
  const isLocal = target.includes("127.0.0.1") || target.toLowerCase().includes("localhost");
  const defaultOpen = isLocal ? [135, 445, 3000, 8080] : [22, 80, 443];

  const batchSize = Math.max(1, Math.floor(threads / 10));
  let portIndex = 0;

  function processBatch() {
    if (abortRequested || portIndex >= total) {
      finishScan(completed, openCount, filteredCount, closedCount, latencies);
      return;
    }

    const currentBatch = ports.slice(portIndex, portIndex + batchSize);
    portIndex += batchSize;

    currentBatch.forEach(port => {
      completed++;
      const isKnown = PORT_SERVICE_MAP[port];
      let state = "CLOSED";
      let latency = Math.round(1.5 + Math.random() * 8.0);
      let banner = "";

      if (defaultOpen.includes(port)) {
        state = "OPEN";
        latency = Math.round(0.8 + Math.random() * 2.5);
        banner = isKnown ? isKnown.banner : "Active Service Response";
        openCount++;
        latencies.push(latency);
      } else if (port % 7 === 0 || port % 13 === 0) {
        state = "FILTERED";
        latency = 1000.0;
        filteredCount++;
      } else {
        state = "CLOSED";
        closedCount++;
      }

      const svc = isKnown ? isKnown.service : "Unknown";
      const desc = isKnown ? isKnown.desc : "General TCP/UDP Port";
      const risk = isKnown ? isKnown.risk : "Low";

      const res = {
        port,
        proto: scanMode,
        state,
        service: svc,
        latency_ms: latency,
        risk,
        banner: banner || desc,
        description: desc
      };

      currentResults.push(res);
      updatePortUI(res);
    });

    // Update Telemetry Metrics
    const elapsedSec = (performance.now() - scanStartTime) / 1000;
    const speed = Math.round(completed / Math.max(elapsedSec, 0.001));
    const percent = Math.min(100, Math.round((completed / total) * 100));

    metricTotal.textContent = completed;
    metricPortRange.textContent = `${completed} / ${total} Probed`;
    metricOpen.textContent = openCount;
    metricFiltered.textContent = filteredCount;
    metricClosed.textContent = closedCount;
    metricSpeed.innerHTML = `${speed} <span class="unit">p/s</span>`;
    progressBarFill.style.width = `${percent}%`;
    scanPercentText.textContent = `${percent}%`;

    const avgLat = latencies.length ? (latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(2) : "0.00";
    metricLatency.textContent = `Avg RTT: ${avgLat} ms`;

    // Next frame
    scanTimer = setTimeout(processBatch, 40);
  }

  processBatch();
}

function updatePortUI(res) {
  // Update node in visual grid if <= 1000
  if (res.port <= 1000) {
    const node = document.getElementById(`port-node-${res.port}`);
    if (node) {
      node.classList.remove("state-open", "state-filtered", "state-closed");
      if (res.state === "OPEN" || res.state === "OPEN|FILTERED") node.classList.add("state-open");
      else if (res.state === "FILTERED") node.classList.add("state-filtered");
      else if (res.state === "CLOSED") node.classList.add("state-closed");
    }
  }

  // Append row to results table if open or if total ports <= 50
  if (res.state === "OPEN" || res.state === "OPEN|FILTERED" || currentResults.length <= 50) {
    const existingEmpty = resultsTableBody.querySelector(".empty-row");
    if (existingEmpty) existingEmpty.remove();

    const tr = document.createElement("tr");
    tr.id = `row-port-${res.port}`;
    tr.innerHTML = `
      <td><strong>${res.port}</strong></td>
      <td>${res.proto}</td>
      <td><span class="state-badge ${res.state}">${res.state}</span></td>
      <td>${res.service}</td>
      <td>${res.latency_ms} ms</td>
      <td><span class="risk-badge risk-${res.risk}">${res.risk}</span></td>
      <td><span title="${res.banner}">${res.banner.slice(0, 45)}</span></td>
      <td><button class="btn btn-outline" style="padding: 4px 10px; font-size: 0.7rem;" onclick="inspectPort(${res.port})">Inspect</button></td>
    `;
    resultsTableBody.appendChild(tr);
  }
}

function finishScan(total, openCount, filteredCount, closedCount, latencies = []) {
  isScanning = false;
  startScanBtn.disabled = false;
  stopScanBtn.disabled = true;

  const duration = ((performance.now() - scanStartTime) / 1000).toFixed(2);
  scanStatusText.textContent = `Scan Complete! Discovered ${openCount} open ports in ${duration}s.`;
  progressBarFill.style.width = "100%";
  scanPercentText.textContent = "100%";
}

function stopScan() {
  if (isScanning) {
    abortRequested = true;
    clearTimeout(scanTimer);
    finishScan(currentResults.length, metricOpen.textContent, metricFiltered.textContent, metricClosed.textContent);
    scanStatusText.textContent = "Scan stopped by user.";
  }
}

// Deep Port Inspection Modal
function inspectPort(port) {
  const result = currentResults.find(r => r.port === port);
  const known = PORT_SERVICE_MAP[port] || {};

  const state = result ? result.state : "UNSCANNED";
  const service = result ? result.service : (known.service || "Unassigned");
  const proto = result ? result.proto : "TCP";
  const latency = result ? result.latency_ms : "N/A";
  const risk = result ? result.risk : (known.risk || "Low");
  const banner = result ? result.banner : (known.banner || "(No handshake captured)");
  const desc = result ? result.description : (known.desc || "Standard TCP/IP port assignment");

  modalPortTitle.innerHTML = `PORT ${port}/${proto} — <span style="color: var(--cyan-primary);">${service}</span> [${state}]`;

  modalPortBody.innerHTML = `
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 16px;">
      <div><strong>Status:</strong> <span class="state-badge ${state}">${state}</span></div>
      <div><strong>Latency (RTT):</strong> ${latency} ms</div>
      <div><strong>Protocol:</strong> ${proto} (Socket Connect)</div>
      <div><strong>Risk Rating:</strong> <span class="risk-badge risk-${risk}">${risk}</span></div>
    </div>

    <div style="margin-bottom: 16px;">
      <div style="color: var(--cyan-primary); font-weight: bold; margin-bottom: 6px;">RFC PROTOCOL & SERVICE DESCRIPTION:</div>
      <p style="color: var(--text-secondary);">${desc}</p>
    </div>

    <div style="margin-bottom: 16px;">
      <div style="color: var(--cyan-primary); font-weight: bold; margin-bottom: 6px;">APPLICATION BANNER / RESPONSE:</div>
      <pre style="background: var(--bg-input); padding: 10px; border-radius: 4px; overflow-x: auto; color: #00ff9d;">${banner}</pre>
    </div>

    <div>
      <div style="color: var(--cyan-primary); font-weight: bold; margin-bottom: 6px;">TCP 3-WAY HANDSHAKE FLOW:</div>
      <pre style="background: var(--bg-input); padding: 10px; border-radius: 4px; font-size: 0.75rem;">
Client (Scanner)               Target (${targetInput.value})
      |                              |
      | -------- [TCP SYN] --------> | (Port ${port})
      |                              |
      | <---- [TCP SYN, ACK] ------- | (Target acknowledges connection)
      |                              |
      | -------- [TCP ACK] --------> | (Session Established -> OPEN)
      |                              |
      | <---- [Banner Stream] ------ | (Service Version Extracted)
      |                              |
      | -------- [TCP RST/FIN] ----> | (Connection Closed Gracefully)
      </pre>
    </div>
  `;

  portModal.classList.add("active");
}

function filterTable() {
  const query = tableFilterInput.value.toLowerCase();
  const rows = resultsTableBody.querySelectorAll("tr");
  rows.forEach(row => {
    if (row.classList.contains("empty-row")) return;
    const text = row.textContent.toLowerCase();
    row.style.display = text.includes(query) ? "" : "none";
  });
}

// Export JSON
function exportJSON() {
  if (currentResults.length === 0) {
    alert("No scan data available to export.");
    return;
  }
  const data = {
    target: targetInput.value,
    timestamp: new Date().toISOString(),
    total_ports: currentResults.length,
    results: currentResults
  };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  downloadBlob(blob, `scan_${targetInput.value.replace(/[^a-zA-Z0-9]/g, "_")}.json`);
}

// Export CSV
function exportCSV() {
  if (currentResults.length === 0) {
    alert("No scan data available to export.");
    return;
  }
  let csv = "Port,Protocol,State,Service,Latency_ms,Risk,Banner\n";
  currentResults.forEach(r => {
    const cleanBanner = (r.banner || "").replace(/"/g, '""');
    csv += `${r.port},${r.proto},${r.state},"${r.service}",${r.latency_ms},${r.risk},"${cleanBanner}"\n`;
  });
  const blob = new Blob([csv], { type: "text/csv" });
  downloadBlob(blob, `scan_${targetInput.value.replace(/[^a-zA-Z0-9]/g, "_")}.csv`);
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
