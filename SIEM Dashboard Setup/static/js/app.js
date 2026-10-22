// CyberGuard SOC - Frontend Dashboard Controller

let timeSeriesChart = null;
let eventPieChart = null;
let currentAlertFilter = 'ALL';
let searchDebounceTimeout = null;
let isSimulatorRunning = true;

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    initClock();
    initCharts();
    loadDashboardData();
    // Poll telemetry every 2.5 seconds
    setInterval(loadDashboardData, 2500);
});

// Live UTC Clock
function initClock() {
    function update() {
        const now = new Date();
        const utcStr = now.toUTCString().split(' ')[4] + ' UTC';
        document.getElementById('liveClock').innerText = utcStr;
    }
    update();
    setInterval(update, 1000);
}

// Chart Initializations
function initCharts() {
    // 1. Time Series Chart
    const ctxTs = document.getElementById('timeSeriesChart').getContext('2d');
    timeSeriesChart = new Chart(ctxTs, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Failed Logins (Attacks)',
                    data: [],
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.15)',
                    fill: true,
                    tension: 0.35,
                    borderWidth: 2,
                    pointRadius: 3
                },
                {
                    label: 'Successful Logins',
                    data: [],
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.05)',
                    fill: true,
                    tension: 0.35,
                    borderWidth: 2,
                    pointRadius: 2
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: '#94a3b8', font: { family: 'Inter', size: 11 } }
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
                }
            }
        }
    });

    // 2. Event Distribution Pie / Doughnut
    const ctxPie = document.getElementById('eventPieChart').getContext('2d');
    eventPieChart = new Chart(ctxPie, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    '#ef4444', // LOGIN_FAILED
                    '#10b981', // LOGIN_SUCCESS
                    '#f59e0b', // WEB_ATTACK
                    '#8b5cf6', // PRIV_ESC
                    '#06b6d4', // FIREWALL_DROP
                    '#64748b'  // OTHERS
                ],
                borderWidth: 2,
                borderColor: '#111827'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#94a3b8', boxWidth: 10, font: { family: 'Inter', size: 10 } }
                }
            },
            cutout: '68%'
        }
    });
}

// Master Data Fetcher
async function loadDashboardData() {
    try {
        await Promise.all([
            fetchMetrics(),
            fetchTopIps(),
            fetchFailedLogins(),
            fetchAlerts(),
            fetchLogs()
        ]);
    } catch (err) {
        console.error("Telemetry update error:", err);
    }
}

// 1. Fetch Metrics & Update Charts
async function fetchMetrics() {
    const res = await fetch('/api/metrics');
    const data = await res.json();
    if (data.status !== 'success') return;

    document.getElementById('kpiTotalLogs').innerText = data.total_logs.toLocaleString();
    document.getElementById('kpiFailedLogins').innerText = data.failed_logins.toLocaleString();
    
    // Percentage
    const totalAuth = (data.failed_logins + data.success_logins) || 1;
    const failPct = Math.round((data.failed_logins / totalAuth) * 100);
    document.getElementById('kpiFailedPercent').innerText = `${failPct}% of authentications`;

    document.getElementById('kpiActiveAlerts').innerText = data.active_alerts;
    document.getElementById('kpiCriticalAlerts').innerText = `${data.critical_alerts} Critical`;

    // Simulator button state
    isSimulatorRunning = data.simulator_active;
    const toggleBtn = document.getElementById('simToggleText');
    if (toggleBtn) {
        toggleBtn.innerText = isSimulatorRunning ? '⏸ Pause Stream' : '▶ Resume Stream';
    }

    // Update Timeseries Chart
    if (data.timeseries && data.timeseries.length > 0) {
        const labels = data.timeseries.map(d => d.time_slot);
        const failedCounts = data.timeseries.map(d => d.failed_cnt);
        const okCounts = data.timeseries.map(d => d.ok_cnt);

        timeSeriesChart.data.labels = labels;
        timeSeriesChart.data.datasets[0].data = failedCounts;
        timeSeriesChart.data.datasets[1].data = okCounts;
        timeSeriesChart.update('none');
    }

    // Update Event Pie Chart
    if (data.event_breakdown) {
        const eventKeys = Object.keys(data.event_breakdown);
        const eventVals = Object.values(data.event_breakdown);
        eventPieChart.data.labels = eventKeys;
        eventPieChart.data.datasets[0].data = eventVals;
        eventPieChart.update('none');
    }
}

// 2. Fetch Top Attacking IPs
async function fetchTopIps() {
    const res = await fetch('/api/top-ips');
    const data = await res.json();
    if (data.status !== 'success') return;

    const tbody = document.getElementById('topIpsBody');
    if (!data.top_ips || data.top_ips.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center">No threats detected yet.</td></tr>`;
        return;
    }

    // Set Top Adversary IP KPI card
    const topThreat = data.top_ips[0];
    document.getElementById('kpiTopIp').innerText = topThreat.source_ip;
    document.getElementById('kpiTopIpGeo').innerText = `Origin: ${topThreat.country} (${topThreat.failed_attempts} attacks)`;

    let html = '';
    data.top_ips.forEach(ip => {
        const scoreColor = ip.threat_score > 75 ? '#ef4444' : (ip.threat_score > 40 ? '#f59e0b' : '#10b981');
        html += `
            <tr>
                <td class="code-font" style="color: #38bdf8; font-weight: 700;">${ip.source_ip}</td>
                <td><span class="badge-tag">${ip.country}</span></td>
                <td>${ip.total_events}</td>
                <td style="color: #f87171; font-weight: 600;">${ip.failed_attempts}</td>
                <td>
                    <div class="threat-bar-container">
                        <div class="threat-bar-fill" style="width: ${ip.threat_score}%; background: ${scoreColor};"></div>
                    </div>
                    <span style="font-weight: 700; color: ${scoreColor}; font-family: var(--font-mono);">${ip.threat_score}%</span>
                </td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="blockIpAlert('${ip.source_ip}')">Block IP</button>
                </td>
            </tr>
        `;
    });
    tbody.innerHTML = html;
}

// 3. Fetch Targeted Users
async function fetchFailedLogins() {
    const res = await fetch('/api/failed-logins');
    const data = await res.json();
    if (data.status !== 'success') return;

    const userList = document.getElementById('targetedUsersList');
    if (!data.targeted_users || data.targeted_users.length === 0) {
        userList.innerHTML = `<div class="text-center">No targeted accounts.</div>`;
        return;
    }

    let html = '';
    data.targeted_users.forEach(u => {
        html += `
            <div class="user-target-item">
                <span class="username">👤 ${u.username}</span>
                <span class="count-pill">${u.count} breaches stopped</span>
            </div>
        `;
    });
    userList.innerHTML = html;
}

// 4. Fetch Active & Historical Alerts
async function fetchAlerts() {
    const res = await fetch('/api/alerts?limit=25');
    const data = await res.json();
    if (data.status !== 'success') return;

    const tbody = document.getElementById('alertsTableBody');
    const badge = document.getElementById('alertCountBadge');

    let alerts = data.alerts || [];
    badge.innerText = `${alerts.length} Incidents`;

    if (currentAlertFilter !== 'ALL') {
        if (currentAlertFilter === 'RESOLVED') {
            alerts = alerts.filter(a => a.status === 'RESOLVED');
        } else {
            alerts = alerts.filter(a => a.severity === currentAlertFilter && a.status !== 'RESOLVED');
        }
    }

    if (alerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center" style="color: #64748b;">No security incidents matching current filter.</td></tr>`;
        return;
    }

    let html = '';
    alerts.forEach(a => {
        const isResolved = a.status === 'RESOLVED';
        const actionBtn = isResolved
            ? `<span style="color:#10b981; font-weight:600;">✓ Closed</span>`
            : `<button class="btn btn-sm btn-success" onclick="resolveAlert(${a.id})">Triage / Resolve</button>`;

        html += `
            <tr>
                <td class="code-font" style="color:#94a3b8;">${a.timestamp}</td>
                <td><span class="badge-sev badge-${a.severity}">${a.severity}</span></td>
                <td style="font-weight: 600; color: #f1f5f9;">${a.title}</td>
                <td class="code-font" style="color: #38bdf8;">${a.source_ip || '---'}</td>
                <td class="code-font" style="color: #facc15;">${a.target_user || 'system'}</td>
                <td><span class="badge-status status-${a.status}">${a.status}</span></td>
                <td>${actionBtn}</td>
            </tr>
        `;
    });
    tbody.innerHTML = html;
}

// 5. Fetch Normalized Live Logs
async function fetchLogs() {
    const query = document.getElementById('logSearchInput').value;
    const severity = document.getElementById('logSeverityFilter').value;
    const eventType = document.getElementById('logEventTypeFilter').value;

    const params = new URLSearchParams({
        query: query,
        severity: severity,
        event_type: eventType,
        limit: 30
    });

    const res = await fetch(`/api/logs?${params.toString()}`);
    const data = await res.json();
    if (data.status !== 'success') return;

    const tbody = document.getElementById('logStreamBody');
    if (!data.logs || data.logs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center">No logs found matching criteria.</td></tr>`;
        return;
    }

    let html = '';
    data.logs.forEach(l => {
        const statusColor = l.status === 'FAILED' || l.status === 'BLOCKED' ? '#ef4444' : (l.status === 'WARNING' ? '#f59e0b' : '#10b981');
        html += `
            <tr>
                <td style="color:#94a3b8;">${l.timestamp.split(' ')[1] || l.timestamp}</td>
                <td><span class="badge-tag">${l.source_type}</span></td>
                <td style="font-weight:600; color:#e2e8f0;">${l.event_type}</td>
                <td style="color:#38bdf8;">${l.source_ip}</td>
                <td style="color:#facc15;">${l.username}</td>
                <td style="color:${statusColor}; font-weight:700;">${l.status}</td>
                <td><span class="badge-sev badge-${l.severity}">${l.severity}</span></td>
                <td title="${escapeHtml(l.raw_message)}" style="color:#cbd5e1;">${escapeHtml(l.raw_message)}</td>
            </tr>
        `;
    });
    tbody.innerHTML = html;
}

// Triage / Resolve Alert
async function resolveAlert(alertId) {
    const res = await fetch(`/api/alerts/${alertId}/status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'RESOLVED', analyst: 'Lead SOC Analyst' })
    });
    const data = await res.json();
    showToast(`Incident #${alertId} Marked as RESOLVED`);
    fetchAlerts();
    fetchMetrics();
}

// Block IP Quick Action
function blockIpAlert(ip) {
    showToast(`Firewall Rule Injected: Null-routed IP ${ip}`, true);
}

// Alert Filter Buttons
function filterAlerts(sev) {
    currentAlertFilter = sev;
    document.querySelectorAll('.filter-group .btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    fetchAlerts();
}

// Log Search Input Debounce
function handleLogSearch() {
    clearTimeout(searchDebounceTimeout);
    searchDebounceTimeout = setTimeout(fetchLogs, 350);
}

// Trigger Simulated Attack Burst
async function triggerAttackSimulation() {
    showToast(`⚡ Launching simulated Brute-Force burst from 185.220.101.5...`);
    const res = await fetch('/api/simulator/generate-attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: '185.220.101.5', user: 'root' })
    });
    const data = await res.json();
    if (data.status === 'success') {
        showToast(`🚨 ALERT TRIGGERED: SSH / Auth Brute Force Detection!`, true);
        loadDashboardData();
    }
}

// Toggle Stream Simulation
async function toggleTelemetryStream() {
    const res = await fetch('/api/simulator/toggle', { method: 'POST' });
    const data = await res.json();
    showToast(data.message);
    fetchMetrics();
}

// Ingest Custom Raw Log
async function submitCustomLog() {
    const rawInput = document.getElementById('rawLogInput').value.trim();
    if (!rawInput) {
        alert("Please enter a raw log string.");
        return;
    }

    const res = await fetch('/api/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_log: rawInput })
    });
    const data = await res.json();
    
    const resultBox = document.getElementById('ingestResultBox');
    resultBox.classList.remove('hidden');

    if (data.status === 'success') {
        let alertMsg = data.triggered_alerts.length > 0 
            ? `⚠️ TRIGGERED ${data.triggered_alerts.length} ALERT(S)!` 
            : `✓ No alerts triggered (Normal event).`;

        resultBox.innerHTML = `
            <strong>Normalization Result:</strong>
            <pre style="margin-top:6px;">${JSON.stringify(data.normalized_event, null, 2)}</pre>
            <div style="margin-top:8px; font-weight:bold; color: #f87171;">${alertMsg}</div>
        `;
        showToast("Log normalized and ingested into SIEM database!");
        loadDashboardData();
    } else {
        resultBox.innerHTML = `<span style="color:#ef4444;">Error: ${data.message}</span>`;
    }
}

// Sample log presets for Modal
function loadSampleLog(type) {
    const textarea = document.getElementById('rawLogInput');
    if (type === 'ssh') {
        textarea.value = "Oct 06 14:22:10 soc-svr sshd[2841]: Failed password for invalid user admin from 185.220.101.5 port 55123 ssh2";
    } else if (type === 'win') {
        textarea.value = "EventID=4625 Category=Logon Status=0xC000006D TargetUserName=Administrator Workstation=DESKTOP-FINANCE SourceIP=194.26.29.112";
    } else if (type === 'sqli') {
        textarea.value = '185.220.101.5 - - [06/Oct/2026:14:30:12] "GET /api/users?id=1 UNION SELECT null,password FROM users HTTP/1.1" 500 412';
    } else if (type === 'sudo') {
        textarea.value = "Oct 06 14:25:01 soc-svr sudo: jsmith : TTY=pts/0 ; PWD=/home/jsmith ; USER=root ; COMMAND=/bin/bash";
    }
}

// Modal open/close
function openModal(id) {
    document.getElementById(id).classList.add('active');
    if (id === 'rulesModal') {
        loadRulesList();
    }
}

function closeModal(id) {
    document.getElementById(id).classList.remove('active');
}

// Fetch Rules for Modal
async function loadRulesList() {
    const res = await fetch('/api/rules');
    const data = await res.json();
    const tbody = document.getElementById('rulesTableBody');
    if (data.status !== 'success') return;

    let html = '';
    data.rules.forEach(r => {
        html += `
            <tr>
                <td style="font-weight:600; color:#fff;">${r.name}</td>
                <td><span class="badge-tag">${r.event_type}</span></td>
                <td class="code-font" style="color:#facc15;">&ge; ${r.threshold} events</td>
                <td class="code-font">${r.time_window_sec}s</td>
                <td><span class="badge-sev badge-${r.severity}">${r.severity}</span></td>
                <td style="color:#94a3b8; font-size:11px;">${r.description}</td>
            </tr>
        `;
    });
    tbody.innerHTML = html;
}

// Toast System
function showToast(message, isAlert = false) {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${isAlert ? 'alert-toast' : ''}`;
    toast.innerHTML = `<span>${isAlert ? '🚨' : 'ℹ️'}</span><span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 4000);
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>"']/g, function(m) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m];
    });
}
