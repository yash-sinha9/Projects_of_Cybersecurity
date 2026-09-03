/* Vulnerable Dashboard JS (dashboard.js) */

function refreshDashboard() {
  const state = getAppState();

  // Populate KPIs
  const totalWhitelisted = state.whitelist.length;
  document.getElementById("kpi-whitelisted").innerText = totalWhitelisted;

  // Aggregate metrics and calculate rates
  let totalClicks = 0, totalSubmissions = 0, totalReports = 0;
  state.campaigns.forEach(c => {
    totalClicks += c.clicks;
    totalSubmissions += c.submissions;
    totalReports += c.reports;
  });

  const simulatedSends = Math.max(totalWhitelisted, 1);
  const ctr = Math.round((totalClicks / simulatedSends) * 100);
  const sr = Math.round((totalSubmissions / simulatedSends) * 100);
  const rr = Math.round((totalReports / simulatedSends) * 100);

  document.getElementById("kpi-ctr").innerText = `${ctr}%`;
  document.getElementById("kpi-sr").innerText = `${sr}%`;
  document.getElementById("kpi-rr").innerText = `${rr}%`;

  // Populate Event Log Table (STORED XSS VULNERABILITY)
  const logListEl = document.getElementById("activity-log-list");
  logListEl.innerHTML = "";
  state.logs.forEach(log => {
    const li = document.createElement("li");
    li.className = "log-item";
    // Security Issue: Direct concatenation of log.message into innerHTML allows stored XSS
    li.innerHTML = `<span class="log-time">[${log.timestamp}]</span> <span>${log.message}</span>`;
    logListEl.appendChild(li);
  });

  // Populate Whitelist Table (STORED XSS VULNERABILITY)
  const tableBody = document.getElementById("whitelist-table-body");
  tableBody.innerHTML = "";
  state.whitelist.forEach(item => {
    const tr = document.createElement("tr");
    // Security Issue: Direct concatenation of item.name and item.email into innerHTML allows stored XSS
    tr.innerHTML = `
      <td><strong>${item.name}</strong></td>
      <td><code>${item.email}</code></td>
    `;
    tableBody.appendChild(tr);
  });
}
