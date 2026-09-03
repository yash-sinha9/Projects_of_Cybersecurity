/* Secure Dashboard JS (secure_dashboard.js) */

function refreshDashboard() {
  const state = getAppState();

  // Populate KPIs safely
  const totalWhitelisted = state.whitelist.length;
  document.getElementById("kpi-whitelisted").textContent = totalWhitelisted;

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

  document.getElementById("kpi-ctr").textContent = `${ctr}%`;
  document.getElementById("kpi-sr").textContent = `${sr}%`;
  document.getElementById("kpi-rr").textContent = `${rr}%`;

  // Populate Event Log Table SAFELY
  const logListEl = document.getElementById("activity-log-list");
  logListEl.textContent = ""; // Clear existing content safely

  if (state.logs.length === 0) {
    const emptyLi = document.createElement("li");
    emptyLi.className = "log-item";
    emptyLi.style.color = "var(--text-secondary)";
    emptyLi.textContent = "[LOG] No simulation events recorded yet.";
    logListEl.appendChild(emptyLi);
  } else {
    state.logs.forEach(log => {
      const li = document.createElement("li");
      li.className = "log-item";

      const timeSpan = document.createElement("span");
      timeSpan.className = "log-time";
      timeSpan.textContent = `[${log.timestamp}] `;

      const messageSpan = document.createElement("span");
      messageSpan.textContent = log.message; // textContent handles escaping automatically

      li.appendChild(timeSpan);
      li.appendChild(messageSpan);
      logListEl.appendChild(li);
    });
  }

  // Populate Whitelist Table SAFELY
  const tableBody = document.getElementById("whitelist-table-body");
  tableBody.textContent = ""; // Clear existing table rows safely

  if (state.whitelist.length === 0) {
    const emptyTr = document.createElement("tr");
    const emptyTd = document.createElement("td");
    emptyTd.colSpan = 2;
    emptyTd.style.textAlign = "center";
    emptyTd.style.color = "var(--text-secondary)";
    emptyTd.textContent = "No participants whitelisted yet.";
    emptyTr.appendChild(emptyTd);
    tableBody.appendChild(emptyTr);
  } else {
    state.whitelist.forEach(item => {
      const tr = document.createElement("tr");

      const nameTd = document.createElement("td");
      const nameStrong = document.createElement("strong");
      nameStrong.textContent = item.name; // safe assignment
      nameTd.appendChild(nameStrong);

      const emailTd = document.createElement("td");
      const emailCode = document.createElement("code");
      emailCode.textContent = item.email; // safe assignment
      emailTd.appendChild(emailCode);

      tr.appendChild(nameTd);
      tr.appendChild(emailTd);
      tableBody.appendChild(tr);
    });
  }
}
