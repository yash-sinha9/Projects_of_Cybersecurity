"""
Reporting and Visualization Engine
Generates Terminal summaries, JSON exports, and interactive HTML dashboards.
"""
import json
import os

def generate_json_report(stats, alerts, packets_log, filename="traffic_report.json"):
    report_data = {
        "summary": stats,
        "total_alerts": len(alerts),
        "alerts": alerts,
        "recent_packets": packets_log[-100:]  # Store last 100 packets
    }
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)
    return os.path.abspath(filename)

def generate_html_report(stats, alerts, packets_log, filename="traffic_report.html"):
    """
    Generates a modern SOC analyst report dashboard in interactive HTML.
    """
    proto_labels = list(stats.get("protocols", {}).keys())
    proto_values = list(stats.get("protocols", {}).values())

    top_ips = sorted(stats.get("ip_talkers", {}).items(), key=lambda x: x[1], reverse=True)[:8]

    # Format alerts HTML
    alert_rows = ""
    for a in alerts:
        badge_color = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#3b82f6",
            "INFO": "#6b7280"
        }.get(a["level"], "#6b7280")

        alert_rows += f"""
        <tr>
            <td><span style="background-color: {badge_color}; color: #fff; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px;">{a['level']}</span></td>
            <td>{a['timestamp']}</td>
            <td><strong>{a['category']}</strong></td>
            <td>{a['src_ip']} &rarr; {a['dst_ip']}</td>
            <td>{a['description']}</td>
        </tr>
        """

    # Format packets table HTML
    packet_rows = ""
    for p in packets_log[-40:]:
        packet_rows += f"""
        <tr>
            <td>{p.get('timestamp', '')}</td>
            <td><span class="proto-tag">{p.get('protocol', 'OTHER')}</span></td>
            <td>{p.get('src_ip', '')}:{p.get('src_port', '')}</td>
            <td>{p.get('dst_ip', '')}:{p.get('dst_port', '')}</td>
            <td>{p.get('length', 0)} B</td>
            <td style="font-family: monospace; font-size: 12px; color: #94a3b8;">{p.get('payload_summary', '')[:60]}</td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Traffic Analyzer - SOC Security Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg: #0f172a;
            --card-bg: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #38bdf8;
            --danger: #ef4444;
            --warning: #f59e0b;
            --border: #334155;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: var(--bg);
            color: var(--text-main);
            padding: 24px;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }}
        .header h1 {{ font-size: 26px; color: var(--accent); }}
        .header p {{ color: var(--text-muted); font-size: 14px; margin-top: 4px; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: var(--card-bg);
            padding: 18px;
            border-radius: 8px;
            border: 1px solid var(--border);
        }}
        .stat-card .val {{ font-size: 28px; font-weight: 700; color: #fff; margin-top: 6px; }}
        .stat-card .label {{ font-size: 12px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.05em; }}
        
        .charts-row {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 24px;
        }}
        @media (max-width: 900px) {{
            .charts-row {{ grid-template-columns: 1fr; }}
        }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 24px;
        }}
        .card h2 {{
            font-size: 18px;
            margin-bottom: 16px;
            color: #e2e8f0;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th, td {{
            text-align: left;
            padding: 10px 12px;
            border-bottom: 1px solid var(--border);
        }}
        th {{ color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 11px; }}
        tr:hover {{ background: rgba(255, 255, 255, 0.02); }}
        .proto-tag {{
            background: #0369a1;
            color: #bae6fd;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🛡️ Network Traffic Security Analysis Dashboard</h1>
            <p>Industry-Standard Real-Time Packet Capture, Protocol Dissection & Anomaly Detection</p>
        </div>
        <div style="text-align: right; color: var(--text-muted); font-size: 13px;">
            <div>Status: <strong>ANALYSIS COMPLETE</strong></div>
            <div>Generated by SOC Traffic Analyzer Engine</div>
        </div>
    </div>

    <!-- Metric Cards -->
    <div class="stats-grid">
        <div class="stat-card">
            <div class="label">Total Packets Captured</div>
            <div class="val">{stats.get("total_packets", 0):,}</div>
        </div>
        <div class="stat-card">
            <div class="label">Total Data Volume</div>
            <div class="val">{round(stats.get("total_bytes", 0) / 1024, 2)} KB</div>
        </div>
        <div class="stat-card">
            <div class="label">Threat Alerts Triggered</div>
            <div class="val" style="color: var(--danger);">{len(alerts)}</div>
        </div>
        <div class="stat-card">
            <div class="label">Unique Communicating Hosts</div>
            <div class="val">{len(stats.get("ip_talkers", {}))}</div>
        </div>
    </div>

    <!-- Charts -->
    <div class="charts-row">
        <div class="card">
            <h2>📊 Protocol Distribution</h2>
            <div style="position: relative; height: 260px;">
                <canvas id="protoChart"></canvas>
            </div>
        </div>
        <div class="card">
            <h2>🌐 Top Talkers (Communicating IP Addresses)</h2>
            <table style="margin-top: 10px;">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Packet Count</th>
                        <th>Percentage</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join([f"<tr><td>{ip}</td><td>{cnt}</td><td>{round((cnt / max(1, stats.get('total_packets', 1))) * 100, 1)}%</td></tr>" for ip, cnt in top_ips])}
                </tbody>
            </table>
        </div>
    </div>

    <!-- Threat Alerts Section -->
    <div class="card">
        <h2>🚨 Security Anomalies & Threat Alerts ({len(alerts)})</h2>
        {f"<p style='color: #4ade80;'>No anomalies detected.</p>" if not alerts else f"""
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Timestamp</th>
                    <th>Alert Type</th>
                    <th>Connection</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {alert_rows}
            </tbody>
        </table>
        """}
    </div>

    <!-- Recent Packets Log -->
    <div class="card">
        <h2>📦 Captured Packet Log (Latest Sample)</h2>
        <table>
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Proto</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Size</th>
                    <th>Payload Summary / Flags</th>
                </tr>
            </thead>
            <tbody>
                {packet_rows}
            </tbody>
        </table>
    </div>

    <script>
        const ctx = document.getElementById('protoChart').getContext('2d');
        new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: {json.dumps(proto_labels)},
                datasets: [{{
                    data: {json.dumps(proto_values)},
                    backgroundColor: ['#38bdf8', '#818cf8', '#34d399', '#fbbf24', '#f87171', '#c084fc', '#94a3b8'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ position: 'right', labels: {{ color: '#cbd5e1' }} }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    return os.path.abspath(filename)
