import os
from flask import Flask, render_template, request, jsonify
from database import get_connection, init_db
from normalizer import LogNormalizer
from alert_engine import AlertEngine
from log_generator import LogSimulator

app = Flask(__name__)

# Ensure Database is initialized on startup
init_db()
LogSimulator.seed_initial_logs(count=100)
# Start live log stream background daemon automatically for active SOC telemetry
LogSimulator.start_background(interval_sec=3.0)

@app.route('/')
def index():
    return render_template('index.html')

# ----------------- SIEM REST API ----------------- #

@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    conn = get_connection()
    cursor = conn.cursor()

    # 1. Total logs
    cursor.execute('SELECT COUNT(*) FROM logs')
    total_logs = cursor.fetchone()[0]

    # 2. Failed Logins
    cursor.execute("SELECT COUNT(*) FROM logs WHERE event_type = 'LOGIN_FAILED'")
    failed_logins = cursor.fetchone()[0]

    # 3. Successful Logins
    cursor.execute("SELECT COUNT(*) FROM logs WHERE event_type = 'LOGIN_SUCCESS'")
    success_logins = cursor.fetchone()[0]

    # 4. Active Alerts
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('OPEN', 'INVESTIGATING')")
    active_alerts = cursor.fetchone()[0]

    # 5. Critical Threats
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL' AND status IN ('OPEN', 'INVESTIGATING')")
    critical_alerts = cursor.fetchone()[0]

    # 6. Severity breakdown
    cursor.execute("SELECT severity, COUNT(*) as cnt FROM logs GROUP BY severity")
    severity_breakdown = {row["severity"]: row["cnt"] for row in cursor.fetchall()}

    # 7. Event Type breakdown
    cursor.execute("SELECT event_type, COUNT(*) as cnt FROM logs GROUP BY event_type ORDER BY cnt DESC")
    event_breakdown = {row["event_type"]: row["cnt"] for row in cursor.fetchall()}

    # 8. Recent 10 minute activity time series
    cursor.execute('''
        SELECT strftime('%H:%M', timestamp) as time_slot,
               SUM(CASE WHEN event_type = 'LOGIN_FAILED' THEN 1 ELSE 0 END) as failed_cnt,
               SUM(CASE WHEN event_type = 'LOGIN_SUCCESS' THEN 1 ELSE 0 END) as ok_cnt,
               COUNT(*) as total_cnt
        FROM logs
        GROUP BY time_slot
        ORDER BY timestamp DESC
        LIMIT 12
    ''')
    timeseries_data = [dict(row) for row in cursor.fetchall()][::-1]

    conn.close()

    return jsonify({
        "status": "success",
        "total_logs": total_logs,
        "failed_logins": failed_logins,
        "success_logins": success_logins,
        "active_alerts": active_alerts,
        "critical_alerts": critical_alerts,
        "severity_breakdown": severity_breakdown,
        "event_breakdown": event_breakdown,
        "timeseries": timeseries_data,
        "simulator_active": LogSimulator.is_running()
    })

@app.route('/api/logs', methods=['GET'])
def get_logs():
    query = request.args.get('query', '').strip()
    severity = request.args.get('severity', '').strip()
    event_type = request.args.get('event_type', '').strip()
    limit = int(request.args.get('limit', 50))
    offset = int(request.args.get('offset', 0))

    conn = get_connection()
    cursor = conn.cursor()

    sql = "SELECT * FROM logs WHERE 1=1"
    params = []

    if query:
        sql += " AND (source_ip LIKE ? OR username LIKE ? OR raw_message LIKE ? OR country LIKE ?)"
        q_param = f"%{query}%"
        params.extend([q_param, q_param, q_param, q_param])
    
    if severity and severity != 'ALL':
        sql += " AND severity = ?"
        params.append(severity)

    if event_type and event_type != 'ALL':
        sql += " AND event_type = ?"
        params.append(event_type)

    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cursor.execute(sql, params)
    logs = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return jsonify({
        "status": "success",
        "count": len(logs),
        "logs": logs
    })

@app.route('/api/top-ips', methods=['GET'])
def get_top_ips():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT 
            source_ip,
            country,
            COUNT(*) as total_events,
            SUM(CASE WHEN event_type = 'LOGIN_FAILED' THEN 1 ELSE 0 END) as failed_attempts,
            SUM(CASE WHEN event_type = 'WEB_ATTACK' THEN 1 ELSE 0 END) as web_attacks,
            MAX(severity) as max_severity
        FROM logs
        WHERE source_ip IS NOT NULL AND source_ip != ''
        GROUP BY source_ip, country
        ORDER BY failed_attempts DESC, total_events DESC
        LIMIT 10
    ''')
    top_ips = []
    for row in cursor.fetchall():
        d = dict(row)
        # Calculate dynamic threat score 0 - 100
        threat_score = min(100, (d["failed_attempts"] * 12) + (d["web_attacks"] * 25))
        d["threat_score"] = threat_score
        top_ips.append(d)

    conn.close()
    return jsonify({
        "status": "success",
        "top_ips": top_ips
    })

@app.route('/api/failed-logins', methods=['GET'])
def get_failed_logins():
    conn = get_connection()
    cursor = conn.cursor()

    # Targeted Usernames
    cursor.execute('''
        SELECT username, COUNT(*) as count
        FROM logs
        WHERE event_type = 'LOGIN_FAILED'
        GROUP BY username
        ORDER BY count DESC
        LIMIT 8
    ''')
    targeted_users = [dict(row) for row in cursor.fetchall()]

    # Attacking Source IPs for failed logins
    cursor.execute('''
        SELECT source_ip, country, COUNT(*) as count
        FROM logs
        WHERE event_type = 'LOGIN_FAILED'
        GROUP BY source_ip, country
        ORDER BY count DESC
        LIMIT 8
    ''')
    failed_ips = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return jsonify({
        "status": "success",
        "targeted_users": targeted_users,
        "failed_ips": failed_ips
    })

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    limit = int(request.args.get('limit', 50))
    alerts = AlertEngine.get_active_alerts(limit=limit)
    return jsonify({
        "status": "success",
        "alerts": alerts
    })

@app.route('/api/alerts/<int:alert_id>/status', methods=['POST'])
def update_alert(alert_id):
    data = request.json or {}
    new_status = data.get('status', 'RESOLVED')
    analyst = data.get('analyst', 'Lead SOC Analyst')
    AlertEngine.update_alert_status(alert_id, new_status, analyst)
    return jsonify({
        "status": "success",
        "message": f"Alert {alert_id} updated to {new_status}"
    })

@app.route('/api/rules', methods=['GET', 'POST'])
def manage_rules():
    conn = get_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        data = request.json
        name = data.get('name')
        event_type = data.get('event_type')
        threshold = int(data.get('threshold', 5))
        time_window = int(data.get('time_window_sec', 60))
        severity = data.get('severity', 'HIGH')
        desc = data.get('description', '')

        cursor.execute('''
            INSERT INTO alert_rules (name, event_type, threshold, time_window_sec, severity, description)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (name, event_type, threshold, time_window, severity, desc))
        conn.commit()
        rule_id = cursor.lastrowid
        conn.close()
        return jsonify({"status": "success", "rule_id": rule_id, "message": "Detection rule added!"})

    cursor.execute('SELECT * FROM alert_rules ORDER BY id ASC')
    rules = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({"status": "success", "rules": rules})

@app.route('/api/ingest', methods=['POST'])
def ingest_log():
    data = request.json or {}
    raw_message = data.get('raw_log') or data.get('message') or ""
    source_hint = data.get('source_type', 'Manual-Ingest')

    if not raw_message:
        return jsonify({"status": "error", "message": "No raw_log provided"}), 400

    normalized = LogNormalizer.normalize(raw_message, source_hint=source_hint)
    
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO logs (timestamp, source_type, source_ip, destination_ip, username, event_type, status, severity, raw_message, country)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        normalized["timestamp"],
        normalized["source_type"],
        normalized["source_ip"],
        normalized["destination_ip"],
        normalized["username"],
        normalized["event_type"],
        normalized["status"],
        normalized["severity"],
        normalized["raw_message"],
        normalized["country"]
    ))
    conn.commit()
    conn.close()

    triggered_alerts = AlertEngine.process_event(normalized)

    return jsonify({
        "status": "success",
        "normalized_event": normalized,
        "triggered_alerts": triggered_alerts
    })

@app.route('/api/simulator/toggle', methods=['POST'])
def toggle_simulator():
    if LogSimulator.is_running():
        LogSimulator.stop_background()
        return jsonify({"status": "success", "simulator_active": False, "message": "Telemetry simulation paused."})
    else:
        LogSimulator.start_background(interval_sec=2.5)
        return jsonify({"status": "success", "simulator_active": True, "message": "Telemetry simulation resumed."})

@app.route('/api/simulator/generate-attack', methods=['POST'])
def trigger_attack_burst():
    """Generates an immediate rapid brute-force attack burst of 6 failed attempts to demonstrate instant alert firing"""
    data = request.json or {}
    attacker_ip = data.get('ip', "185.220.101.5")
    target_user = data.get('user', "root")

    alerts_generated = []
    for _ in range(6):
        raw = f"Oct 06 14:00:00 soc-svr sshd[9999]: Failed password for invalid user {target_user} from {attacker_ip} port 49152 ssh2"
        normalized = LogNormalizer.normalize(raw)
        
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO logs (timestamp, source_type, source_ip, destination_ip, username, event_type, status, severity, raw_message, country)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            normalized["timestamp"], normalized["source_type"], normalized["source_ip"],
            normalized["destination_ip"], normalized["username"], normalized["event_type"],
            normalized["status"], normalized["severity"], normalized["raw_message"], normalized["country"]
        ))
        conn.commit()
        conn.close()

        alerts = AlertEngine.process_event(normalized)
        alerts_generated.extend(alerts)

    return jsonify({
        "status": "success",
        "message": f"Generated 6 rapid failed attempts from {attacker_ip} targeting '{target_user}'.",
        "alerts_triggered": alerts_generated
    })

import sys
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

if __name__ == '__main__':
    print("="*60)
    print("[*] SIEM DASHBOARD COMMAND CENTER STARTING")
    print("[*] Access Dashboard at: http://127.0.0.1:5000")
    print("="*60)
    app.run(host='0.0.0.0', port=5000, debug=False)

