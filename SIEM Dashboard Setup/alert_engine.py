from datetime import datetime, timedelta
import sqlite3
from database import get_connection

class AlertEngine:
    @staticmethod
    def process_event(normalized_event: dict):
        """
        Evaluates an ingested normalized event against configured alert rules.
        Creates an alert if conditions/thresholds are met.
        """
        conn = get_connection()
        cursor = conn.cursor()

        event_type = normalized_event.get("event_type")
        source_ip = normalized_event.get("source_ip", "unknown")
        username = normalized_event.get("username", "unknown")
        event_time = normalized_event.get("timestamp")

        # Fetch enabled rules for this event type
        cursor.execute('''
            SELECT id, name, threshold, time_window_sec, severity, description
            FROM alert_rules
            WHERE enabled = 1 AND event_type = ?
        ''', (event_type,))
        rules = cursor.fetchall()

        created_alerts = []

        for rule in rules:
            rule_id = rule["id"]
            rule_name = rule["name"]
            threshold = rule["threshold"]
            time_window = rule["time_window_sec"]
            severity = rule["severity"]
            desc_template = rule["description"]

            # Calculate time cutoff for sliding window
            try:
                event_dt = datetime.strptime(event_time, "%Y-%m-%d %H:%M:%S")
            except Exception:
                event_dt = datetime.now()
            
            cutoff = (event_dt - timedelta(seconds=time_window)).strftime("%Y-%m-%d %H:%M:%S")

            # Count occurrences within time window for this source_ip or user
            cursor.execute('''
                SELECT COUNT(*) as cnt FROM logs
                WHERE event_type = ? 
                  AND (source_ip = ? OR username = ?)
                  AND timestamp >= ?
            ''', (event_type, source_ip, username, cutoff))
            count = cursor.fetchone()["cnt"]

            if count >= threshold:
                # Check for alert deduplication (don't create duplicate OPEN alert within last 2 minutes for same IP/rule)
                dup_cutoff = (event_dt - timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute('''
                    SELECT id FROM alerts
                    WHERE rule_id = ? AND source_ip = ? AND status IN ('OPEN', 'INVESTIGATING') AND timestamp >= ?
                ''', (rule_id, source_ip, dup_cutoff))
                existing_alert = cursor.fetchone()

                if not existing_alert:
                    alert_desc = f"{rule_name} triggered: {count} events detected from IP {source_ip} (Target: {username}) in past {time_window}s."
                    cursor.execute('''
                        INSERT INTO alerts (timestamp, rule_id, title, description, severity, source_ip, target_user, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, 'OPEN')
                    ''', (event_time, rule_id, rule_name, alert_desc, severity, source_ip, username))
                    
                    alert_id = cursor.lastrowid
                    created_alerts.append({
                        "id": alert_id,
                        "title": rule_name,
                        "description": alert_desc,
                        "severity": severity,
                        "source_ip": source_ip,
                        "target_user": username,
                        "status": "OPEN",
                        "timestamp": event_time
                    })

        conn.commit()
        conn.close()
        return created_alerts

    @staticmethod
    def get_active_alerts(limit=50):
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM alerts
            ORDER BY id DESC
            LIMIT ?
        ''', (limit,))
        alerts = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return alerts

    @staticmethod
    def update_alert_status(alert_id: int, new_status: str, analyst: str = "SOC Analyst 1"):
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE alerts
            SET status = ?, assigned_analyst = ?
            WHERE id = ?
        ''', (new_status, analyst, alert_id))
        conn.commit()
        conn.close()
        return True
