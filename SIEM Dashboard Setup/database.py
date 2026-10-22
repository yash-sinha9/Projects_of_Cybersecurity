import sqlite3
import os
import json
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(__file__), 'siem_data.db')

def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=20.0)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # Logs Table (Normalized Log Schema)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_type TEXT NOT NULL,       -- e.g. SSH, Windows-Event, Web, Firewall, Syslog
            source_ip TEXT,
            destination_ip TEXT,
            username TEXT,
            event_type TEXT NOT NULL,        -- e.g. LOGIN_SUCCESS, LOGIN_FAILED, PORT_SCAN, SQL_INJECTION, PRIV_ESC
            status TEXT NOT NULL,            -- SUCCESS, FAILED, WARNING, BLOCKED
            severity TEXT NOT NULL,          -- INFO, LOW, MEDIUM, HIGH, CRITICAL
            raw_message TEXT NOT NULL,
            country TEXT DEFAULT 'Unknown',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Alerts Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            rule_id INTEGER,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,          -- LOW, MEDIUM, HIGH, CRITICAL
            source_ip TEXT,
            target_user TEXT,
            status TEXT DEFAULT 'OPEN',      -- OPEN, INVESTIGATING, RESOLVED
            assigned_analyst TEXT DEFAULT 'Unassigned',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Alert Rules Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alert_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            event_type TEXT NOT NULL,
            threshold INTEGER NOT NULL,
            time_window_sec INTEGER NOT NULL,
            severity TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            description TEXT
        )
    ''')

    # Create Indexes for performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs (timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON logs (source_ip)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_event_type ON logs (event_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs (severity)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status)')

    # Seed Default Detection Rules if empty
    cursor.execute('SELECT COUNT(*) FROM alert_rules')
    if cursor.fetchone()[0] == 0:
        default_rules = [
            ("SSH / Auth Brute Force Detection", "LOGIN_FAILED", 5, 60, "CRITICAL", 1, "Triggers when >= 5 failed login attempts occur from the same IP within 60 seconds."),
            ("Repeated Access Denied", "ACCESS_DENIED", 4, 120, "HIGH", 1, "Detects repeated unauthorized file/service access attempts."),
            ("Web Application Attack (SQLi / XSS)", "WEB_ATTACK", 2, 60, "HIGH", 1, "Detects pattern-matched web exploitation attempts (e.g. SQL injection, Path Traversal)."),
            ("Privilege Escalation Attempt", "PRIV_ESC", 1, 30, "CRITICAL", 1, "Immediate alert when unauthorized sudo or administrative token escalation is detected."),
            ("Port Scan & Reconnaissance", "PORT_SCAN", 8, 45, "MEDIUM", 1, "Detects rapid connection probes on multiple ports from a single external IP."),
            ("Firewall Mass Drop Burst", "FIREWALL_DROP", 10, 60, "LOW", 1, "Monitors spike in perimeter firewall dropped packets.")
        ]
        cursor.executemany('''
            INSERT INTO alert_rules (name, event_type, threshold, time_window_sec, severity, enabled, description)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', default_rules)

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    print("Database initialized successfully at:", DB_PATH)
