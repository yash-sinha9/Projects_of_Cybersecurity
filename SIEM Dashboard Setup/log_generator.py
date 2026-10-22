import random
import time
import threading
from datetime import datetime, timedelta
from database import get_connection
from normalizer import LogNormalizer
from alert_engine import AlertEngine

ATTACKER_IPS = [
    "185.220.101.5",
    "194.26.29.112",
    "45.154.255.87",
    "103.235.46.10",
    "89.248.165.74",
    "91.240.118.23"
]

BENIGN_IPS = [
    "192.168.1.15",
    "192.168.1.42",
    "10.0.0.45",
    "10.0.0.88",
    "172.16.0.12"
]

USERNAMES_TARGET = ["root", "admin", "administrator", "guest", "oracle", "dbadmin", "jsmith", "bwayne", "cstark"]

RAW_LOG_TEMPLATES = [
    # SSH Brute Force / Auth Failure
    ("ssh_fail", "Oct 06 {time} soc-svr sshd[{pid}]: Failed password for invalid user {user} from {ip} port {port} ssh2"),
    ("ssh_fail", "Oct 06 {time} soc-svr sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2"),
    # SSH Success
    ("ssh_ok", "Oct 06 {time} soc-svr sshd[{pid}]: Accepted publickey for {user} from {benign_ip} port {port} ssh2: RSA SHA256:7uG..."),
    # Windows Security 4625 (Failed Logon)
    ("win_fail", "EventID=4625 Category=Logon Status=0xC000006D TargetUserName={user} Workstation=WORKSTATION-{pid} SourceIP={ip}"),
    # Windows Security 4624 (Logon Success)
    ("win_ok", "EventID=4624 Category=Logon Status=0x0 TargetUserName={user} Workstation=CORP-PC SourceIP={benign_ip}"),
    # Web SQL Injection / Web Attacks
    ("web_sqli", '{ip} - - [{webtime}] "GET /api/v1/auth/login?username=admin\'%20OR%20\'1\'=\'1&pass=foo HTTP/1.1" 500 488'),
    ("web_sqli", '{ip} - - [{webtime}] "POST /catalog/items?id=1%20UNION%20SELECT%20null,password,secret%20FROM%20users-- HTTP/1.1" 403 214'),
    ("web_xss", '{ip} - - [{webtime}] "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1" 403 312'),
    ("web_ok", '{benign_ip} - - [{webtime}] "GET /dashboard/overview HTTP/1.1" 200 1520'),
    ("web_ok", '{benign_ip} - - [{webtime}] "GET /assets/main.css HTTP/1.1" 200 45890'),
    # Linux Privilege Escalation
    ("priv_esc", "Oct 06 {time} soc-svr sudo: {user} : TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash"),
    # Firewall Drop
    ("fw_drop", "kernel: [UFW BLOCK] IN=eth0 OUT= SRC={ip} DST=10.0.0.5 PROTO=TCP SPT={port} DPT=22")
]

class LogSimulator:
    _instance = None
    _running = False
    _thread = None

    @classmethod
    def start_background(cls, interval_sec=2.5):
        if not cls._running:
            cls._running = True
            cls._thread = threading.Thread(target=cls._run_loop, args=(interval_sec,), daemon=True)
            cls._thread.start()

    @classmethod
    def stop_background(cls):
        cls._running = False

    @classmethod
    def is_running(cls):
        return cls._running

    @classmethod
    def _run_loop(cls, interval_sec):
        while cls._running:
            cls.generate_and_ingest_single()
            time.sleep(interval_sec)

    @classmethod
    def generate_and_ingest_single(cls, custom_timestamp=None):
        now = datetime.now() if not custom_timestamp else custom_timestamp
        time_str = now.strftime("%H:%M:%S")
        webtime_str = now.strftime("%d/%b/%Y:%H:%M:%S +0000")
        timestamp_iso = now.strftime("%Y-%m-%d %H:%M:%S")

        # Pick weighted random template (attacks slightly favored for active SOC presentation)
        template_type, template_str = random.choices(
            RAW_LOG_TEMPLATES,
            weights=[25, 20, 15, 15, 10, 8, 8, 5, 20, 15, 4, 15]
        )[0]

        attacker_ip = random.choice(ATTACKER_IPS)
        benign_ip = random.choice(BENIGN_IPS)
        user = random.choice(USERNAMES_TARGET)
        pid = random.randint(1000, 9999)
        port = random.randint(1024, 65535)

        raw = template_str.format(
            time=time_str,
            webtime=webtime_str,
            pid=pid,
            user=user,
            ip=attacker_ip,
            benign_ip=benign_ip,
            port=port
        )

        normalized = LogNormalizer.normalize(raw)
        normalized["timestamp"] = timestamp_iso

        # Save to database
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

        # Run alert correlation
        alerts = AlertEngine.process_event(normalized)
        return normalized, alerts

    @classmethod
    def seed_initial_logs(cls, count=120):
        """Generates realistic historical events over the past 2 hours"""
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM logs")
        existing = cursor.fetchone()[0]
        conn.close()

        if existing > 20:
            return existing

        now = datetime.now()
        for i in range(count):
            # Spread over last 120 minutes
            offset_seconds = (count - i) * 60 + random.randint(-15, 15)
            past_time = now - timedelta(seconds=max(0, offset_seconds))
            cls.generate_and_ingest_single(custom_timestamp=past_time)

        return count

if __name__ == '__main__':
    from database import init_db
    init_db()
    count = LogSimulator.seed_initial_logs(60)
    print(f"Generated {count} seed logs successfully.")
