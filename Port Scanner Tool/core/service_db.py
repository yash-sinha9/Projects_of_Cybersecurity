"""
Service Database and Port Knowledge Base
Contains port descriptions, default protocol types, and security risk ratings.
"""

COMMON_PORTS = {
    20: {"service": "FTP-DATA", "proto": "TCP", "desc": "File Transfer Protocol (Data Transfer)", "risk": "Medium"},
    21: {"service": "FTP", "proto": "TCP", "desc": "File Transfer Protocol (Control / Command)", "risk": "High"},
    22: {"service": "SSH", "proto": "TCP", "desc": "Secure Shell (Remote Encrypted Terminal)", "risk": "Medium"},
    23: {"service": "Telnet", "proto": "TCP", "desc": "Unencrypted Text Communications", "risk": "Critical"},
    25: {"service": "SMTP", "proto": "TCP", "desc": "Simple Mail Transfer Protocol (Email Routing)", "risk": "Medium"},
    53: {"service": "DNS", "proto": "TCP/UDP", "desc": "Domain Name System", "risk": "Low"},
    67: {"service": "DHCP", "proto": "UDP", "desc": "Dynamic Host Configuration Protocol (Server)", "risk": "Low"},
    68: {"service": "DHCP", "proto": "UDP", "desc": "Dynamic Host Configuration Protocol (Client)", "risk": "Low"},
    69: {"service": "TFTP", "proto": "UDP", "desc": "Trivial File Transfer Protocol (No Auth)", "risk": "High"},
    80: {"service": "HTTP", "proto": "TCP", "desc": "Hypertext Transfer Protocol (World Wide Web)", "risk": "Medium"},
    88: {"service": "Kerberos", "proto": "TCP/UDP", "desc": "Network Authentication Protocol", "risk": "Low"},
    110: {"service": "POP3", "proto": "TCP", "desc": "Post Office Protocol v3 (Unencrypted Mail)", "risk": "High"},
    111: {"service": "RPCBind", "proto": "TCP/UDP", "desc": "Remote Procedure Call Portmapper", "risk": "High"},
    119: {"service": "NNTP", "proto": "TCP", "desc": "Network News Transfer Protocol", "risk": "Low"},
    123: {"service": "NTP", "proto": "UDP", "desc": "Network Time Protocol (Clock Sync)", "risk": "Low"},
    135: {"service": "MSRPC", "proto": "TCP", "desc": "Microsoft Windows RPC Endpoint Mapper", "risk": "High"},
    137: {"service": "NetBIOS-NS", "proto": "UDP", "desc": "NetBIOS Name Service", "risk": "Medium"},
    138: {"service": "NetBIOS-DGM", "proto": "UDP", "desc": "NetBIOS Datagram Service", "risk": "Medium"},
    139: {"service": "NetBIOS-SSN", "proto": "TCP", "desc": "NetBIOS Session Service", "risk": "High"},
    143: {"service": "IMAP", "proto": "TCP", "desc": "Internet Message Access Protocol", "risk": "Medium"},
    161: {"service": "SNMP", "proto": "UDP", "desc": "Simple Network Management Protocol", "risk": "High"},
    162: {"service": "SNMP-Trap", "proto": "UDP", "desc": "SNMP Trap Receiver", "risk": "Medium"},
    179: {"service": "BGP", "proto": "TCP", "desc": "Border Gateway Protocol", "risk": "Low"},
    389: {"service": "LDAP", "proto": "TCP/UDP", "desc": "Lightweight Directory Access Protocol", "risk": "Medium"},
    443: {"service": "HTTPS", "proto": "TCP", "desc": "HTTP over TLS/SSL (Secure Web)", "risk": "Low"},
    445: {"service": "SMB", "proto": "TCP", "desc": "Microsoft Server Message Block (File Sharing)", "risk": "Critical"},
    465: {"service": "SMTPS", "proto": "TCP", "desc": "Secure SMTP (SSL Wrapped)", "risk": "Low"},
    500: {"service": "ISAKMP", "proto": "UDP", "desc": "IPsec Key Exchange / VPN", "risk": "Low"},
    514: {"service": "Syslog", "proto": "UDP", "desc": "System Logging Protocol", "risk": "Low"},
    587: {"service": "Submission", "proto": "TCP", "desc": "SMTP Message Submission (STARTTLS)", "risk": "Low"},
    636: {"service": "LDAPS", "proto": "TCP", "desc": "Secure LDAP over TLS/SSL", "risk": "Low"},
    873: {"service": "Rsync", "proto": "TCP", "desc": "Remote File Synchronization Service", "risk": "Medium"},
    993: {"service": "IMAPS", "proto": "TCP", "desc": "Secure IMAP over TLS/SSL", "risk": "Low"},
    995: {"service": "POP3S", "proto": "TCP", "desc": "Secure POP3 over TLS/SSL", "risk": "Low"},
    1080: {"service": "SOCKS", "proto": "TCP", "desc": "SOCKS Proxy Server", "risk": "Medium"},
    1194: {"service": "OpenVPN", "proto": "UDP/TCP", "desc": "OpenVPN Virtual Private Network", "risk": "Low"},
    1433: {"service": "MSSQL", "proto": "TCP", "desc": "Microsoft SQL Server Database Engine", "risk": "High"},
    1434: {"service": "MSSQL-Monitor", "proto": "UDP", "desc": "Microsoft SQL Server Browser Monitor", "risk": "Medium"},
    1521: {"service": "Oracle", "proto": "TCP", "desc": "Oracle Database Listener", "risk": "High"},
    1723: {"service": "PPTP", "proto": "TCP", "desc": "Point-to-Point Tunneling Protocol VPN", "risk": "High"},
    2049: {"service": "NFS", "proto": "TCP/UDP", "desc": "Network File System", "risk": "High"},
    2181: {"service": "ZooKeeper", "proto": "TCP", "desc": "Apache ZooKeeper Coordination", "risk": "Medium"},
    2375: {"service": "Docker-HTTP", "proto": "TCP", "desc": "Docker Daemon REST API (Unencrypted)", "risk": "Critical"},
    2376: {"service": "Docker-TLS", "proto": "TCP", "desc": "Docker Daemon REST API (TLS Encrypted)", "risk": "Medium"},
    3000: {"service": "Dev-Web", "proto": "TCP", "desc": "Node/React/Grafana Development Server", "risk": "Low"},
    3306: {"service": "MySQL", "proto": "TCP", "desc": "MySQL / MariaDB Database Server", "risk": "High"},
    3389: {"service": "RDP", "proto": "TCP", "desc": "Microsoft Remote Desktop Protocol", "risk": "High"},
    5000: {"service": "Flask/Dev", "proto": "TCP", "desc": "Python Flask / Docker Registry", "risk": "Low"},
    5432: {"service": "PostgreSQL", "proto": "TCP", "desc": "PostgreSQL Relational Database", "risk": "High"},
    5900: {"service": "VNC", "proto": "TCP", "desc": "Virtual Network Computing (Remote GUI)", "risk": "High"},
    6379: {"service": "Redis", "proto": "TCP", "desc": "Redis In-Memory Key-Value Store", "risk": "High"},
    8000: {"service": "HTTP-Alt", "proto": "TCP", "desc": "Common HTTP Alternate / Django Dev Server", "risk": "Medium"},
    8080: {"service": "HTTP-Proxy", "proto": "TCP", "desc": "HTTP Alternate / Apache Tomcat / Proxy", "risk": "Medium"},
    8443: {"service": "HTTPS-Alt", "proto": "TCP", "desc": "HTTPS Alternate / Management Console", "risk": "Low"},
    8888: {"service": "Jupyter", "proto": "TCP", "desc": "Jupyter Notebook / Web Alternate", "risk": "Medium"},
    9000: {"service": "PHP-FPM/Sonar", "proto": "TCP", "desc": "PHP FastCGI / SonarQube Service", "risk": "Medium"},
    9092: {"service": "Kafka", "proto": "TCP", "desc": "Apache Kafka Message Broker", "risk": "Medium"},
    9200: {"service": "Elasticsearch", "proto": "TCP", "desc": "Elasticsearch REST API", "risk": "High"},
    9418: {"service": "Git", "proto": "TCP", "desc": "Git Version Control Daemon", "risk": "Low"},
    27017: {"service": "MongoDB", "proto": "TCP", "desc": "MongoDB NoSQL Database Server", "risk": "High"},
}

# Pre-defined Port Selection Sets for Quick Scanning
PORT_SETS = {
    "quick": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 27017],
    "top50": [
        20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139, 143, 161,
        179, 389, 443, 445, 465, 500, 514, 587, 636, 873, 993, 995, 1080, 1194, 1433, 1521, 1723,
        2049, 2375, 3000, 3306, 3389, 5000, 5432, 5900, 6379, 8000, 8080, 8443, 27017
    ],
    "well_known": list(range(1, 1025)),
}


def lookup_service(port: int, proto: str = "TCP") -> dict:
    """Returns service information for a given port."""
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    return {
        "service": "Unknown",
        "proto": proto,
        "desc": "Unassigned or Custom Private Port",
        "risk": "Low"
    }
