"""
Network Traffic Analyzer Engine
Core packet capture, dissection, and aggregation module.
Supports live sniffing (via Scapy), PCAP file replay, and realistic simulation mode.
"""
from collections import Counter, defaultdict
import datetime
import random
import time
from detector import AnomalyDetector

class NetworkAnalyzer:
    def __init__(self, interface=None, pcap_file=None):
        self.interface = interface
        self.pcap_file = pcap_file
        self.detector = AnomalyDetector()
        
        # Statistics storage
        self.stats = {
            "total_packets": 0,
            "total_bytes": 0,
            "protocols": Counter(),
            "ip_talkers": Counter(),
            "ports": Counter(),
            "start_time": time.time(),
            "end_time": None
        }
        self.packet_log = []

    def parse_scapy_packet(self, pkt):
        """
        Extract key protocol information from a raw Scapy packet.
        """
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.l2 import Ether, ARP
        from scapy.packet import Raw

        info = {
            "timestamp": datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "length": len(pkt),
            "protocol": "OTHER",
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "tcp_flags": "",
            "dns_query": None,
            "payload_summary": ""
        }

        # Check Layer 2 / ARP
        if pkt.haslayer(ARP):
            info["protocol"] = "ARP"
            info["src_ip"] = pkt[ARP].psrc
            info["dst_ip"] = pkt[ARP].pdst
            info["payload_summary"] = f"ARP Who has {pkt[ARP].pdst}? Tell {pkt[ARP].psrc}"

        # Layer 3 - IPv4
        elif pkt.haslayer(IP):
            info["src_ip"] = pkt[IP].src
            info["dst_ip"] = pkt[IP].dst
            proto_num = pkt[IP].proto

            # Layer 4
            if pkt.haslayer(TCP):
                info["protocol"] = "TCP"
                info["src_port"] = pkt[TCP].sport
                info["dst_port"] = pkt[TCP].dport
                info["tcp_flags"] = str(pkt[TCP].flags)
                info["payload_summary"] = f"TCP Flags: [{info['tcp_flags']}]"
                
                # Check HTTP / Application
                if pkt.haslayer(Raw):
                    raw_data = pkt[Raw].load.decode(errors="ignore")
                    info["payload_summary"] += " | " + raw_data[:50].replace("\r\n", " ")

            elif pkt.haslayer(UDP):
                info["protocol"] = "UDP"
                info["src_port"] = pkt[UDP].sport
                info["dst_port"] = pkt[UDP].dport
                
                # Check DNS
                if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                    info["protocol"] = "DNS"
                    qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                    info["dns_query"] = qname
                    info["payload_summary"] = f"DNS Query: {qname}"

            elif pkt.haslayer(ICMP):
                info["protocol"] = "ICMP"
                info["payload_summary"] = f"ICMP Type {pkt[ICMP].type} Code {pkt[ICMP].code}"

        return info

    def process_packet(self, packet_info):
        """
        Update statistics, run anomaly detection, and log packet.
        """
        self.stats["total_packets"] += 1
        self.stats["total_bytes"] += packet_info.get("length", 0)

        proto = packet_info.get("protocol", "OTHER")
        self.stats["protocols"][proto] += 1

        src = packet_info.get("src_ip")
        dst = packet_info.get("dst_ip")
        if src:
            self.stats["ip_talkers"][src] += 1
        if dst:
            self.stats["ip_talkers"][dst] += 1

        dst_port = packet_info.get("dst_port")
        if dst_port:
            self.stats["ports"][dst_port] += 1

        self.packet_log.append(packet_info)

        # Run Anomaly Detection
        new_alerts = self.detector.inspect_packet(packet_info)
        return new_alerts

    def start_live_capture(self, packet_count=0, filter_exp=None):
        """
        Capture packets in real-time from network interface using Scapy.
        """
        try:
            from scapy.all import sniff
        except ImportError:
            raise RuntimeError("Scapy is not installed. Please run: pip install scapy")

        print(f"[*] Starting live capture on interface: {self.interface or 'default'}...")
        if filter_exp:
            print(f"[*] Applying BPF filter: '{filter_exp}'")

        def _scapy_callback(pkt):
            info = self.parse_scapy_packet(pkt)
            alerts = self.process_packet(info)
            self._print_live_packet_summary(info, alerts)

        sniff(
            iface=self.interface,
            filter=filter_exp,
            prn=_scapy_callback,
            count=packet_count,
            store=False
        )
        self.stats["end_time"] = time.time()

    def analyze_pcap(self, pcap_path):
        """
        Read and analyze an offline PCAP file.
        """
        try:
            from scapy.utils import rdpcap
        except ImportError:
            raise RuntimeError("Scapy is not installed. Please run: pip install scapy")

        print(f"[*] Reading PCAP file: {pcap_path}")
        packets = rdpcap(pcap_path)
        for pkt in packets:
            info = self.parse_scapy_packet(pkt)
            alerts = self.process_packet(info)
            self._print_live_packet_summary(info, alerts)
        self.stats["end_time"] = time.time()

    def run_simulation(self, count=80):
        """
        Generates realistic network traffic scenarios:
        - Normal browsing (HTTPS, DNS, HTTP)
        - Reconnaissance (Port scan)
        - Suspicious connection (Metasploit shell on port 4444)
        - Cleartext credentials leak
        - High-rate SYN burst
        - DNS Tunneling anomaly
        """
        print(f"[*] Running realistic SOC traffic simulation ({count} packets)...")
        sample_ips = ["192.168.1.105", "192.168.1.1", "10.0.0.45", "172.16.0.22", "8.8.8.8", "142.250.190.46"]
        
        for i in range(1, count + 1):
            time.sleep(0.02)
            timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            
            # Simulate scenarios based on index
            if i in [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]:
                # Port scan simulation from 10.0.0.45
                info = {
                    "timestamp": timestamp,
                    "length": 64,
                    "protocol": "TCP",
                    "src_ip": "10.0.0.45",
                    "dst_ip": "192.168.1.105",
                    "src_port": 50000 + i,
                    "dst_port": i * 10,
                    "tcp_flags": "S",
                    "dns_query": None,
                    "payload_summary": f"TCP SYN probe to port {i * 10}"
                }
            elif i == 35:
                # Suspicious Metasploit port connection
                info = {
                    "timestamp": timestamp,
                    "length": 256,
                    "protocol": "TCP",
                    "src_ip": "192.168.1.105",
                    "dst_ip": "185.220.101.5",
                    "src_port": 49152,
                    "dst_port": 4444,
                    "tcp_flags": "PA",
                    "dns_query": None,
                    "payload_summary": "TCP Metasploit / Reverse Shell Payload"
                }
            elif i == 45:
                # Cleartext password leak over HTTP/FTP
                info = {
                    "timestamp": timestamp,
                    "length": 180,
                    "protocol": "TCP",
                    "src_ip": "192.168.1.105",
                    "dst_ip": "192.168.1.50",
                    "src_port": 52110,
                    "dst_port": 21,
                    "tcp_flags": "PA",
                    "dns_query": None,
                    "payload_summary": "USER admin | PASS SuperSecret123!"
                }
            elif i == 55:
                # DNS Tunneling query length anomaly
                long_domain = "a8f39b7d8c001e33f679bca3488d.exfil-data-chunk.c2server-malicious.org"
                info = {
                    "timestamp": timestamp,
                    "length": 142,
                    "protocol": "DNS",
                    "src_ip": "192.168.1.105",
                    "dst_ip": "8.8.8.8",
                    "src_port": 53535,
                    "dst_port": 53,
                    "tcp_flags": "",
                    "dns_query": long_domain,
                    "payload_summary": f"DNS Query: {long_domain}"
                }
            elif 60 <= i <= 70:
                # SYN flood pattern
                info = {
                    "timestamp": timestamp,
                    "length": 60,
                    "protocol": "TCP",
                    "src_ip": "198.51.100.77",
                    "dst_ip": "192.168.1.1",
                    "src_port": 30000 + i,
                    "dst_port": 80,
                    "tcp_flags": "S",
                    "dns_query": None,
                    "payload_summary": "TCP SYN Flood Flood Packet"
                }
            else:
                # Routine traffic
                proto = random.choice(["TCP", "UDP", "DNS", "ICMP"])
                src = random.choice(sample_ips)
                dst = random.choice(sample_ips)
                while dst == src:
                    dst = random.choice(sample_ips)
                
                dport = 443 if proto == "TCP" else (53 if proto == "DNS" else random.choice([80, 8080, 123]))
                info = {
                    "timestamp": timestamp,
                    "length": random.randint(64, 1480),
                    "protocol": proto,
                    "src_ip": src,
                    "dst_ip": dst,
                    "src_port": random.randint(30000, 60000),
                    "dst_port": dport,
                    "tcp_flags": "A" if proto == "TCP" else "",
                    "dns_query": "api.github.com" if proto == "DNS" else None,
                    "payload_summary": f"Standard {proto} Data Exchange"
                }

            alerts = self.process_packet(info)
            self._print_live_packet_summary(info, alerts)

        self.stats["end_time"] = time.time()

    def _print_live_packet_summary(self, info, alerts):
        proto_str = f"[{info['protocol']:<4}]"
        conn_str = f"{str(info['src_ip']):<15} -> {str(info['dst_ip']):<15}"
        port_str = f"Port: {info.get('dst_port') or 'N/A'}"
        
        print(f"{info['timestamp']} | {proto_str} | {conn_str} | {port_str:<10} | {info['length']:>5} B")
        for alert in alerts:
            print(f"   └──> \033[91m[ALERT - {alert['level']}] {alert['category']}: {alert['description']}\033[0m")
