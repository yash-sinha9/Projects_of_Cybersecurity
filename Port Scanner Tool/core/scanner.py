"""
Core Port Scanner Engine
Demonstrates low-level Python socket programming, TCP/UDP scanning,
banner grabbing, latency measurement, and multithreaded concurrency.
"""

import socket
import time
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional, Tuple, Any

from core.service_db import lookup_service


class ScanResult:
    def __init__(self, port: int, state: str, proto: str = "TCP",
                 latency_ms: float = 0.0, banner: str = "", service: str = "",
                 description: str = "", risk: str = "Low"):
        self.port = port
        self.state = state  # "OPEN", "CLOSED", "FILTERED", "OPEN|FILTERED"
        self.proto = proto
        self.latency_ms = round(latency_ms, 2)
        self.banner = banner
        self.service = service
        self.description = description
        self.risk = risk

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "state": self.state,
            "proto": self.proto,
            "latency_ms": self.latency_ms,
            "banner": self.banner,
            "service": self.service,
            "description": self.description,
            "risk": self.risk,
        }


class PortScanner:
    def __init__(self, target: str, ports: List[int], timeout: float = 1.0,
                 threads: int = 50, grab_banners: bool = True, scan_type: str = "TCP"):
        self.raw_target = target.strip()
        self.ports = sorted(list(set(ports)))
        self.timeout = timeout
        self.threads = min(max(threads, 1), 300)
        self.grab_banners = grab_banners
        self.scan_type = scan_type.upper()  # "TCP", "UDP", "BOTH"
        
        self.target_ip = ""
        self.hostname = ""
        self.results: List[ScanResult] = []
        self.start_time = 0.0
        self.end_time = 0.0
        self.is_running = False
        self._stop_requested = False

    def resolve_target(self) -> Tuple[bool, str]:
        """Resolves target hostname to IPv4 address."""
        try:
            self.target_ip = socket.gethostbyname(self.raw_target)
            try:
                self.hostname = socket.gethostbyaddr(self.target_ip)[0]
            except (socket.herror, socket.gaierror, socket.error):
                self.hostname = self.raw_target
            return True, f"Resolved {self.raw_target} -> {self.target_ip}"
        except socket.gaierror as e:
            return False, f"Could not resolve host '{self.raw_target}': {e}"

    def scan_tcp_port(self, port: int) -> ScanResult:
        """
        Executes a 3-way TCP Connect Handshake (SYN -> SYN/ACK -> ACK).
        Classifies port into OPEN, CLOSED, or FILTERED based on socket response.
        """
        svc_info = lookup_service(port, "TCP")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        t_start = time.perf_counter()
        
        try:
            res = s.connect_ex((self.target_ip, port))
            t_end = time.perf_counter()
            latency = (t_end - t_start) * 1000.0

            if res == 0:
                banner = ""
                if self.grab_banners:
                    banner = self._grab_banner_from_socket(s, port)
                s.close()
                return ScanResult(
                    port=port,
                    state="OPEN",
                    proto="TCP",
                    latency_ms=latency,
                    banner=banner,
                    service=svc_info["service"],
                    description=svc_info["desc"],
                    risk=svc_info["risk"]
                )
            elif res in (10061, 111):  # WSAECONNREFUSED on Windows or ECONNREFUSED on Linux
                s.close()
                return ScanResult(
                    port=port,
                    state="CLOSED",
                    proto="TCP",
                    latency_ms=latency,
                    service=svc_info["service"],
                    description=svc_info["desc"],
                    risk=svc_info["risk"]
                )
            else:
                # 10060 = WSAETIMEDOUT (packet dropped by firewall)
                s.close()
                return ScanResult(
                    port=port,
                    state="FILTERED",
                    proto="TCP",
                    latency_ms=latency,
                    service=svc_info["service"],
                    description=svc_info["desc"],
                    risk=svc_info["risk"]
                )
        except (socket.timeout, TimeoutError):
            s.close()
            return ScanResult(
                port=port,
                state="FILTERED",
                proto="TCP",
                latency_ms=self.timeout * 1000.0,
                service=svc_info["service"],
                description=svc_info["desc"],
                risk=svc_info["risk"]
            )
        except ConnectionRefusedError:
            s.close()
            return ScanResult(
                port=port,
                state="CLOSED",
                proto="TCP",
                latency_ms=(time.perf_counter() - t_start) * 1000.0,
                service=svc_info["service"],
                description=svc_info["desc"],
                risk=svc_info["risk"]
            )
        except Exception:
            s.close()
            return ScanResult(
                port=port,
                state="FILTERED",
                proto="TCP",
                latency_ms=self.timeout * 1000.0,
                service=svc_info["service"],
                description=svc_info["desc"],
                risk=svc_info["risk"]
            )

    def scan_udp_port(self, port: int) -> ScanResult:
        """
        Probes UDP service with protocol-specific datagrams.
        UDP is connectionless; lack of ICMP unreachable or receipt of response determines state.
        """
        svc_info = lookup_service(port, "UDP")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        t_start = time.perf_counter()
        
        # Build protocol-specific probes
        probe = b"\x00" * 4
        if port == 53:  # DNS Query Header for standard root lookup
            probe = b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03"
        elif port == 123:  # NTP Client Mode 3 packet
            probe = b"\x1b" + 47 * b"\0"
        elif port == 161:  # SNMP v1 GetNextRequest for sysDescr
            probe = b"\x30\x29\x02\x01\x00\x04\x06public\xa1\x1c\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"

        try:
            s.sendto(probe, (self.target_ip, port))
            data, _ = s.recvfrom(1024)
            latency = (time.perf_counter() - t_start) * 1000.0
            banner = data[:80].decode("latin-1", errors="ignore").strip()
            s.close()
            return ScanResult(
                port=port,
                state="OPEN",
                proto="UDP",
                latency_ms=latency,
                banner=banner,
                service=svc_info["service"],
                description=svc_info["desc"],
                risk=svc_info["risk"]
            )
        except (socket.timeout, TimeoutError):
            s.close()
            # In UDP scanning, no response indicates either OPEN or FILTERED by firewall
            return ScanResult(
                port=port,
                state="OPEN|FILTERED",
                proto="UDP",
                latency_ms=self.timeout * 1000.0,
                service=svc_info["service"],
                description=svc_info["desc"],
                risk=svc_info["risk"]
            )
        except ConnectionRefusedError:
            s.close()
            return ScanResult(
                port=port,
                state="CLOSED",
                proto="UDP",
                latency_ms=(time.perf_counter() - t_start) * 1000.0,
                service=svc_info["service"],
                description=svc_info["desc"],
                risk=svc_info["risk"]
            )
        except Exception:
            s.close()
            return ScanResult(
                port=port,
                state="FILTERED",
                proto="UDP",
                latency_ms=self.timeout * 1000.0,
                service=svc_info["service"],
                description=svc_info["desc"],
                risk=svc_info["risk"]
            )

    def _grab_banner_from_socket(self, s: socket.socket, port: int) -> str:
        """Sends application-layer probe triggers to extract service banner strings."""
        try:
            s.settimeout(0.75)
            if port in (80, 8080, 8000, 3000, 5000):
                probe = f"HEAD / HTTP/1.1\r\nHost: {self.target_ip}\r\nUser-Agent: PortScanner/2.0\r\nConnection: close\r\n\r\n"
                s.sendall(probe.encode("utf-8"))
            elif port in (21, 22, 25, 110, 143):
                # These protocols send a banner immediately upon connection
                pass
            elif port == 6379:
                s.sendall(b"INFO\r\n")
            elif port == 3306:
                # MySQL sends handshake packet automatically
                pass
            else:
                s.sendall(b"\r\n\r\n")
            
            data = s.recv(1024)
            if data:
                # Clean and sanitize received banner
                clean_lines = []
                for line in data.decode("latin-1", errors="ignore").splitlines():
                    clean = line.strip()
                    if clean:
                        clean_lines.append(clean)
                if clean_lines:
                    return clean_lines[0][:100]
        except Exception:
            pass
        return ""

    def stop(self):
        """Signals active scan to stop."""
        self._stop_requested = True

    def run_scan(self, progress_callback: Optional[Callable[[int, int, ScanResult], None]] = None) -> List[ScanResult]:
        """
        Runs multi-threaded scan over selected ports.
        Calls progress_callback(completed, total, latest_result) on each evaluated port.
        """
        self.is_running = True
        self._stop_requested = False
        self.results = []
        self.start_time = time.time()
        total_ports = len(self.ports)
        completed_count = 0

        scan_func = self.scan_tcp_port
        if self.scan_type == "UDP":
            scan_func = self.scan_udp_port

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {executor.submit(scan_func, p): p for p in self.ports}
            
            for future in as_completed(future_to_port):
                if self._stop_requested:
                    break
                try:
                    res = future.result()
                    self.results.append(res)
                except Exception as e:
                    port = future_to_port[future]
                    res = ScanResult(port=port, state="ERROR", banner=str(e))
                    self.results.append(res)
                
                completed_count += 1
                if progress_callback:
                    progress_callback(completed_count, total_ports, res)

        self.end_time = time.time()
        self.is_running = False
        self.results.sort(key=lambda x: x.port)
        return self.results

    def get_summary(self) -> Dict[str, Any]:
        """Calculates statistical summary of scan results."""
        duration = self.end_time - self.start_time if self.end_time > 0 else 0
        open_list = [r for r in self.results if r.state in ("OPEN", "OPEN|FILTERED")]
        closed_list = [r for r in self.results if r.state == "CLOSED"]
        filtered_list = [r for r in self.results if r.state == "FILTERED"]
        
        avg_latency = 0.0
        if open_list:
            avg_latency = sum(r.latency_ms for r in open_list) / len(open_list)
        
        return {
            "target": self.raw_target,
            "target_ip": self.target_ip,
            "hostname": self.hostname,
            "scan_type": self.scan_type,
            "total_ports_scanned": len(self.results),
            "open_ports_count": len(open_list),
            "closed_ports_count": len(closed_list),
            "filtered_ports_count": len(filtered_list),
            "scan_duration_sec": round(duration, 3),
            "ports_per_sec": round(len(self.results) / duration, 1) if duration > 0 else 0,
            "avg_open_latency_ms": round(avg_latency, 2),
            "open_ports": [r.to_dict() for r in open_list],
            "all_results": [r.to_dict() for r in self.results],
        }
