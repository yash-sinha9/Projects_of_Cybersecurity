#!/usr/bin/env python3
"""
Firewall Rules Audit & Perimeter Defense Tool
Author: Antigravity Cyber Security Suite
Description: Parses and audits Linux iptables firewall rules for security flaws,
             shadowed rules, overly permissive policies, and CIS/NIST compliance.
"""

import sys
import re
import json
import argparse
import ipaddress
from typing import List, Dict, Any, Optional, Tuple

# ANSI Colors for terminal output
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"

SENSITIVE_PORTS = {
    21: "FTP (Plaintext)",
    22: "SSH (Remote Admin)",
    23: "Telnet (Unencrypted Admin)",
    69: "TFTP (Trivial FTP)",
    135: "RPC / MS-RPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    445: "SMB (File Sharing)",
    1433: "MSSQL Server",
    1521: "Oracle DB",
    3306: "MySQL Server",
    3389: "RDP (Windows Remote Desktop)",
    5432: "PostgreSQL Database",
    5900: "VNC Remote Desktop",
    6379: "Redis In-Memory Store",
    8080: "HTTP Alternate / Dev Server",
    9200: "Elasticsearch",
    27017: "MongoDB Database",
}

CLEARTEXT_PORTS = {
    21: "FTP",
    23: "Telnet",
    80: "HTTP",
}


class FirewallRule:
    def __init__(self, raw_line: str, line_no: int, chain: str):
        self.raw_line = raw_line.strip()
        self.line_no = line_no
        self.chain = chain
        self.action = "UNKNOWN"
        self.protocol = "all"
        self.src_ip = "0.0.0.0/0"
        self.dst_ip = "0.0.0.0/0"
        self.in_interface = "any"
        self.out_interface = "any"
        self.sport = "any"
        self.dport = "any"
        self.state = "any"
        self.has_limit = False
        self.log_prefix = ""
        self.parse_rule()

    def parse_rule(self):
        tokens = self.raw_line.split()
        i = 0
        while i < len(tokens):
            token = tokens[i]
            if token in ("-j", "--jump") and i + 1 < len(tokens):
                self.action = tokens[i + 1].upper()
                i += 2
            elif token in ("-p", "--protocol") and i + 1 < len(tokens):
                self.protocol = tokens[i + 1].lower()
                i += 2
            elif token in ("-s", "--source") and i + 1 < len(tokens):
                self.src_ip = tokens[i + 1]
                i += 2
            elif token in ("-d", "--destination") and i + 1 < len(tokens):
                self.dst_ip = tokens[i + 1]
                i += 2
            elif token in ("-i", "--in-interface") and i + 1 < len(tokens):
                self.in_interface = tokens[i + 1]
                i += 2
            elif token in ("-o", "--out-interface") and i + 1 < len(tokens):
                self.out_interface = tokens[i + 1]
                i += 2
            elif token in ("--dport", "--destination-port") and i + 1 < len(tokens):
                self.dport = tokens[i + 1]
                i += 2
            elif token in ("--sport", "--source-port") and i + 1 < len(tokens):
                self.sport = tokens[i + 1]
                i += 2
            elif token in ("--ctstate", "--state") and i + 1 < len(tokens):
                self.state = tokens[i + 1].upper()
                i += 2
            elif token == "--limit" and i + 1 < len(tokens):
                self.has_limit = True
                i += 2
            elif token == "--log-prefix" and i + 1 < len(tokens):
                self.log_prefix = tokens[i + 1].strip('"\'')
                i += 2
            else:
                i += 1

        # Normalize IP representations
        if "/" not in self.src_ip and self.src_ip != "0.0.0.0/0":
            self.src_ip += "/32"
        if "/" not in self.dst_ip and self.dst_ip != "0.0.0.0/0":
            self.dst_ip += "/32"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "line_no": self.line_no,
            "chain": self.chain,
            "action": self.action,
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "in_interface": self.in_interface,
            "out_interface": self.out_interface,
            "dport": self.dport,
            "sport": self.sport,
            "state": self.state,
            "raw": self.raw_line
        }


class FirewallAuditor:
    def __init__(self, raw_content: str):
        self.raw_content = raw_content
        self.default_policies = {"INPUT": "ACCEPT", "FORWARD": "ACCEPT", "OUTPUT": "ACCEPT"}
        self.rules: List[FirewallRule] = []
        self.findings: List[Dict[str, Any]] = []
        self.shadowed_rules: List[Dict[str, Any]] = []
        self.redundant_rules: List[Dict[str, Any]] = []
        self.score = 100
        self.parse()

    def parse(self):
        lines = self.raw_content.splitlines()
        for idx, line in enumerate(lines, start=1):
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue

            # Parse default policies like :INPUT DROP [0:0]
            if clean.startswith(":"):
                match = re.match(r":(\w+)\s+(\w+)", clean)
                if match:
                    chain, policy = match.groups()
                    self.default_policies[chain.upper()] = policy.upper()
                continue

            # Parse iptables commands or table entries
            if clean.startswith("-A ") or "iptables" in clean:
                rule_part = clean
                if "iptables " in clean:
                    rule_part = clean.split("iptables ", 1)[1]
                
                chain_match = re.search(r"(?:-A|--append)\s+([A-Za-z0-9_-]+)", rule_part)
                chain = chain_match.group(1).upper() if chain_match else "INPUT"
                rule = FirewallRule(rule_part, idx, chain)
                self.rules.append(rule)

    def is_ip_contained(self, sub_ip: str, super_ip: str) -> bool:
        if super_ip == "0.0.0.0/0":
            return True
        if sub_ip == "0.0.0.0/0":
            return False
        try:
            n_sub = ipaddress.ip_network(sub_ip, strict=False)
            n_super = ipaddress.ip_network(super_ip, strict=False)
            return n_sub.subnet_of(n_super)
        except Exception:
            return sub_ip == super_ip

    def ports_overlap(self, p1: str, p2: str) -> bool:
        if p1 == "any" or p2 == "any":
            return True
        return p1 == p2

    def is_rule_subsumed(self, candidate: FirewallRule, earlier: FirewallRule) -> bool:
        """Checks if 'earlier' rule completely subsumes 'candidate' rule."""
        if earlier.chain != candidate.chain:
            return False
        if earlier.protocol != "all" and earlier.protocol != candidate.protocol:
            return False
        if earlier.in_interface != "any" and earlier.in_interface != candidate.in_interface:
            return False
        if earlier.out_interface != "any" and earlier.out_interface != candidate.out_interface:
            return False
        if not self.is_ip_contained(candidate.src_ip, earlier.src_ip):
            return False
        if not self.is_ip_contained(candidate.dst_ip, earlier.dst_ip):
            return False
        if not self.ports_overlap(candidate.dport, earlier.dport):
            return False
        if earlier.state != "any" and earlier.state != candidate.state:
            return False
        return True

    def audit(self):
        self.findings.clear()
        self.shadowed_rules.clear()
        self.redundant_rules.clear()
        deductions = 0

        # 1. Default Policy Audit (CIS Linux 3.4.1)
        for chain, policy in self.default_policies.items():
            if policy == "ACCEPT":
                severity = "CRITICAL" if chain in ("INPUT", "FORWARD") else "MEDIUM"
                pts = 20 if chain in ("INPUT", "FORWARD") else 10
                deductions += pts
                self.findings.append({
                    "id": f"DEF-POL-{chain}",
                    "severity": severity,
                    "title": f"Insecure Default Policy on Chain {chain}",
                    "detail": f"Default policy for '{chain}' is set to ACCEPT. Perimeter must default to DROP to enforce Zero-Trust defense.",
                    "remediation": f"Set default policy to DROP: 'iptables -P {chain} DROP' and explicitly allow required traffic.",
                    "cve_ref": "CIS Benchmark 3.4.1 / PCI-DSS Req 1.2"
                })

        # 2. Check for missing Loopback rule
        has_loopback = any(
            r.chain == "INPUT" and (r.in_interface == "lo" or r.src_ip == "127.0.0.1/32") and r.action == "ACCEPT"
            for r in self.rules
        )
        if not has_loopback and self.default_policies.get("INPUT") == "DROP":
            deductions += 10
            self.findings.append({
                "id": "SYS-LO-MISSING",
                "severity": "HIGH",
                "title": "Missing Local Loopback (lo) Acceptance",
                "detail": "No explicit rule allows traffic on loopback interface 'lo'. Local services (systemd, IPC, DB sockets) may malfunction.",
                "remediation": "Add rule: 'iptables -A INPUT -i lo -j ACCEPT' and 'iptables -A OUTPUT -o lo -j ACCEPT'.",
                "cve_ref": "CIS Benchmark 3.4.2"
            })

        # 3. Check for Stateful Inspection (conntrack RELATED,ESTABLISHED)
        has_stateful = any(
            "ESTABLISHED" in r.state and r.action == "ACCEPT"
            for r in self.rules
        )
        if not has_stateful:
            deductions += 15
            self.findings.append({
                "id": "NET-STATEFUL-MISSING",
                "severity": "HIGH",
                "title": "Missing Stateful Connection Tracking",
                "detail": "No rule allowing established and related connections was detected. Causes asymmetric routing drops or forces stateless wide-open configurations.",
                "remediation": "Add: 'iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT'.",
                "cve_ref": "NIST SP 800-41 Rev 2"
            })

        # 4. Check for Outbound Egress Restriction
        if self.default_policies.get("OUTPUT") == "ACCEPT":
            loose_egress = not any(r.chain == "OUTPUT" and r.action in ("DROP", "REJECT") for r in self.rules)
            if loose_egress:
                deductions += 10
                self.findings.append({
                    "id": "NET-LOOSE-EGRESS",
                    "severity": "MEDIUM",
                    "title": "Unrestricted Outbound Egress Traffic",
                    "detail": "OUTPUT chain allows all unrestricted egress. If host is compromised, malware or C2 reverse shells can communicate freely.",
                    "remediation": "Default OUTPUT to DROP or restrict outbound to essential ports (DNS:53, NTP:123, HTTPS:443).",
                    "cve_ref": "MITRE ATT&CK T1071 / PCI-DSS 1.3"
                })

        # 5. Rule-by-rule analysis
        for idx, rule in enumerate(self.rules):
            # Check for overly permissive sensitive ports
            if rule.action == "ACCEPT" and rule.src_ip == "0.0.0.0/0":
                try:
                    port_num = int(rule.dport) if rule.dport != "any" else None
                except ValueError:
                    port_num = None

                if port_num in SENSITIVE_PORTS:
                    service = SENSITIVE_PORTS[port_num]
                    severity = "CRITICAL" if port_num in (22, 23, 3389, 3306, 5432, 6379, 27017) else "HIGH"
                    pts = 15 if severity == "CRITICAL" else 8
                    deductions += pts
                    self.findings.append({
                        "id": f"EXP-PORT-{port_num}-L{rule.line_no}",
                        "severity": severity,
                        "title": f"Overly Permissive Access to {service} (Port {port_num})",
                        "detail": f"Rule on line {rule.line_no} allows unrestricted 0.0.0.0/0 ingress to port {port_num} ({service}).",
                        "remediation": f"Restrict source IP using '-s <MANAGEMENT_IP_OR_SUBNET>' rather than 0.0.0.0/0.",
                        "cve_ref": "CWE-284 / NIST 800-41"
                    })

                # Cleartext protocols
                if port_num in CLEARTEXT_PORTS:
                    proto_name = CLEARTEXT_PORTS[port_num]
                    if port_num == 23:
                        deductions += 10
                        self.findings.append({
                            "id": f"CLEARTEXT-{proto_name}-L{rule.line_no}",
                            "severity": "CRITICAL",
                            "title": f"Unencrypted Cleartext Protocol ({proto_name}) Allowed",
                            "detail": f"Line {rule.line_no} exposes Telnet (port 23). Transmits credentials and shell data in plaintext.",
                            "remediation": "Disable Telnet daemon immediately; replace with SSH key-based access.",
                            "cve_ref": "PCI-DSS 4.1"
                        })

            # Check for Shadowed Rules and Redundancy
            for prior_idx in range(idx):
                prior_rule = self.rules[prior_idx]
                if self.is_rule_subsumed(rule, prior_rule):
                    if prior_rule.action == rule.action:
                        # Redundant / duplicate
                        self.redundant_rules.append({
                            "rule_line": rule.line_no,
                            "prior_line": prior_rule.line_no,
                            "detail": f"Rule on line {rule.line_no} is completely redundant with line {prior_rule.line_no}."
                        })
                    else:
                        # Shadowed (e.g. prior allows all, current drops specific, but prior already matched)
                        deductions += 10
                        shadow_item = {
                            "shadowed_line": rule.line_no,
                            "by_line": prior_rule.line_no,
                            "chain": rule.chain,
                            "action": rule.action,
                            "prior_action": prior_rule.action,
                            "detail": f"Rule #{idx+1} (Line {rule.line_no}: {rule.action}) is SHADOWED by earlier Rule #{prior_idx+1} (Line {prior_rule.line_no}: {prior_rule.action}) and will NEVER be triggered!"
                        }
                        self.shadowed_rules.append(shadow_item)
                        self.findings.append({
                            "id": f"SHADOW-L{rule.line_no}",
                            "severity": "HIGH",
                            "title": f"Shadowed Dead Rule Detected (Line {rule.line_no})",
                            "detail": shadow_item["detail"],
                            "remediation": f"Move the specific rule (Line {rule.line_no}) ABOVE the broader rule (Line {prior_rule.line_no}) using 'iptables -I'.",
                            "cve_ref": "Firewall Rule Ordering Flaw / NIST SP 800-41"
                        })
                    break

        self.score = max(0, 100 - deductions)

    def get_grade(self) -> str:
        if self.score >= 95:
            return "A+"
        elif self.score >= 85:
            return "A"
        elif self.score >= 75:
            return "B"
        elif self.score >= 60:
            return "C"
        elif self.score >= 45:
            return "D"
        else:
            return "F"

    def simulate_packet(self, src_ip: str, dst_ip: str, proto: str, dport: int, chain: str = "INPUT") -> Dict[str, Any]:
        """Simulates how a packet traverses the chain step-by-step using first-match-wins logic."""
        steps = []
        for idx, rule in enumerate(self.rules):
            if rule.chain != chain:
                continue

            matched = True
            reasons = []

            # Protocol check
            if rule.protocol != "all" and rule.protocol != proto.lower():
                matched = False
                reasons.append(f"Proto mismatch ({proto} != {rule.protocol})")

            # Port check
            if matched and rule.dport != "any":
                try:
                    if int(rule.dport) != dport:
                        matched = False
                        reasons.append(f"Port mismatch ({dport} != {rule.dport})")
                except ValueError:
                    if rule.dport != str(dport):
                        matched = False

            # Source IP check
            if matched and rule.src_ip != "0.0.0.0/0":
                try:
                    net = ipaddress.ip_network(rule.src_ip, strict=False)
                    host = ipaddress.ip_address(src_ip)
                    if host not in net:
                        matched = False
                        reasons.append(f"Source IP {src_ip} not in {rule.src_ip}")
                except Exception:
                    pass

            # Destination IP check
            if matched and rule.dst_ip != "0.0.0.0/0":
                try:
                    net = ipaddress.ip_network(rule.dst_ip, strict=False)
                    host = ipaddress.ip_address(dst_ip)
                    if host not in net:
                        matched = False
                        reasons.append(f"Dest IP {dst_ip} not in {rule.dst_ip}")
                except Exception:
                    pass

            step_info = {
                "rule_number": idx + 1,
                "line_no": rule.line_no,
                "raw": rule.raw_line,
                "matched": matched,
                "action": rule.action,
                "notes": ", ".join(reasons) if not matched else "Criteria satisfied"
            }
            steps.append(step_info)

            if matched:
                return {
                    "verdict": rule.action,
                    "matched_rule": step_info,
                    "is_default_policy": False,
                    "chain": chain,
                    "evaluation_steps": steps
                }

        # Fallback to chain default policy
        default_policy = self.default_policies.get(chain, "DROP")
        return {
            "verdict": default_policy,
            "matched_rule": None,
            "is_default_policy": True,
            "chain": chain,
            "evaluation_steps": steps,
            "notes": f"Packet reached end of {chain} chain. Default policy [{default_policy}] applied."
        }

    def print_cli_report(self):
        grade = self.get_grade()
        grade_color = GREEN if self.score >= 80 else (YELLOW if self.score >= 60 else RED)

        print(f"\n{BOLD}{CYAN}{'=' * 75}{RESET}")
        print(f"{BOLD}{WHITE}🛡️  NETWORK SECURITY: FIREWALL RULES AUDIT REPORT{RESET}")
        print(f"{BOLD}{CYAN}{'=' * 75}{RESET}\n")

        print(f"{BOLD}Default Policies:{RESET}")
        for chain, pol in self.default_policies.items():
            col = RED if pol == "ACCEPT" else GREEN
            print(f"  • {chain:<8}: {col}{pol}{RESET}")

        print(f"\n{BOLD}Total Rules Audited:{RESET} {len(self.rules)}")
        print(f"{BOLD}Security Posture Score:{RESET} {grade_color}{self.score}/100 (Grade: {grade}){RESET}\n")

        # Findings
        print(f"{BOLD}{YELLOW}━━━ SECURITY GAPS & VULNERABILITY FINDINGS ({len(self.findings)}) ━━━{RESET}")
        if not self.findings:
            print(f"  {GREEN}✔ No critical firewall flaws found! Ruleset conforms to baseline hardening.{RESET}")
        else:
            for idx, f in enumerate(self.findings, 1):
                sev_color = RED if f["severity"] == "CRITICAL" else (YELLOW if f["severity"] == "HIGH" else BLUE)
                print(f"\n{sev_color}[{f['severity']}]{RESET} {BOLD}{f['title']}{RESET} ({f['cve_ref']})")
                print(f"  {WHITE}Detail:{RESET}      {f['detail']}")
                print(f"  {CYAN}Remediation:{RESET} {f['remediation']}")

        # Shadowed Rules Section
        if self.shadowed_rules:
            print(f"\n{BOLD}{RED}━━━ SHADOWED / DEAD RULES DETECTED ({len(self.shadowed_rules)}) ━━━{RESET}")
            for sh in self.shadowed_rules:
                print(f"  {RED}✖{RESET} {sh['detail']}")

        # Redundant Rules Section
        if self.redundant_rules:
            print(f"\n{BOLD}{YELLOW}━━━ REDUNDANT RULES ({len(self.redundant_rules)}) ━━━{RESET}")
            for rd in self.redundant_rules:
                print(f"  {YELLOW}⚠{RESET} {rd['detail']}")

        print(f"\n{BOLD}{CYAN}{'=' * 75}{RESET}\n")


def main():
    parser = argparse.ArgumentParser(description="Firewall Rules Audit & Security Analyzer")
    parser.add_argument("file", help="Path to iptables-save dump file or iptables rule script")
    parser.add_argument("--json", action="store_true", help="Output audit report in JSON format")
    parser.add_argument("--test-packet", nargs=4, metavar=("SRC_IP", "DST_IP", "PROTO", "PORT"),
                        help="Simulate a packet traversal: e.g. --test-packet 198.51.100.50 10.0.0.5 tcp 22")
    args = parser.parse_args()

    try:
        with open(args.file, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        print(f"{RED}Error reading file '{args.file}': {e}{RESET}")
        sys.exit(1)

    auditor = FirewallAuditor(content)
    auditor.audit()

    if args.test_packet:
        src, dst, proto, port = args.test_packet
        res = auditor.simulate_packet(src, dst, proto, int(port))
        print(f"\n{BOLD}{MAGENTA}--- Packet Simulation Result ---{RESET}")
        print(f"Packet: {src} -> {dst} ({proto.upper()}:{port})")
        print(f"Verdict: {GREEN if res['verdict'] == 'ACCEPT' else RED}{res['verdict']}{RESET}")
        if res["is_default_policy"]:
            print(f"Matched: Default Chain Policy ({res['chain']})")
        else:
            mr = res["matched_rule"]
            print(f"Matched Rule #{mr['rule_number']} (Line {mr['line_no']}): {mr['raw']}")
        print()
        sys.exit(0)

    if args.json:
        report = {
            "score": auditor.score,
            "grade": auditor.get_grade(),
            "default_policies": auditor.default_policies,
            "total_rules": len(auditor.rules),
            "findings": auditor.findings,
            "shadowed_rules": auditor.shadowed_rules,
            "redundant_rules": auditor.redundant_rules,
            "rules": [r.to_dict() for r in auditor.rules]
        }
        print(json.dumps(report, indent=2))
    else:
        auditor.print_cli_report()


if __name__ == "__main__":
    main()
