"""
Custom Port Scanner - High-Tech Desktop GUI Application
Dark Cyber Aesthetic, Live Real-time Treeview, Multi-threaded Scanning,
Banner Inspector, and Nmap Comparative Benchmarking.
"""

import os
import sys
import time
import json
import csv
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import List

# Ensure core package can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.scanner import PortScanner, ScanResult
from core.service_db import PORT_SETS, lookup_service
from core.nmap_compare import COMPARISON_MATRIX, get_nmap_comparison_report

# Dark Cybersecurity Color Palette
BG_DARK = "#0d1117"
BG_CARD = "#161b22"
BG_INPUT = "#21262d"
BORDER_COLOR = "#30363d"
TEXT_PRIMARY = "#f0f6fc"
TEXT_SECONDARY = "#8b949e"
ACCENT_CYAN = "#58a6ff"
ACCENT_GREEN = "#3fb950"
ACCENT_RED = "#f85149"
ACCENT_YELLOW = "#d29922"
ACCENT_PURPLE = "#bc8cff"


class PortScannerGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("ApexPort Scanner v2.0 - Network Security Tool")
        self.root.geometry("1120x760")
        self.root.minsize(980, 680)
        self.root.configure(bg=BG_DARK)

        self.scanner_instance: PortScanner = None
        self.scan_thread: threading.Thread = None
        self.scan_active = False
        self.scan_start_time = 0.0
        self.results: List[ScanResult] = []

        self._setup_styles()
        self._build_ui()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        # Configure generic TTK widgets
        style.configure(".", background=BG_DARK, foreground=TEXT_PRIMARY, font=("Segoe UI", 9))
        style.configure("TNotebook", background=BG_DARK, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG_CARD, foreground=TEXT_SECONDARY,
                        padding=[14, 8], font=("Segoe UI", 10, "bold"), borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", BG_INPUT)],
                  foreground=[("selected", ACCENT_CYAN)])

        # Treeview styling
        style.configure("Treeview",
                        background=BG_CARD,
                        foreground=TEXT_PRIMARY,
                        fieldbackground=BG_CARD,
                        rowheight=28,
                        font=("Consolas", 9),
                        borderwidth=0)
        style.configure("Treeview.Heading",
                        background=BG_INPUT,
                        foreground=TEXT_PRIMARY,
                        font=("Segoe UI", 9, "bold"),
                        relief="flat",
                        padding=6)
        style.map("Treeview",
                  background=[("selected", "#1f3a5f")],
                  foreground=[("selected", "#ffffff")])
        style.map("Treeview.Heading",
                  background=[("active", "#2d333b")])

        # Progressbar styling
        style.configure("Horizontal.TProgressbar",
                        background=ACCENT_CYAN,
                        troughcolor=BG_INPUT,
                        borderwidth=0,
                        thickness=10)

    def _build_ui(self):
        # Top Header Bar
        header = tk.Frame(self.root, bg=BG_CARD, padx=20, pady=12, highlightbackground=BORDER_COLOR, highlightthickness=1)
        header.pack(fill=tk.X, side=tk.TOP)

        title_frame = tk.Frame(header, bg=BG_CARD)
        title_frame.pack(side=tk.LEFT)

        title_lbl = tk.Label(title_frame, text="⚡ ApexPort Network Scanner", font=("Segoe UI", 16, "bold"),
                             fg=ACCENT_CYAN, bg=BG_CARD)
        title_lbl.pack(anchor="w")

        sub_lbl = tk.Label(title_frame, text="Custom Python Socket Engine • TCP/UDP Handshake • Banner Grabbing • Nmap Benchmark",
                           font=("Segoe UI", 9), fg=TEXT_SECONDARY, bg=BG_CARD)
        sub_lbl.pack(anchor="w")

        # Top Control / Inputs Panel
        config_frame = tk.Frame(self.root, bg=BG_CARD, padx=20, pady=12, highlightbackground=BORDER_COLOR, highlightthickness=1)
        config_frame.pack(fill=tk.X, padx=16, pady=10)

        # Row 1 Inputs: Target, Port Presets, Scan Type, Threads
        r1 = tk.Frame(config_frame, bg=BG_CARD)
        r1.pack(fill=tk.X)

        tk.Label(r1, text="Target Host / IP:", font=("Segoe UI", 9, "bold"), fg=TEXT_PRIMARY, bg=BG_CARD).pack(side=tk.LEFT, padx=(0, 6))
        self.target_entry = tk.Entry(r1, bg=BG_INPUT, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY,
                                     relief="flat", font=("Segoe UI", 10), width=18)
        self.target_entry.insert(0, "127.0.0.1")
        self.target_entry.pack(side=tk.LEFT, padx=(0, 16), ipady=3)

        tk.Label(r1, text="Ports:", font=("Segoe UI", 9, "bold"), fg=TEXT_PRIMARY, bg=BG_CARD).pack(side=tk.LEFT, padx=(0, 6))
        self.port_preset_var = tk.StringVar(value="Quick Top 20")
        presets = ["Quick Top 20", "Top 50 Common", "Well-Known (1-1024)", "Custom Range"]
        self.preset_menu = ttk.Combobox(r1, textvariable=self.port_preset_var, values=presets, width=18, state="readonly")
        self.preset_menu.pack(side=tk.LEFT, padx=(0, 6))
        self.preset_menu.bind("<<ComboboxSelected>>", self._on_preset_change)

        self.custom_ports_entry = tk.Entry(r1, bg=BG_INPUT, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY,
                                           relief="flat", font=("Segoe UI", 10), width=16)
        self.custom_ports_entry.insert(0, "21,22,80,443,3306")
        self.custom_ports_entry.pack(side=tk.LEFT, padx=(0, 16), ipady=3)
        self.custom_ports_entry.configure(state="disabled")

        tk.Label(r1, text="Mode:", font=("Segoe UI", 9, "bold"), fg=TEXT_PRIMARY, bg=BG_CARD).pack(side=tk.LEFT, padx=(0, 6))
        self.proto_var = tk.StringVar(value="TCP")
        proto_cb = ttk.Combobox(r1, textvariable=self.proto_var, values=["TCP", "UDP"], width=6, state="readonly")
        proto_cb.pack(side=tk.LEFT, padx=(0, 16))

        tk.Label(r1, text="Threads:", font=("Segoe UI", 9, "bold"), fg=TEXT_PRIMARY, bg=BG_CARD).pack(side=tk.LEFT, padx=(0, 6))
        self.threads_var = tk.IntVar(value=75)
        threads_spin = tk.Spinbox(r1, from_=5, to=300, textvariable=self.threads_var, width=5, bg=BG_INPUT, fg=TEXT_PRIMARY, relief="flat")
        threads_spin.pack(side=tk.LEFT, padx=(0, 16))

        self.banner_chk_var = tk.BooleanVar(value=True)
        chk = tk.Checkbutton(r1, text="Banner Grab (-sV)", variable=self.banner_chk_var, bg=BG_CARD, fg=TEXT_PRIMARY,
                             selectcolor=BG_INPUT, activebackground=BG_CARD, activeforeground=ACCENT_CYAN)
        chk.pack(side=tk.LEFT)

        # Action Buttons Row
        r2 = tk.Frame(config_frame, bg=BG_CARD, pady=10)
        r2.pack(fill=tk.X)

        self.btn_scan = tk.Button(r2, text="▶ START SCAN", bg=ACCENT_GREEN, fg="#ffffff", font=("Segoe UI", 10, "bold"),
                                  activebackground="#349b42", activeforeground="#ffffff", relief="flat", padx=16, pady=5,
                                  cursor="hand2", command=self.start_scan)
        self.btn_scan.pack(side=tk.LEFT, padx=(0, 8))

        self.btn_stop = tk.Button(r2, text="⏹ STOP", bg="#b62324", fg="#ffffff", font=("Segoe UI", 10, "bold"),
                                  activebackground="#961b1c", activeforeground="#ffffff", relief="flat", padx=14, pady=5,
                                  cursor="hand2", command=self.stop_scan, state="disabled")
        self.btn_stop.pack(side=tk.LEFT, padx=(0, 16))

        self.btn_nmap = tk.Button(r2, text="⚖️ Nmap Benchmark", bg=BG_INPUT, fg=ACCENT_PURPLE, font=("Segoe UI", 9, "bold"),
                                  activebackground=BORDER_COLOR, activeforeground="#ffffff", relief="flat", padx=12, pady=5,
                                  cursor="hand2", command=self.show_nmap_benchmark)
        self.btn_nmap.pack(side=tk.LEFT, padx=(0, 8))

        self.btn_export_json = tk.Button(r2, text="💾 Export JSON", bg=BG_INPUT, fg=ACCENT_CYAN, font=("Segoe UI", 9),
                                         activebackground=BORDER_COLOR, activeforeground="#ffffff", relief="flat", padx=12, pady=5,
                                         cursor="hand2", command=self.export_json)
        self.btn_export_json.pack(side=tk.LEFT, padx=(0, 8))

        self.btn_export_csv = tk.Button(r2, text="📄 Export CSV", bg=BG_INPUT, fg=TEXT_PRIMARY, font=("Segoe UI", 9),
                                        activebackground=BORDER_COLOR, activeforeground="#ffffff", relief="flat", padx=12, pady=5,
                                        cursor="hand2", command=self.export_csv)
        self.btn_export_csv.pack(side=tk.LEFT)

        # Status & Metric Cards
        metric_bar = tk.Frame(self.root, bg=BG_DARK, padx=16)
        metric_bar.pack(fill=tk.X, pady=(0, 10))

        self.card_scanned = self._create_metric_card(metric_bar, "TOTAL SCANNED", "0", TEXT_PRIMARY)
        self.card_open = self._create_metric_card(metric_bar, "OPEN PORTS", "0", ACCENT_GREEN)
        self.card_filtered = self._create_metric_card(metric_bar, "FILTERED", "0", ACCENT_YELLOW)
        self.card_closed = self._create_metric_card(metric_bar, "CLOSED", "0", ACCENT_RED)
        self.card_speed = self._create_metric_card(metric_bar, "SPEED", "0 p/s", ACCENT_CYAN)

        # Progress bar
        self.prog_frame = tk.Frame(self.root, bg=BG_DARK, padx=16)
        self.prog_frame.pack(fill=tk.X, pady=(0, 6))

        self.progress_bar = ttk.Progressbar(self.prog_frame, style="Horizontal.TProgressbar", mode="determinate")
        self.progress_bar.pack(fill=tk.X)

        self.lbl_status = tk.Label(self.prog_frame, text="Ready. Enter a target and click Start Scan.",
                                   font=("Segoe UI", 8), fg=TEXT_SECONDARY, bg=BG_DARK, anchor="w")
        self.lbl_status.pack(fill=tk.X, pady=(4, 0))

        # Main Tabs Area
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 16))

        # Tab 1: Live Results Table
        self.tab_results = tk.Frame(self.notebook, bg=BG_CARD)
        self.notebook.add(self.tab_results, text=" 📊 Port Matrix & Results ")
        self._build_results_table(self.tab_results)

        # Tab 2: Service Inspector
        self.tab_inspector = tk.Frame(self.notebook, bg=BG_CARD)
        self.notebook.add(self.tab_inspector, text=" 🔍 Banner & Service Inspector ")
        self._build_inspector_tab(self.tab_inspector)

        # Tab 3: Nmap Comparison
        self.tab_nmap = tk.Frame(self.notebook, bg=BG_CARD)
        self.notebook.add(self.tab_nmap, text=" ⚖️ Nmap Benchmark Comparison ")
        self._build_nmap_tab(self.tab_nmap)

        # Tab 4: Raw Terminal Console
        self.tab_log = tk.Frame(self.notebook, bg=BG_CARD)
        self.notebook.add(self.tab_log, text=" 💻 Live Activity Log ")
        self._build_log_tab(self.tab_log)

    def _create_metric_card(self, parent, label: str, value: str, color: str):
        card = tk.Frame(parent, bg=BG_CARD, padx=14, pady=8, highlightbackground=BORDER_COLOR, highlightthickness=1)
        card.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=4)

        lbl = tk.Label(card, text=label, font=("Segoe UI", 7, "bold"), fg=TEXT_SECONDARY, bg=BG_CARD)
        lbl.pack(anchor="w")

        val_lbl = tk.Label(card, text=value, font=("Segoe UI", 15, "bold"), fg=color, bg=BG_CARD)
        val_lbl.pack(anchor="w")
        return val_lbl

    def _build_results_table(self, parent):
        table_frame = tk.Frame(parent, bg=BG_CARD)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        cols = ("port", "proto", "state", "service", "latency", "risk", "banner")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")

        self.tree.heading("port", text="Port")
        self.tree.heading("proto", text="Proto")
        self.tree.heading("state", text="State")
        self.tree.heading("service", text="Service")
        self.tree.heading("latency", text="Latency (ms)")
        self.tree.heading("risk", text="Risk Rating")
        self.tree.heading("banner", text="Service Banner / Handshake")

        self.tree.column("port", width=80, anchor="center")
        self.tree.column("proto", width=70, anchor="center")
        self.tree.column("state", width=90, anchor="center")
        self.tree.column("service", width=120, anchor="w")
        self.tree.column("latency", width=100, anchor="center")
        self.tree.column("risk", width=90, anchor="center")
        self.tree.column("banner", width=420, anchor="w")

        # Color tags
        self.tree.tag_configure("OPEN", foreground=ACCENT_GREEN)
        self.tree.tag_configure("CLOSED", foreground=ACCENT_RED)
        self.tree.tag_configure("FILTERED", foreground=ACCENT_YELLOW)

        sb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<<TreeviewSelect>>", self._on_port_selected)

    def _build_inspector_tab(self, parent):
        pane = tk.Frame(parent, bg=BG_CARD, padx=20, pady=20)
        pane.pack(fill=tk.BOTH, expand=True)

        self.inspect_title = tk.Label(pane, text="Select an open port from Results to inspect handshake & payload.",
                                      font=("Segoe UI", 13, "bold"), fg=ACCENT_CYAN, bg=BG_CARD)
        self.inspect_title.pack(anchor="w", pady=(0, 10))

        self.inspect_details = tk.Text(pane, bg=BG_INPUT, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY,
                                       font=("Consolas", 10), relief="flat", wrap="word", padx=12, pady=12)
        self.inspect_details.pack(fill=tk.BOTH, expand=True)
        self.inspect_details.insert(tk.END, "No port currently selected.\n\nRun a scan and click any row to view:\n• TCP/UDP socket layer details\n• Application layer banner extraction\n• CVE & Security Risk Rating\n• Service signature breakdown")
        self.inspect_details.configure(state="disabled")

    def _build_nmap_tab(self, parent):
        pane = tk.Frame(parent, bg=BG_CARD, padx=20, pady=15)
        pane.pack(fill=tk.BOTH, expand=True)

        lbl = tk.Label(pane, text="Why Industry & Recruiters Value This Custom Socket Scanner",
                       font=("Segoe UI", 13, "bold"), fg=ACCENT_PURPLE, bg=BG_CARD)
        lbl.pack(anchor="w", pady=(0, 10))

        text_area = tk.Text(pane, bg=BG_INPUT, fg=TEXT_PRIMARY, font=("Segoe UI", 9), relief="flat", wrap="word", padx=12, pady=10)
        text_area.pack(fill=tk.BOTH, expand=True)

        content = """★ PROJECT SHOWCASE: WHY BUILDING A PORT SCANNER MATTERS ★

Recruiters love seeing candidates who can build tools, not just run existing utilities.
Anyone can type 'nmap -sT target.com', but writing a socket-level scanner demonstrates core systems and security mastery.

------------------------------------------------------------------------------------------------------
CORE ARCHITECTURAL COMPARISONS:
------------------------------------------------------------------------------------------------------
"""
        for item in COMPARISON_MATRIX:
            content += f"▶ {item['criterion']}:\n"
            content += f"   • Our Custom Scanner : {item['custom_scanner']}\n"
            content += f"   • Nmap Default Engine: {item['nmap_default']}\n"
            content += f"   • Recruiter Takeaway : {item['industry_takeaway']}\n\n"

        content += """------------------------------------------------------------------------------------------------------
KEY INTERVIEW QUESTIONS YOU CAN NOW ANSWER CONFIDENTLY:
------------------------------------------------------------------------------------------------------
1. How does a TCP Connect scan differ from a TCP SYN scan at the packet level?
   Answer: A TCP Connect scan invokes the OS connect() API, completing the full 3-way handshake (SYN, SYN/ACK, ACK).
   A SYN scan crafts raw IP/TCP packets, sends SYN, receives SYN/ACK, and immediately aborts with RST, never completing the session.

2. How do operating system error codes correspond to port states?
   Answer: 0 indicates socket connected (OPEN). WSAECONNREFUSED (10061/111) indicates an active TCP RST packet from target (CLOSED).
   WSAETIMEDOUT (10060) indicates dropped packets by a stateful firewall or no response (FILTERED).

3. Why is UDP scanning significantly harder and slower than TCP scanning?
   Answer: UDP is connectionless. There is no SYN-ACK handshake. Probing requires protocol-specific payloads. If no response is received,
   the port may be open or filtered by a firewall (OPEN|FILTERED). If closed, the target OS may emit an ICMP Type 3 Code 3 (Port Unreachable)
   which is rate-limited by OS kernels (e.g. Linux limits to 1 per second).
"""
        text_area.insert(tk.END, content)
        text_area.configure(state="disabled")

    def _build_log_tab(self, parent):
        pane = tk.Frame(parent, bg=BG_CARD, padx=10, pady=10)
        pane.pack(fill=tk.BOTH, expand=True)

        self.log_text = tk.Text(pane, bg=BG_INPUT, fg="#a6e22e", font=("Consolas", 9), relief="flat", wrap="word")
        sb = ttk.Scrollbar(pane, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=sb.set)

        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

    def _log(self, text: str):
        self.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {text}\n")
        self.log_text.see(tk.END)

    def _on_preset_change(self, event=None):
        preset = self.port_preset_var.get()
        if preset == "Custom Range":
            self.custom_ports_entry.configure(state="normal")
        else:
            self.custom_ports_entry.configure(state="disabled")

    def _on_port_selected(self, event=None):
        selected_item = self.tree.selection()
        if not selected_item:
            return
        vals = self.tree.item(selected_item[0], "values")
        if not vals:
            return

        port = int(vals[0])
        proto = vals[1]
        state = vals[2]
        service = vals[3]
        latency = vals[4]
        risk = vals[5]
        banner = vals[6]

        info = lookup_service(port, proto)
        self.inspect_title.configure(text=f"Port {port}/{proto} — {service} [{state}]")

        self.inspect_details.configure(state="normal")
        self.inspect_details.delete("1.0", tk.END)
        details = f"""======================================================================
PORT INSPECTION & SECURITY DETAILS
======================================================================
Port Number       : {port}
Protocol          : {proto}
Discovered State  : {state}
Service Name      : {service}
Measured Latency  : {latency} ms
Security Risk     : {risk}

TECHNICAL DESCRIPTION:
{info['desc']}

APPLICATION BANNER / RESPONSE:
{banner if banner else '(No banner emitted during handshake or banner grab timed out)'}

SECURITY ANALYSIS:
• State Assessment: {state} state verified via OS socket connect_ex / UDP probe.
• Common Attack Vectors: {'Common target for brute-force and remote code execution if misconfigured.' if risk in ('High', 'Critical') else 'Standard operational service.'}
• Defense Recommendation: Restrict port access via firewall rules (iptables/Windows Defender Firewall) or bind to localhost if unneeded publicly.
"""
        self.inspect_details.insert(tk.END, details)
        self.inspect_details.configure(state="disabled")

    def start_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please specify a target hostname or IP.")
            return

        # Determine ports
        preset = self.port_preset_var.get()
        if preset == "Quick Top 20":
            ports = PORT_SETS["quick"]
        elif preset == "Top 50 Common":
            ports = PORT_SETS["top50"]
        elif preset == "Well-Known (1-1024)":
            ports = PORT_SETS["well_known"]
        else:
            raw = self.custom_ports_entry.get().strip()
            from port_scanner_cli import parse_ports
            ports = parse_ports(raw)

        if not ports:
            messagebox.showerror("Error", "No valid ports specified.")
            return

        # Reset UI
        for row in self.tree.get_children():
            self.tree.delete(row)

        self.card_scanned.configure(text="0")
        self.card_open.configure(text="0")
        self.card_filtered.configure(text="0")
        self.card_closed.configure(text="0")
        self.card_speed.configure(text="0 p/s")
        self.progress_bar["value"] = 0
        self.progress_bar["maximum"] = len(ports)

        self.results = []
        self.scan_active = True
        self.btn_scan.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.lbl_status.configure(text=f"Resolving target '{target}'...")

        self.scanner_instance = PortScanner(
            target=target,
            ports=ports,
            timeout=1.0,
            threads=self.threads_var.get(),
            grab_banners=self.banner_chk_var.get(),
            scan_type=self.proto_var.get()
        )

        self.scan_thread = threading.Thread(target=self._run_scan_worker, daemon=True)
        self.scan_thread.start()

    def _run_scan_worker(self):
        self.scan_start_time = time.time()
        self._log(f"Initiating scan against {self.scanner_instance.raw_target}")

        resolved, msg = self.scanner_instance.resolve_target()
        if not resolved:
            self.root.after(0, lambda: messagebox.showerror("Host Error", msg))
            self.root.after(0, self._scan_finished)
            return

        self._log(msg)
        self.root.after(0, lambda: self.lbl_status.configure(text=f"Scanning {self.scanner_instance.target_ip} ({len(self.scanner_instance.ports)} ports)..."))

        open_c = 0
        closed_c = 0
        filtered_c = 0

        def on_prog(completed, total, res: ScanResult):
            nonlocal open_c, closed_c, filtered_c
            if res.state in ("OPEN", "OPEN|FILTERED"):
                open_c += 1
            elif res.state == "CLOSED":
                closed_c += 1
            elif res.state == "FILTERED":
                filtered_c += 1

            self.root.after(0, lambda: self._update_progress_ui(completed, total, open_c, closed_c, filtered_c, res))

        self.results = self.scanner_instance.run_scan(progress_callback=on_prog)
        self.root.after(0, self._scan_finished)

    def _update_progress_ui(self, completed, total, open_c, closed_c, filtered_c, res: ScanResult):
        self.progress_bar["value"] = completed
        self.card_scanned.configure(text=str(completed))
        self.card_open.configure(text=str(open_c))
        self.card_filtered.configure(text=str(filtered_c))
        self.card_closed.configure(text=str(closed_c))

        elapsed = max(time.time() - self.scan_start_time, 0.001)
        speed = round(completed / elapsed, 1)
        self.card_speed.configure(text=f"{speed} p/s")

        # Insert into treeview if open or if total ports <= 100
        if res.state in ("OPEN", "OPEN|FILTERED") or total <= 50:
            banner_disp = res.banner if res.banner else res.description
            self.tree.insert("", tk.END, values=(
                res.port, res.proto, res.state, res.service,
                res.latency_ms, res.risk, banner_disp
            ), tags=(res.state,))

        if res.state in ("OPEN", "OPEN|FILTERED"):
            self._log(f"[OPEN] Port {res.port}/{res.proto} ({res.service}) - {res.latency_ms}ms")

    def _scan_finished(self):
        self.scan_active = False
        self.btn_scan.configure(state="normal")
        self.btn_stop.configure(state="disabled")

        if self.scanner_instance:
            summary = self.scanner_instance.get_summary()
            self.lbl_status.configure(
                text=f"Scan Complete! Discovered {summary['open_ports_count']} open ports in {summary['scan_duration_sec']}s ({summary['ports_per_sec']} ports/sec)."
            )
            self._log(f"Scan finished. Open: {summary['open_ports_count']} | Closed: {summary['closed_ports_count']} | Filtered: {summary['filtered_ports_count']}")

    def stop_scan(self):
        if self.scanner_instance:
            self.scanner_instance.stop()
            self.lbl_status.configure(text="Stopping scan...")
            self._log("Scan cancellation requested by user.")

    def show_nmap_benchmark(self):
        self.notebook.select(self.tab_nmap)

    def export_json(self):
        if not self.results:
            messagebox.showinfo("Export", "No scan results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")])
        if path:
            summary = self.scanner_instance.get_summary() if self.scanner_instance else {}
            with open(path, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2)
            messagebox.showinfo("Exported", f"Successfully exported scan to:\n{path}")

    def export_csv(self):
        if not self.results:
            messagebox.showinfo("Export", "No scan results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if path:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Port", "Protocol", "State", "Service", "Latency_ms", "Risk", "Banner"])
                for r in self.results:
                    writer.writerow([r.port, r.proto, r.state, r.service, r.latency_ms, r.risk, r.banner or r.description])
            messagebox.showinfo("Exported", f"Successfully exported CSV to:\n{path}")


def main():
    root = tk.Tk()
    app = PortScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
