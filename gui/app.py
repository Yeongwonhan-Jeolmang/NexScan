"""
NexScan GUI — Main Application Window
Dark terminal-inspired professional port scanner interface.
"""

from collections import defaultdict
import datetime
import ipaddress
import json
import os
import queue
import socket
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core.scanner import (
    PortResult,
    PortScanner,
    PortState,
    ScanConfig,
    ScanResult,
    ScanType,
    parse_ports,
    parse_targets,
)
from core.service_db import COMMON_PORTS, ServiceDatabase
from reports.exporter import (
    export_csv,
    export_html,
    export_json,
    export_txt,
    export_xml,
)

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─────────────────────────── COLOR PALETTE ───────────────────────────
C = {
    "bg": "#0b0e14",
    "surface": "#111620",
    "surface2": "#161c2a",
    "border": "#1e2840",
    "border2": "#253050",
    "accent": "#00d4ff",
    "accent2": "#0099bb",
    "accent_dim": "#004455",
    "green": "#00ff88",
    "green_dim": "#003322",
    "yellow": "#ffcc00",
    "yellow_dim": "#332800",
    "red": "#ff4466",
    "red_dim": "#330011",
    "purple": "#bb66ff",
    "purple_dim": "#220033",
    "orange": "#ff8822",
    "text": "#ccd6f6",
    "text2": "#7888aa",
    "text3": "#445566",
    "white": "#e8f0ff",
    "header_bg": "#0d1220",
    "row_alt": "#0f1520",
    "row_hover": "#152030",
    "select": "#1a3050",
    "input_bg": "#0d1525",
    "btn_bg": "#0d1a2e",
    "btn_hover": "#1a2d48",
    "tag_open": "#003322",
    "tag_filt": "#332800",
    "tag_closed": "#1a1a2a",
}

FONT_MONO = ("Consolas", 10)
FONT_MONO_SM = ("Consolas", 9)
FONT_MONO_LG = ("Consolas", 12)
FONT_MONO_XL = ("Consolas", 14)
FONT_UI = ("Segoe UI", 10)
FONT_UI_BOLD = ("Segoe UI", 10, "bold")
FONT_UI_SM = ("Segoe UI", 9)
FONT_TITLE = ("Consolas", 16, "bold")
FONT_STAT = ("Consolas", 22, "bold")


class NexScanApp(tk.Tk):
    VERSION = "2.0"

    def __init__(self):
        super().__init__()
        self.title(f"NexScan v{self.VERSION} — Advanced Port Scanner")
        self.configure(bg=C["bg"])
        self.geometry("1400x900")
        self.minsize(1100, 700)

        self._setup_style()
        self._init_state()
        self._build_ui()
        self._setup_bindings()

        # Queue for thread-safe UI updates
        self._ui_queue = queue.Queue()
        self._poll_queue()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _setup_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        # Treeview
        style.configure(
            "Treeview",
            background=C["surface"],
            foreground=C["text"],
            fieldbackground=C["surface"],
            borderwidth=0,
            rowheight=26,
            font=FONT_MONO_SM,
        )
        style.configure(
            "Treeview.Heading",
            background=C["header_bg"],
            foreground=C["accent"],
            borderwidth=0,
            relief="flat",
            font=FONT_MONO_SM,
        )
        style.map(
            "Treeview",
            background=[("selected", C["select"])],
            foreground=[("selected", C["white"])],
        )
        style.map("Treeview.Heading", background=[("active", C["border"])])

        # Scrollbars
        style.configure(
            "Vertical.TScrollbar",
            background=C["surface2"],
            troughcolor=C["bg"],
            borderwidth=0,
            arrowsize=12,
            width=10,
        )
        style.configure(
            "Horizontal.TScrollbar",
            background=C["surface2"],
            troughcolor=C["bg"],
            borderwidth=0,
            arrowsize=12,
            width=10,
        )

        # Progressbar
        style.configure(
            "Scan.Horizontal.TProgressbar",
            background=C["accent"],
            troughcolor=C["surface2"],
            borderwidth=0,
            thickness=6,
        )

        # Notebook tabs
        style.configure("TNotebook", background=C["bg"], borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background=C["surface2"],
            foreground=C["text2"],
            padding=[14, 8],
            font=FONT_MONO_SM,
            borderwidth=0,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", C["surface"]), ("active", C["border"])],
            foreground=[("selected", C["accent"]), ("active", C["text"])],
        )

        # Separators
        style.configure("TSeparator", background=C["border"])

        # Combobox
        style.configure(
            "TCombobox",
            fieldbackground=C["input_bg"],
            background=C["surface2"],
            foreground=C["text"],
            selectbackground=C["select"],
            bordercolor=C["border2"],
            arrowsize=12,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", C["input_bg"])],
            foreground=[("readonly", C["text"])],
        )

        # Spinbox
        style.configure(
            "TSpinbox",
            fieldbackground=C["input_bg"],
            background=C["surface2"],
            foreground=C["text"],
            bordercolor=C["border2"],
        )

        # Checkbutton
        style.configure(
            "TCheckbutton", background=C["surface2"], foreground=C["text"], focuscolor=C["accent"]
        )
        style.map(
            "TCheckbutton",
            background=[("active", C["surface2"])],
            foreground=[("active", C["white"])],
        )

        # Labelframe
        style.configure(
            "Card.TLabelframe",
            background=C["surface2"],
            foreground=C["accent"],
            bordercolor=C["border2"],
            relief="solid",
            borderwidth=1,
        )
        style.configure(
            "Card.TLabelframe.Label",
            background=C["surface2"],
            foreground=C["accent"],
            font=FONT_MONO_SM,
        )

    def _init_state(self):
        self.service_db = ServiceDatabase()
        self.scanner: PortScanner = None
        self.scan_thread: threading.Thread = None
        self.scan_results: list[ScanResult] = []
        self.is_scanning = False
        self.is_paused = False
        self.scan_start_time = None
        self.filtered_results = []

        # Live scan stats
        self.stat_open = tk.IntVar(value=0)
        self.stat_filtered = tk.IntVar(value=0)
        self.stat_hosts_up = tk.IntVar(value=0)
        self.stat_ports_done = tk.IntVar(value=0)
        self.stat_total_ports = tk.IntVar(value=0)
        self.stat_eta = tk.StringVar(value="—")

        # Settings vars
        self.var_scan_type = tk.StringVar(value="TCP Connect")
        self.var_threads = tk.IntVar(value=300)
        self.var_timeout = tk.DoubleVar(value=1.5)
        self.var_connect_timeout = tk.DoubleVar(value=3.0)
        self.var_banner_grab = tk.BooleanVar(value=True)
        self.var_service_detect = tk.BooleanVar(value=True)
        self.var_os_detect = tk.BooleanVar(value=False)
        self.var_ssl_probe = tk.BooleanVar(value=True)
        self.var_host_discovery = tk.BooleanVar(value=True)
        self.var_rate_limit = tk.DoubleVar(value=0.0)
        self.var_retry = tk.IntVar(value=1)
        self.var_show_closed = tk.BooleanVar(value=False)
        self.var_show_filtered = tk.BooleanVar(value=True)
        self.var_port_preset = tk.StringVar(value="Top 100")
        self.var_sort_col = tk.StringVar(value="port")
        self.var_filter_text = tk.StringVar()
        self.var_filter_text.trace_add("write", self._apply_filter)
        self.var_filter_regex = tk.BooleanVar(value=False)

    def _build_ui(self):
        # ── Top bar ──
        self._build_topbar()
        # ── Main paned layout ──
        self._build_main()
        # ── Status bar ──
        self._build_statusbar()

    def _build_topbar(self):
        bar = tk.Frame(self, bg=C["header_bg"], height=52)
        bar.pack(fill="x", side="top")
        bar.pack_propagate(False)

        # Logo
        logo = tk.Label(bar, text="◈ NEXSCAN", font=FONT_TITLE, bg=C["header_bg"], fg=C["accent"])
        logo.pack(side="left", padx=20, pady=10)

        ver = tk.Label(
            bar, text=f"v{self.VERSION}", font=FONT_MONO_SM, bg=C["header_bg"], fg=C["text3"]
        )
        ver.pack(side="left", pady=10)

        # Separator
        sep = tk.Frame(bar, bg=C["border"], width=1)
        sep.pack(side="left", fill="y", padx=20, pady=10)

        # Quick action buttons
        for text, cmd, fg in [
            ("▶  START SCAN", self._start_scan, C["green"]),
            ("⏸  PAUSE", self._toggle_pause, C["yellow"]),
            ("■  STOP", self._stop_scan, C["red"]),
            ("⟳  CLEAR", self._clear_results, C["text2"]),
        ]:
            btn = self._make_button(
                bar, text, cmd, fg=fg, bg=C["btn_bg"], hover_bg=C["btn_hover"], pad=(14, 6)
            )
            btn.pack(side="left", padx=4, pady=10)

        # Right side: export + settings
        tk.Frame(bar, bg=C["header_bg"]).pack(side="left", fill="x", expand=True)

        for text, cmd, fg in [
            ("⬇  EXPORT", self._export_menu, C["purple"]),
            ("✦  ABOUT", self._show_about, C["text2"]),
        ]:
            btn = self._make_button(
                bar, text, cmd, fg=fg, bg=C["btn_bg"], hover_bg=C["btn_hover"], pad=(14, 6)
            )
            btn.pack(side="right", padx=4, pady=10)

        # Scan elapsed timer label
        self.lbl_timer = tk.Label(
            bar, text="00:00:00", font=FONT_MONO_LG, bg=C["header_bg"], fg=C["text3"]
        )
        self.lbl_timer.pack(side="right", padx=16)
        self.lbl_timer_icon = tk.Label(
            bar, text="⏱", font=FONT_MONO_SM, bg=C["header_bg"], fg=C["text3"]
        )
        self.lbl_timer_icon.pack(side="right")

    def _build_main(self):
        main = tk.PanedWindow(
            self, orient="horizontal", bg=C["border"], sashwidth=4, sashrelief="flat", handlesize=0
        )
        main.pack(fill="both", expand=True, padx=0, pady=0)

        # Left panel
        left = self._build_left_panel(main)
        main.add(left, minsize=320, width=360)

        # Right panel (tabbed)
        right = self._build_right_panel(main)
        main.add(right, minsize=600)

    def _build_left_panel(self, parent):
        frame = tk.Frame(parent, bg=C["surface"])

        # ── Target input ──
        sec = self._section(frame, "TARGET")
        self.txt_targets = tk.Text(
            sec,
            height=4,
            bg=C["input_bg"],
            fg=C["text"],
            font=FONT_MONO_SM,
            insertbackground=C["accent"],
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightcolor=C["accent2"],
            highlightbackground=C["border2"],
            wrap="none",
            padx=6,
            pady=6,
        )
        self.txt_targets.insert("1.0", "192.168.1.1")
        self.txt_targets.pack(fill="x", padx=8, pady=(0, 6))

        hint = tk.Label(
            sec,
            text="Single IP, range (192.168.1.1-50), CIDR, or hostname. One per line or comma-separated.",
            bg=C["surface2"],
            fg=C["text3"],
            font=("Consolas", 8),
            wraplength=300,
            justify="left",
        )
        hint.pack(fill="x", padx=8, pady=(0, 6))

        # ── Port config ──
        sec2 = self._section(frame, "PORTS")

        # Preset selector
        prow = tk.Frame(sec2, bg=C["surface2"])
        prow.pack(fill="x", padx=8, pady=(0, 4))
        tk.Label(prow, text="Preset:", bg=C["surface2"], fg=C["text2"], font=FONT_MONO_SM).pack(
            side="left"
        )
        presets = self.service_db.get_presets()
        cb = ttk.Combobox(
            prow,
            textvariable=self.var_port_preset,
            values=presets,
            state="readonly",
            width=18,
            font=FONT_MONO_SM,
        )
        cb.pack(side="left", padx=6)
        cb.bind("<<ComboboxSelected>>", self._apply_port_preset)

        self._make_button(
            prow,
            "Apply",
            self._apply_port_preset,
            fg=C["accent"],
            bg=C["btn_bg"],
            hover_bg=C["btn_hover"],
            pad=(8, 2),
        ).pack(side="left", padx=4)

        tk.Label(
            sec2, text="Port range / list:", bg=C["surface2"], fg=C["text2"], font=FONT_MONO_SM
        ).pack(anchor="w", padx=8)

        self.txt_ports = tk.Text(
            sec2,
            height=3,
            bg=C["input_bg"],
            fg=C["text"],
            font=FONT_MONO_SM,
            insertbackground=C["accent"],
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightcolor=C["accent2"],
            highlightbackground=C["border2"],
            wrap="none",
            padx=6,
            pady=6,
        )
        self.txt_ports.insert(
            "1.0",
            "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,8080,8443,27017",
        )
        self.txt_ports.pack(fill="x", padx=8, pady=(2, 6))

        phint = tk.Label(
            sec2,
            text="e.g.: 22,80,443  or  1-1024  or  80,443,8000-9000",
            bg=C["surface2"],
            fg=C["text3"],
            font=("Consolas", 8),
        )
        phint.pack(anchor="w", padx=8, pady=(0, 6))

        # ── Scan Type ──
        sec3 = self._section(frame, "SCAN TYPE")
        scan_types = [
            "TCP Connect",
            "UDP",
            "SYN Stealth*",
            "ACK*",
            "FIN*",
            "XMAS*",
            "NULL*",
            "Window*",
        ]
        for i, st in enumerate(scan_types):
            needs_root = st.endswith("*")
            fg = C["text2"] if needs_root else C["text"]
            rb = tk.Radiobutton(
                sec3,
                text=st,
                variable=self.var_scan_type,
                value=st,
                bg=C["surface2"],
                fg=fg,
                selectcolor=C["accent_dim"],
                activebackground=C["surface2"],
                activeforeground=C["white"],
                font=FONT_MONO_SM,
                cursor="hand2" if not needs_root else "arrow",
                indicatoron=True,
            )
            rb.pack(anchor="w", padx=8, pady=1)

        tk.Label(
            sec3,
            text="* Requires root/admin privileges",
            bg=C["surface2"],
            fg=C["text3"],
            font=("Consolas", 8),
        ).pack(anchor="w", padx=8, pady=(2, 6))

        # ── Settings tabs ──
        sec4 = self._section(frame, "SETTINGS")
        nb = ttk.Notebook(sec4)
        nb.pack(fill="both", expand=True, padx=6, pady=4)

        self._build_perf_tab(nb)
        self._build_output_tab(nb)
        self._build_advanced_tab(nb)

        return frame

    def _build_perf_tab(self, notebook):
        tab = tk.Frame(notebook, bg=C["surface2"])
        notebook.add(tab, text="Performance")

        items = [
            ("Threads", self.var_threads, 1, 1000, ""),
            ("Timeout (s)", self.var_timeout, 0.1, 30.0, ""),
            ("Connect Timeout (s)", self.var_connect_timeout, 0.5, 60.0, ""),
            ("Rate Limit (ms)", self.var_rate_limit, 0.0, 5000.0, "0 = unlimited"),
            ("Retries", self.var_retry, 0, 5, ""),
        ]
        for label, var, mn, mx, hint in items:
            row = tk.Frame(tab, bg=C["surface2"])
            row.pack(fill="x", padx=8, pady=3)
            tk.Label(
                row,
                text=label,
                bg=C["surface2"],
                fg=C["text2"],
                font=FONT_MONO_SM,
                width=20,
                anchor="w",
            ).pack(side="left")
            is_int = isinstance(var, tk.IntVar)
            inc = 1 if is_int else 0.1
            sp = ttk.Spinbox(
                row, from_=mn, to=mx, textvariable=var, width=8, font=FONT_MONO_SM, increment=inc
            )
            sp.pack(side="left", padx=4)
            if hint:
                tk.Label(
                    row, text=hint, bg=C["surface2"], fg=C["text3"], font=("Consolas", 8)
                ).pack(side="left")

    def _build_output_tab(self, notebook):
        tab = tk.Frame(notebook, bg=C["surface2"])
        notebook.add(tab, text="Detection")

        checks = [
            ("Banner Grabbing", self.var_banner_grab),
            ("Service Detection", self.var_service_detect),
            ("OS Detection (heuristic)", self.var_os_detect),
            ("SSL/TLS Probing", self.var_ssl_probe),
            ("Host Discovery", self.var_host_discovery),
            ("Show Filtered Ports", self.var_show_filtered),
            ("Show Closed Ports", self.var_show_closed),
        ]
        for label, var in checks:
            ttk.Checkbutton(tab, text=label, variable=var, style="TCheckbutton").pack(
                anchor="w", padx=10, pady=2
            )

    def _build_advanced_tab(self, notebook):
        tab = tk.Frame(notebook, bg=C["surface2"])
        notebook.add(tab, text="Advanced")

        # Jitter
        jrow = tk.Frame(tab, bg=C["surface2"])
        jrow.pack(fill="x", padx=8, pady=3)
        self.var_jitter = tk.DoubleVar(value=0.0)
        tk.Label(
            jrow,
            text="Jitter (ms)",
            bg=C["surface2"],
            fg=C["text2"],
            font=FONT_MONO_SM,
            width=20,
            anchor="w",
        ).pack(side="left")
        ttk.Spinbox(
            jrow,
            from_=0,
            to=5000,
            textvariable=self.var_jitter,
            width=8,
            font=FONT_MONO_SM,
            increment=10,
        ).pack(side="left", padx=4)

        # Max banner wait
        brow = tk.Frame(tab, bg=C["surface2"])
        brow.pack(fill="x", padx=8, pady=3)
        self.var_max_banner = tk.DoubleVar(value=2.0)
        tk.Label(
            brow,
            text="Banner Wait (s)",
            bg=C["surface2"],
            fg=C["text2"],
            font=FONT_MONO_SM,
            width=20,
            anchor="w",
        ).pack(side="left")
        ttk.Spinbox(
            brow,
            from_=0.1,
            to=10.0,
            textvariable=self.var_max_banner,
            width=8,
            font=FONT_MONO_SM,
            increment=0.1,
        ).pack(side="left", padx=4)

        # UDP probes
        self.var_udp_probes = tk.BooleanVar(value=True)
        ttk.Checkbutton(tab, text="UDP Service Probes", variable=self.var_udp_probes).pack(
            anchor="w", padx=10, pady=3
        )

        # Quick resolve
        self.var_quick_resolve = tk.BooleanVar(value=True)
        ttk.Checkbutton(tab, text="DNS Reverse Lookup", variable=self.var_quick_resolve).pack(
            anchor="w", padx=10, pady=3
        )

        # Resolve button
        rrow = tk.Frame(tab, bg=C["surface2"])
        rrow.pack(fill="x", padx=8, pady=6)
        self._make_button(
            rrow,
            "Resolve Targets Now",
            self._resolve_targets,
            fg=C["accent"],
            bg=C["btn_bg"],
            hover_bg=C["btn_hover"],
            pad=(8, 4),
        ).pack(side="left")

        # Port count display
        crow = tk.Frame(tab, bg=C["surface2"])
        crow.pack(fill="x", padx=8, pady=3)
        self.lbl_port_count = tk.Label(
            crow, text="Ports to scan: —", bg=C["surface2"], fg=C["text3"], font=FONT_MONO_SM
        )
        self.lbl_port_count.pack(side="left")
        self._make_button(
            crow,
            "Count",
            self._count_ports,
            fg=C["text2"],
            bg=C["btn_bg"],
            hover_bg=C["btn_hover"],
            pad=(6, 2),
        ).pack(side="left", padx=4)

        # Profile management
        prow = tk.Frame(tab, bg=C["surface2"])
        prow.pack(fill="x", padx=8, pady=6)

        self._make_button(
            prow,
            "💾 Save Profile",
            self._save_profile,
            fg=C["accent"],
            bg=C["btn_bg"],
            hover_bg=C["btn_hover"],
            pad=(8, 4),
        ).pack(side="left", padx=2)

        self._make_button(
            prow,
            "📂 Load Profile",
            self._load_profile,
            fg=C["accent"],
            bg=C["btn_bg"],
            hover_bg=C["btn_hover"],
            pad=(8, 4),
        ).pack(side="left", padx=2)

    def _build_right_panel(self, parent):
        frame = tk.Frame(parent, bg=C["bg"])

        # ── Stats bar ──
        self._build_stats_bar(frame)

        # ── Progress bar with ETA ──
        pbar_frame = tk.Frame(frame, bg=C["bg"])
        pbar_frame.pack(fill="x", padx=12, pady=(0, 6))

        self.progress = ttk.Progressbar(
            pbar_frame, style="Scan.Horizontal.TProgressbar", mode="determinate", length=400
        )
        self.progress.pack(fill="x", side="left", expand=True)

        eta_col = tk.Frame(pbar_frame, bg=C["bg"])
        eta_col.pack(side="right", padx=4)
        self.lbl_progress = tk.Label(
            eta_col, text="0%", bg=C["bg"], fg=C["text3"], font=FONT_MONO_SM, width=4
        )
        self.lbl_progress.pack(side="left", padx=2)
        tk.Label(eta_col, text="ETA:", bg=C["bg"], fg=C["text3"], font=FONT_MONO_SM).pack(
            side="left", padx=(8, 2)
        )
        self.lbl_eta = tk.Label(
            eta_col,
            textvariable=self.stat_eta,
            bg=C["bg"],
            fg=C["accent"],
            font=FONT_MONO_SM,
            width=10,
        )
        self.lbl_eta.pack(side="left")

        # ── Notebook: Results / Log / SSL / OS ──
        nb = ttk.Notebook(frame)
        nb.pack(fill="both", expand=True, padx=8, pady=(0, 4))

        self._build_results_tab(nb)
        self._build_log_tab(nb)
        self._build_detail_tab(nb)
        self._build_compare_tab(nb)
        self._build_vuln_tab(nb)

        return frame

    def _build_stats_bar(self, parent):
        bar = tk.Frame(parent, bg=C["surface"], height=88)
        bar.pack(fill="x", padx=8, pady=(8, 4))
        bar.pack_propagate(False)

        stats = [
            ("OPEN PORTS", self.stat_open, C["green"]),
            ("FILTERED", self.stat_filtered, C["yellow"]),
            ("HOSTS UP", self.stat_hosts_up, C["accent"]),
            ("PORTS DONE", self.stat_ports_done, C["purple"]),
        ]

        for label, var, color in stats:
            col = tk.Frame(bar, bg=C["surface"])
            col.pack(side="left", expand=True, fill="both", padx=1)

            inner = tk.Frame(col, bg=C["surface2"])
            inner.pack(fill="both", expand=True, padx=2, pady=4)

            val_lbl = tk.Label(inner, textvariable=var, font=FONT_STAT, bg=C["surface2"], fg=color)
            val_lbl.pack(pady=(8, 0))
            tk.Label(inner, text=label, font=FONT_MONO_SM, bg=C["surface2"], fg=C["text3"]).pack()

        # Separator + scan info
        sep = tk.Frame(bar, bg=C["border"], width=1)
        sep.pack(side="left", fill="y", pady=8)

        info_col = tk.Frame(bar, bg=C["surface"])
        info_col.pack(side="left", fill="both", expand=True, padx=2)
        inner2 = tk.Frame(info_col, bg=C["surface2"])
        inner2.pack(fill="both", expand=True, padx=2, pady=4)

        tk.Label(inner2, text="STATUS", font=FONT_MONO_SM, bg=C["surface2"], fg=C["text3"]).pack(
            pady=(8, 0)
        )
        self.lbl_status = tk.Label(
            inner2, text="IDLE", font=FONT_MONO_LG, bg=C["surface2"], fg=C["text2"]
        )
        self.lbl_status.pack()
        self.lbl_current = tk.Label(
            inner2, text="—", font=FONT_MONO_SM, bg=C["surface2"], fg=C["text3"], wraplength=200
        )
        self.lbl_current.pack()

    def _build_results_tab(self, notebook):
        tab = tk.Frame(notebook, bg=C["bg"])
        notebook.add(tab, text="  Results  ")

        # Filter bar
        fbar = tk.Frame(tab, bg=C["surface"])
        fbar.pack(fill="x", padx=4, pady=(4, 2))

        tk.Label(fbar, text="🔍 Filter:", bg=C["surface"], fg=C["text2"], font=FONT_MONO_SM).pack(
            side="left", padx=8
        )
        self.entry_filter = tk.Entry(
            fbar,
            textvariable=self.var_filter_text,
            bg=C["input_bg"],
            fg=C["text"],
            insertbackground=C["accent"],
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightcolor=C["accent2"],
            highlightbackground=C["border2"],
            font=FONT_MONO_SM,
            width=30,
        )
        self.entry_filter.pack(side="left", padx=4, ipady=4)

        ttk.Checkbutton(fbar, text="Regex", variable=self.var_filter_regex).pack(
            side="left", padx=2
        )

        # Sort controls
        tk.Label(fbar, text="Sort:", bg=C["surface"], fg=C["text2"], font=FONT_MONO_SM).pack(
            side="left", padx=(12, 4)
        )
        sort_opts = ["Port ↑", "Port ↓", "Service", "Response Time", "State"]
        self.var_sort = tk.StringVar(value="Port ↑")
        sort_cb = ttk.Combobox(
            fbar,
            textvariable=self.var_sort,
            values=sort_opts,
            state="readonly",
            width=14,
            font=FONT_MONO_SM,
        )
        sort_cb.pack(side="left", padx=4)
        sort_cb.bind("<<ComboboxSelected>>", lambda e: self._refresh_results_view())

        # Host filter
        tk.Label(fbar, text="Host:", bg=C["surface"], fg=C["text2"], font=FONT_MONO_SM).pack(
            side="left", padx=(12, 4)
        )
        self.var_host_filter = tk.StringVar(value="All")
        self.cb_host_filter = ttk.Combobox(
            fbar,
            textvariable=self.var_host_filter,
            values=["All"],
            state="readonly",
            width=18,
            font=FONT_MONO_SM,
        )
        self.cb_host_filter.pack(side="left", padx=4)
        self.cb_host_filter.bind("<<ComboboxSelected>>", lambda e: self._refresh_results_view())

        # Count label
        self.lbl_result_count = tk.Label(
            fbar, text="0 results", bg=C["surface"], fg=C["text3"], font=FONT_MONO_SM
        )
        self.lbl_result_count.pack(side="right", padx=12)

        # Treeview
        cols = ("host", "port", "proto", "state", "service", "version", "rtt", "banner")
        col_labels = ("Host", "Port", "Proto", "State", "Service", "Version", "RTT ms", "Banner")
        col_widths = (130, 60, 55, 80, 110, 140, 70, 200)

        tree_frame = tk.Frame(tab, bg=C["bg"])
        tree_frame.pack(fill="both", expand=True, padx=4, pady=(0, 4))

        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="extended")

        for col, lbl, w in zip(cols, col_labels, col_widths):
            self.tree.heading(col, text=lbl, command=lambda c=col: self._sort_tree(c))
            self.tree.column(col, width=w, minwidth=40, anchor="w")

        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self.tree.pack(fill="both", expand=True)

        # Row tags
        self.tree.tag_configure("open", background=C["tag_open"], foreground=C["green"])
        self.tree.tag_configure("filtered", background=C["tag_filt"], foreground=C["yellow"])
        self.tree.tag_configure("closed", background=C["tag_closed"], foreground=C["text3"])
        self.tree.tag_configure("alt", background=C["row_alt"])

        # Context menu
        self.tree.bind("<Button-3>", self._tree_context_menu)
        self.tree.bind("<Double-Button-1>", self._show_port_detail)

    def _build_log_tab(self, notebook):
        tab = tk.Frame(notebook, bg=C["bg"])
        notebook.add(tab, text="  Live Log  ")

        # Controls
        ctrl = tk.Frame(tab, bg=C["surface"])
        ctrl.pack(fill="x", padx=4, pady=(4, 2))

        self.var_log_level = tk.StringVar(value="All")
        for lbl, val in [("All", "All"), ("Open Only", "Open"), ("Errors", "Error")]:
            rb = tk.Radiobutton(
                ctrl,
                text=lbl,
                variable=self.var_log_level,
                value=val,
                bg=C["surface"],
                fg=C["text2"],
                selectcolor=C["accent_dim"],
                activebackground=C["surface"],
                activeforeground=C["white"],
                font=FONT_MONO_SM,
                cursor="hand2",
            )
            rb.pack(side="left", padx=8, pady=4)

        self._make_button(
            ctrl,
            "Clear Log",
            self._clear_log,
            fg=C["text2"],
            bg=C["btn_bg"],
            hover_bg=C["btn_hover"],
            pad=(8, 3),
        ).pack(side="right", padx=8)

        self.var_autoscroll = tk.BooleanVar(value=True)
        ttk.Checkbutton(ctrl, text="Auto-scroll", variable=self.var_autoscroll).pack(
            side="right", padx=4
        )

        # Log text area
        log_frame = tk.Frame(tab, bg=C["bg"])
        log_frame.pack(fill="both", expand=True, padx=4, pady=(0, 4))

        self.txt_log = tk.Text(
            log_frame,
            bg=C["bg"],
            fg=C["text"],
            font=FONT_MONO_SM,
            state="disabled",
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=C["border"],
            insertbackground=C["accent"],
            wrap="none",
            padx=8,
            pady=6,
        )

        log_vsb = ttk.Scrollbar(log_frame, orient="vertical", command=self.txt_log.yview)
        log_hsb = ttk.Scrollbar(log_frame, orient="horizontal", command=self.txt_log.xview)
        self.txt_log.configure(yscrollcommand=log_vsb.set, xscrollcommand=log_hsb.set)

        log_vsb.pack(side="right", fill="y")
        log_hsb.pack(side="bottom", fill="x")
        self.txt_log.pack(fill="both", expand=True)

        # Log tags
        self.txt_log.tag_configure("open", foreground=C["green"])
        self.txt_log.tag_configure("filtered", foreground=C["yellow"])
        self.txt_log.tag_configure("closed", foreground=C["text3"])
        self.txt_log.tag_configure("info", foreground=C["accent"])
        self.txt_log.tag_configure("error", foreground=C["red"])
        self.txt_log.tag_configure("host", foreground=C["purple"])
        self.txt_log.tag_configure("timestamp", foreground=C["text3"])
        self.txt_log.tag_configure("ssl", foreground=C["accent2"])
        self.txt_log.tag_configure("banner", foreground=C["orange"])

    def _build_detail_tab(self, notebook):
        tab = tk.Frame(notebook, bg=C["bg"])
        notebook.add(tab, text="  Port Detail  ")

        # Left: host tree
        pw = tk.PanedWindow(tab, orient="horizontal", bg=C["border"], sashwidth=3, handlesize=0)
        pw.pack(fill="both", expand=True)

        left = tk.Frame(pw, bg=C["surface"])
        pw.add(left, minsize=200, width=240)

        tk.Label(left, text="HOSTS", bg=C["surface"], fg=C["accent"], font=FONT_MONO_SM).pack(
            anchor="w", padx=8, pady=4
        )

        self.host_listbox = tk.Listbox(
            left,
            bg=C["surface2"],
            fg=C["text"],
            font=FONT_MONO_SM,
            selectbackground=C["select"],
            selectforeground=C["white"],
            relief="flat",
            bd=0,
            highlightthickness=0,
            activestyle="none",
        )
        self.host_listbox.pack(fill="both", expand=True, padx=4, pady=4)
        self.host_listbox.bind("<<ListboxSelect>>", self._on_host_select)

        # Right: detail view
        right = tk.Frame(pw, bg=C["bg"])
        pw.add(right, minsize=400)

        self.detail_text = tk.Text(
            right,
            bg=C["bg"],
            fg=C["text"],
            font=FONT_MONO_SM,
            state="disabled",
            relief="flat",
            bd=0,
            highlightthickness=0,
            wrap="none",
            padx=12,
            pady=8,
        )

        det_vsb = ttk.Scrollbar(right, orient="vertical", command=self.detail_text.yview)
        det_hsb = ttk.Scrollbar(right, orient="horizontal", command=self.detail_text.xview)
        self.detail_text.configure(yscrollcommand=det_vsb.set, xscrollcommand=det_hsb.set)

        det_vsb.pack(side="right", fill="y")
        det_hsb.pack(side="bottom", fill="x")
        self.detail_text.pack(fill="both", expand=True)

        # Detail text tags
        for tag, fg_color in [
            ("header", C["accent"]),
            ("subheader", C["purple"]),
            ("key", C["text2"]),
            ("value", C["text"]),
            ("open", C["green"]),
            ("filtered", C["yellow"]),
            ("closed", C["text3"]),
            ("banner_text", C["orange"]),
            ("ssl_text", C["accent2"]),
            ("sep", C["border2"]),
        ]:
            self.detail_text.tag_configure(tag, foreground=fg_color)
        self.detail_text.tag_configure("bold", font=("Consolas", 10, "bold"))
        self.detail_text.tag_configure("mono_lg", font=FONT_MONO_LG)

    def _build_compare_tab(self, notebook):
        tab = tk.Frame(notebook, bg=C["bg"])
        notebook.add(tab, text="  Statistics  ")

        # Stats grid
        stats_frame = tk.Frame(tab, bg=C["bg"])
        stats_frame.pack(fill="both", expand=True, padx=8, pady=8)

        self.stats_text = tk.Text(
            stats_frame,
            bg=C["bg"],
            fg=C["text"],
            font=FONT_MONO_SM,
            state="disabled",
            relief="flat",
            bd=0,
            wrap="none",
            highlightthickness=0,
            padx=12,
            pady=8,
        )
        self.stats_text.pack(fill="both", expand=True)

        for tag, fg_c in [
            ("header", C["accent"]),
            ("key", C["text2"]),
            ("val", C["white"]),
            ("bar_fill", C["green"]),
            ("bar_empty", C["text3"]),
            ("sep", C["border2"]),
            ("warn", C["yellow"]),
            ("danger", C["red"]),
        ]:
            self.stats_text.tag_configure(tag, foreground=fg_c)

    def _build_vuln_tab(self, notebook):
        """Tab for CVE/vulnerability info and geolocation."""
        tab = tk.Frame(notebook, bg=C["bg"])
        notebook.add(tab, text="  Vulnerabilities  ")

        ctrl = tk.Frame(tab, bg=C["surface"])
        ctrl.pack(fill="x", padx=4, pady=(4, 2))

        self._make_button(
            ctrl,
            "🔍 Lookup CVEs",
            self._lookup_cves,
            fg=C["red"],
            bg=C["btn_bg"],
            hover_bg=C["btn_hover"],
            pad=(8, 3),
        ).pack(side="left", padx=4)

        self._make_button(
            ctrl,
            "📍 Lookup Geolocation",
            self._lookup_geolocation,
            fg=C["accent"],
            bg=C["btn_bg"],
            hover_bg=C["btn_hover"],
            pad=(8, 3),
        ).pack(side="left", padx=4)

        # Vulnerability text area
        vuln_frame = tk.Frame(tab, bg=C["bg"])
        vuln_frame.pack(fill="both", expand=True, padx=4, pady=(0, 4))

        self.vuln_text = tk.Text(
            vuln_frame,
            bg=C["bg"],
            fg=C["text"],
            font=FONT_MONO_SM,
            state="disabled",
            relief="flat",
            bd=0,
            wrap="word",
            highlightthickness=1,
            highlightbackground=C["border"],
            padx=12,
            pady=8,
        )

        vuln_vsb = ttk.Scrollbar(vuln_frame, orient="vertical", command=self.vuln_text.yview)
        vuln_hsb = ttk.Scrollbar(vuln_frame, orient="horizontal", command=self.vuln_text.xview)
        self.vuln_text.configure(yscrollcommand=vuln_vsb.set, xscrollcommand=vuln_hsb.set)

        vuln_vsb.pack(side="right", fill="y")
        vuln_hsb.pack(side="bottom", fill="x")
        self.vuln_text.pack(fill="both", expand=True)

        # Tags
        for tag, fg_c in [
            ("cve_critical", C["red"]),
            ("cve_high", C["orange"]),
            ("cve_medium", C["yellow"]),
            ("cve_low", C["green"]),
            ("header", C["accent"]),
            ("geo_info", C["accent2"]),
        ]:
            self.vuln_text.tag_configure(tag, foreground=fg_c)

    def _lookup_cves(self):
        """Trigger CVE lookup for detected services."""
        if not self.scan_results:
            messagebox.showwarning("No Data", "Run a scan first to lookup CVEs")
            return

        from core.cve_lookup import lookup_service_cves, format_cve_report
        from core.scanner import PortState

        self.vuln_text.configure(state="normal")
        self.vuln_text.delete("1.0", "end")

        self.vuln_text.insert("end", "CVE VULNERABILITY LOOKUP\n", "header")
        self.vuln_text.insert("end", "=" * 60 + "\n\n", "header")

        cve_count = 0
        for result in self.scan_results:
            for port in result.ports:
                if port.state == PortState.OPEN and port.service:
                    cves = lookup_service_cves(port.service, port.version, limit=3)
                    if cves:
                        cve_count += len(cves)
                        tag = (
                            "cve_critical"
                            if cves[0].severity == "CRITICAL"
                            else (
                                "cve_high"
                                if cves[0].severity == "HIGH"
                                else "cve_medium" if cves[0].severity == "MEDIUM" else "cve_low"
                            )
                        )
                        self.vuln_text.insert(
                            "end",
                            f"\n{result.target}:{port.port}/{port.protocol} — {port.service} {port.version}\n",
                            "header",
                        )
                        report = format_cve_report(port.service, port.version, cves)
                        self.vuln_text.insert("end", report + "\n\n", tag)

        if cve_count == 0:
            self.vuln_text.insert(
                "end", "  ✓ No known CVEs found for detected services\n", "cve_low"
            )
        else:
            self.vuln_text.insert(
                "end", f"\n{cve_count} CVE(s) found — check details above\n", "header"
            )

        self.vuln_text.configure(state="disabled")

    def _lookup_geolocation(self):
        """Lookup geolocation for discovered hosts."""
        if not self.scan_results:
            messagebox.showwarning("No Data", "Run a scan first to lookup geolocation")
            return

        from core.geoloc import lookup_geolocation, format_geolocation_report

        self.vuln_text.configure(state="normal")
        self.vuln_text.delete("1.0", "end")

        self.vuln_text.insert("end", "GEOLOCATION LOOKUP\n", "header")
        self.vuln_text.insert("end", "=" * 60 + "\n\n", "header")

        for result in self.scan_results:
            if result.host_up:
                geo = lookup_geolocation(result.ip_address)
                if geo:
                    report = format_geolocation_report(geo)
                    self.vuln_text.insert("end", report + "\n\n", "geo_info")
                else:
                    self.vuln_text.insert(
                        "end", f"  {result.target} ({result.ip_address}) — No info\n\n", "header"
                    )

        self.vuln_text.configure(state="disabled")

    def _build_statusbar(self):
        bar = tk.Frame(self, bg=C["header_bg"], height=24)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        self.lbl_statusbar = tk.Label(
            bar,
            text="Ready — Load a target and click Start Scan",
            bg=C["header_bg"],
            fg=C["text3"],
            font=FONT_MONO_SM,
            anchor="w",
        )
        self.lbl_statusbar.pack(side="left", padx=12)

        # Right side: hostname display
        self.lbl_hostname = tk.Label(
            bar, text="", bg=C["header_bg"], fg=C["text3"], font=FONT_MONO_SM
        )
        self.lbl_hostname.pack(side="right", padx=12)

        tk.Label(
            bar,
            text=f"◈ NexScan v{self.VERSION}",
            bg=C["header_bg"],
            fg=C["text3"],
            font=FONT_MONO_SM,
        ).pack(side="right", padx=12)

    # ─────────────────────────── HELPERS ───────────────────────────

    def _make_button(self, parent, text, command, fg=None, bg=None, hover_bg=None, pad=(12, 6)):
        fg = fg or C["text"]
        bg = bg or C["btn_bg"]
        hover_bg = hover_bg or C["btn_hover"]
        btn = tk.Label(
            parent,
            text=text,
            font=FONT_MONO_SM,
            bg=bg,
            fg=fg,
            cursor="hand2",
            padx=pad[0],
            pady=pad[1],
        )
        btn.bind("<Button-1>", lambda e: command())
        btn.bind("<Enter>", lambda e: btn.configure(bg=hover_bg))
        btn.bind("<Leave>", lambda e: btn.configure(bg=bg))
        return btn

    def _section(self, parent, title):
        outer = tk.Frame(parent, bg=C["surface"])
        outer.pack(fill="x", padx=4, pady=3)

        # Section header
        hdr = tk.Frame(outer, bg=C["surface"])
        hdr.pack(fill="x")
        tk.Label(
            hdr,
            text=f"  {title}",
            bg=C["accent_dim"],
            fg=C["accent"],
            font=FONT_MONO_SM,
            anchor="w",
            pady=3,
        ).pack(fill="x")

        # Content area
        content = tk.Frame(
            outer, bg=C["surface2"], highlightthickness=1, highlightbackground=C["border"]
        )
        content.pack(fill="x", pady=1)
        return content

    def _log(self, msg: str, tag: str = "info"):
        def _insert():
            self.txt_log.configure(state="normal")
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            self.txt_log.insert("end", f"[{ts}] ", "timestamp")
            self.txt_log.insert("end", f"{msg}\n", tag)
            if self.var_autoscroll.get():
                self.txt_log.see("end")
            self.txt_log.configure(state="disabled")

        self.after(0, _insert)

    def _set_status(self, text: str, color: str = None):
        color = color or C["text2"]
        self.after(0, lambda: self.lbl_status.configure(text=text, fg=color))
        self.after(0, lambda: self.lbl_statusbar.configure(text=text))

    def _set_current(self, text: str):
        self.after(0, lambda: self.lbl_current.configure(text=text))

    # ─────────────────────────── SCAN CONTROL ───────────────────────────

    def _get_scan_config(self) -> ScanConfig:
        """Build ScanConfig from UI state."""
        target_text = self.txt_targets.get("1.0", "end").strip()
        port_text = self.txt_ports.get("1.0", "end").strip().replace("\n", ",")

        targets = parse_targets(target_text)
        ports = parse_ports(port_text)

        if not targets:
            raise ValueError("No valid targets specified.")
        if not ports:
            raise ValueError("No valid ports specified.")

        scan_type_map = {
            "TCP Connect": ScanType.TCP_CONNECT,
            "UDP": ScanType.UDP,
            "SYN Stealth*": ScanType.SYN_STEALTH,
            "ACK*": ScanType.ACK,
            "FIN*": ScanType.FIN,
            "XMAS*": ScanType.XMAS,
            "NULL*": ScanType.NULL,
            "Window*": ScanType.WINDOW,
        }
        stype = scan_type_map.get(self.var_scan_type.get(), ScanType.TCP_CONNECT)

        return ScanConfig(
            targets=targets,
            ports=ports,
            scan_type=stype,
            threads=self.var_threads.get(),
            timeout=self.var_timeout.get(),
            connect_timeout=self.var_connect_timeout.get(),
            grab_banners=self.var_banner_grab.get(),
            detect_service=self.var_service_detect.get(),
            detect_os=self.var_os_detect.get(),
            ssl_probe=self.var_ssl_probe.get(),
            rate_limit=self.var_rate_limit.get() / 1000.0,
            retry_count=self.var_retry.get(),
            jitter=getattr(self, "var_jitter", tk.DoubleVar(value=0.0)).get(),
            max_banner_wait=getattr(self, "var_max_banner", tk.DoubleVar(value=2.0)).get(),
            host_discovery=self.var_host_discovery.get(),
            udp_payload_probes=getattr(self, "var_udp_probes", tk.BooleanVar(value=True)).get(),
        )

    def _start_scan(self):
        if self.is_scanning:
            return

        try:
            config = self._get_scan_config()
        except ValueError as e:
            messagebox.showerror("Configuration Error", str(e))
            return

        # Confirm large scans
        total = len(config.targets) * len(config.ports)
        if total > 500_000:
            ok = messagebox.askyesno(
                "Large Scan",
                f"This scan covers {total:,} port/host combinations.\n"
                "This may take a long time. Continue?",
                icon="warning",
            )
            if not ok:
                return

        self._clear_results_internal()
        self.is_scanning = True
        self.is_paused = False
        self.scan_start_time = time.time()

        self.stat_total_ports.set(total)
        self._set_status("SCANNING", C["green"])
        self._log(
            f"Starting {config.scan_type.value} scan on {len(config.targets)} "
            f"target(s), {len(config.ports)} port(s) each",
            "info",
        )
        self._log(
            f"Threads: {config.threads}  Timeout: {config.timeout}s  "
            f"Banner: {config.grab_banners}  OS-detect: {config.detect_os}",
            "info",
        )

        self.scanner = PortScanner(
            config,
            callback=self._on_port_found,
            progress_callback=self._on_progress,
            host_callback=self._on_host_complete,
        )

        self.scan_thread = threading.Thread(target=self._run_scan, daemon=True)
        self.scan_thread.start()
        self._update_timer()

    def _run_scan(self):
        try:
            results = self.scanner.run()
            self.scan_results = results
            self._ui_queue.put(("scan_complete", results))
        except Exception as e:
            self._ui_queue.put(("scan_error", str(e)))

    def _toggle_pause(self):
        if not self.is_scanning:
            return
        if self.is_paused:
            self.scanner.resume()
            self.is_paused = False
            self._set_status("SCANNING", C["green"])
            self._log("Scan resumed.", "info")
        else:
            self.scanner.pause()
            self.is_paused = True
            self._set_status("PAUSED", C["yellow"])
            self._log("Scan paused.", "info")

    def _stop_scan(self):
        if not self.is_scanning:
            return
        # Ask for confirmation
        ok = messagebox.askyesno(
            "Cancel Scan", "Are you sure you want to cancel the scan?", icon="warning"
        )
        if ok and self.scanner:
            self.scanner.stop()
            self._set_status("STOPPING...", C["red"])
            self._log("Stop requested...", "error")

    def _on_port_found(self, target: str, port_result: PortResult):
        """Called from scan thread when an open port is found."""
        self._ui_queue.put(("port_found", target, port_result))

    def _on_progress(
        self, completed: int, total: int, target: str, host_done: int, host_total: int
    ):
        self._ui_queue.put(("progress", completed, total, target, host_done, host_total))

    def _on_host_complete(self, result: ScanResult):
        self._ui_queue.put(("host_complete", result))

    def _poll_queue(self):
        """Process UI queue messages (called from main thread)."""
        try:
            while True:
                msg = self._ui_queue.get_nowait()
                self._handle_queue_msg(msg)
        except queue.Empty:
            pass
        self.after(30, self._poll_queue)

    def _handle_queue_msg(self, msg):
        kind = msg[0]

        if kind == "port_found":
            _, target, pr = msg
            self._add_result_row(target, pr)
            if pr.state == PortState.OPEN:
                self.stat_open.set(self.stat_open.get() + 1)
            elif pr.state in (PortState.FILTERED, PortState.OPEN_FILTERED):
                self.stat_filtered.set(self.stat_filtered.get() + 1)

            tag = pr.state.value.split("|")[0]
            log_msg = f"[{target}:{pr.port}/{pr.protocol}] {pr.state.value:<15} {pr.service:<18} {pr.version[:30]}"
            if pr.banner:
                banner_line = pr.banner.splitlines()[0][:60]
                self._log(log_msg, "open" if pr.state == PortState.OPEN else "filtered")
                self._log(f"  ↳ Banner: {banner_line}", "banner")
            elif pr.state in (PortState.OPEN, PortState.OPEN_FILTERED):
                self._log(log_msg, "open" if pr.state == PortState.OPEN else "filtered")

            if pr.ssl_info and pr.ssl_info.get("version"):
                self._log(
                    f"  ↳ SSL: {pr.ssl_info['version']}  CN={pr.ssl_info.get('common_name', '')}",
                    "ssl",
                )

        elif kind == "progress":
            _, done, total, target, hdone, htotal = msg
            pct = int(done / total * 100) if total else 0
            self.progress["value"] = pct
            self.lbl_progress.configure(text=f"{pct}%")
            self.stat_ports_done.set(done)
            self._set_current(f"{target} [{hdone}/{htotal}]")

            # Calculate ETA
            if done > 0 and total > 0 and self.is_scanning:
                elapsed = time.time() - self.scan_start_time
                rate = done / elapsed if elapsed > 0 else 1
                remaining = (total - done) / rate if rate > 0 else 0
                m, s = int(remaining) // 60, int(remaining) % 60
                eta_str = f"{m}m {s}s" if m > 0 else f"{s}s"
                self.stat_eta.set(eta_str)
            else:
                self.stat_eta.set("—")

        elif kind == "host_complete":
            _, result = msg
            self.stat_hosts_up.set(self.stat_hosts_up.get() + (1 if result.host_up else 0))
            status = "UP" if result.host_up else "DOWN"
            self._log(
                f"Host {result.target} ({result.ip_address}) — {status}  "
                f"Open:{result.open_count} Filtered:{result.filtered_count}  "
                f"Duration:{result.scan_duration:.2f}s",
                "host",
            )
            if result.os_guess:
                self._log(
                    f"  ↳ OS Guess: {result.os_guess} ({result.os_confidence}% confidence)", "info"
                )
            self._update_host_list()
            self._update_stats_tab()

        elif kind == "scan_complete":
            _, results = msg
            self.is_scanning = False
            self._set_status("COMPLETE", C["accent"])
            elapsed = time.time() - self.scan_start_time
            self._log(
                f"Scan complete in {elapsed:.1f}s  "
                f"Open:{self.stat_open.get()}  "
                f"Filtered:{self.stat_filtered.get()}  "
                f"Hosts up:{self.stat_hosts_up.get()}",
                "info",
            )
            self.progress["value"] = 100
            self.lbl_progress.configure(text="100%")
            self._update_stats_tab()

        elif kind == "scan_error":
            _, err = msg
            self.is_scanning = False
            self._set_status("ERROR", C["red"])
            self._log(f"Scan error: {err}", "error")
            messagebox.showerror("Scan Error", str(err))

    def _add_result_row(self, target: str, pr: PortResult):
        """Add a row to the results treeview."""
        show_filtered = self.var_show_filtered.get()
        show_closed = self.var_show_closed.get()

        if pr.state == PortState.OPEN:
            tag = "open"
        elif pr.state in (PortState.FILTERED, PortState.OPEN_FILTERED):
            if not show_filtered:
                return
            tag = "filtered"
        else:
            if not show_closed:
                return
            tag = "closed"

        rtt = f"{pr.response_time * 1000:.1f}"
        banner_short = pr.banner.splitlines()[0][:80] if pr.banner else ""

        # Filter check
        ftext = self.var_filter_text.get().lower()
        row_str = f"{target} {pr.port} {pr.protocol} {pr.state.value} {pr.service} {pr.version} {banner_short}".lower()
        if ftext and ftext not in row_str:
            return

        iid = self.tree.insert(
            "",
            "end",
            values=(
                target,
                pr.port,
                pr.protocol.upper(),
                pr.state.value,
                pr.service,
                pr.version,
                rtt,
                banner_short,
            ),
            tags=(tag,),
        )

        # Alternating row
        count = len(self.tree.get_children())
        if count % 2 == 0:
            self.tree.item(iid, tags=(tag, "alt"))

    def _update_timer(self):
        if not self.is_scanning:
            return
        if not self.is_paused:
            elapsed = int(time.time() - self.scan_start_time)
            h, m, s = elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60
            self.lbl_timer.configure(text=f"{h:02d}:{m:02d}:{s:02d}", fg=C["accent"])
            self.lbl_timer_icon.configure(fg=C["accent"])
        self.after(1000, self._update_timer)

    def _update_host_list(self):
        hosts = ["All"] + [r.target for r in self.scan_results]
        self.cb_host_filter["values"] = hosts

        self.host_listbox.delete(0, "end")
        for r in self.scan_results:
            status = "▲" if r.host_up else "▼"
            color = C["green"] if r.host_up else C["red"]
            self.host_listbox.insert("end", f"{status} {r.target}  [{r.open_count} open]")

    def _on_host_select(self, event):
        sel = self.host_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        if idx < len(self.scan_results):
            self._show_host_detail(self.scan_results[idx])

    def _show_host_detail(self, result: ScanResult):
        """Show detailed info for a host in the detail tab."""
        dt = self.detail_text
        dt.configure(state="normal")
        dt.delete("1.0", "end")

        def w(text, tag=None):
            dt.insert("end", text, tag)

        sep = "─" * 68 + "\n"
        w(f"◈ HOST REPORT\n", "header")
        w(sep, "sep")

        w(f"  Target       : ", "key")
        w(f"{result.target}\n", "value")
        w(f"  IP Address   : ", "key")
        w(f"{result.ip_address}\n", "value")
        if result.hostname and result.hostname != result.target:
            w(f"  Hostname     : ", "key")
            w(f"{result.hostname}\n", "value")
        w(f"  Status       : ", "key")
        if result.host_up:
            w("UP\n", "open")
        else:
            w("DOWN\n", "closed")
        if result.ttl:
            w(f"  TTL          : ", "key")
            w(f"{result.ttl}\n", "value")
        if result.os_guess:
            w(f"  OS Guess     : ", "key")
            w(f"{result.os_guess} ({result.os_confidence}% confidence)\n", "value")

        w(f"  Scan Type    : ", "key")
        w(f"{result.scan_type}\n", "value")
        w(f"  Duration     : ", "key")
        w(f"{result.scan_duration:.3f}s\n", "value")
        w(f"  Timestamp    : ", "key")
        w(f"{result.timestamp}\n", "value")
        w(f"  Open / Filt / Closed : ", "key")
        w(f"{result.open_count}", "open")
        w(f" / ", "key")
        w(f"{result.filtered_count}", "filtered")
        w(f" / ", "key")
        w(f"{result.closed_count}\n", "closed")

        open_ports = [p for p in result.ports if p.state == PortState.OPEN]
        filt_ports = [
            p for p in result.ports if p.state in (PortState.FILTERED, PortState.OPEN_FILTERED)
        ]

        w("\n")
        w(sep, "sep")
        w(f"  OPEN PORTS ({len(open_ports)})\n", "subheader")
        w(sep, "sep")

        if open_ports:
            w(f"  {'PORT':<8} {'PROTO':<6} {'SERVICE':<18} {'VERSION':<25} {'RTT':>8}\n", "key")
            w("  " + "─" * 66 + "\n", "sep")
            for p in open_ports:
                w(f"  {p.port:<8} {p.protocol.upper():<6} ", "value")
                w(f"{p.service:<18} ", "open")
                w(f"{p.version[:24]:<25} ", "value")
                w(f"{p.response_time*1000:>7.1f}ms\n", "value")
                if p.banner:
                    for line in p.banner.splitlines()[:4]:
                        w(f"          ↳ {line[:65]}\n", "banner_text")
                if p.ssl_info:
                    ssl = p.ssl_info
                    w(
                        f"          ↳ SSL: {ssl.get('version','')}  Cipher: {ssl.get('cipher','')} ({ssl.get('cipher_bits',0)} bits)\n",
                        "ssl_text",
                    )
                    if ssl.get("common_name"):
                        w(f"          ↳ CN: {ssl['common_name']}", "ssl_text")
                    if ssl.get("not_after"):
                        w(f"  Expires: {ssl['not_after']}\n", "ssl_text")
        else:
            w("  No open ports found.\n", "closed")

        if filt_ports:
            w("\n")
            w(sep, "sep")
            w(f"  FILTERED PORTS ({len(filt_ports)})\n", "subheader")
            w(sep, "sep")
            ports_str = ", ".join(str(p.port) for p in filt_ports[:50])
            if len(filt_ports) > 50:
                ports_str += f" ... (+{len(filt_ports)-50} more)"
            w(f"  {ports_str}\n", "filtered")

        dt.configure(state="disabled")

    def _update_stats_tab(self):
        """Update the statistics tab with current scan data."""
        st = self.stats_text
        st.configure(state="normal")
        st.delete("1.0", "end")

        def w(text, tag=None):
            st.insert("end", text, tag)

        if not self.scan_results:
            w("  No scan data available yet.\n", "key")
            st.configure(state="disabled")
            return

        sep = "─" * 60 + "\n"

        w("◈ SCAN STATISTICS\n", "header")
        w(sep, "sep")

        all_open = []
        service_counts = defaultdict(int)
        port_counts = defaultdict(int)
        for r in self.scan_results:
            for p in r.ports:
                if p.state == PortState.OPEN:
                    all_open.append(p)
                    if p.service:
                        service_counts[p.service] += 1
                    port_counts[p.port] += 1

        total_scanned = sum(len(r.ports) for r in self.scan_results)
        hosts_up = sum(1 for r in self.scan_results if r.host_up)

        w(f"  Hosts Scanned     : ", "key")
        w(f"{len(self.scan_results)}\n", "val")
        w(f"  Hosts Up          : ", "key")
        w(f"{hosts_up}\n", "val")
        w(f"  Total Ports Tested: ", "key")
        w(f"{total_scanned:,}\n", "val")
        w(f"  Open Ports Found  : ", "key")
        w(f"{len(all_open)}\n", "val")
        w(f"  Filtered Ports    : ", "key")
        w(f"{self.stat_filtered.get()}\n", "val")

        if self.scan_results:
            total_dur = sum(r.scan_duration for r in self.scan_results)
            w(f"  Total Scan Time   : ", "key")
            w(f"{total_dur:.2f}s\n", "val")
            if total_scanned > 0:
                rate = total_scanned / max(total_dur, 0.01)
                w(f"  Avg Port Rate     : ", "key")
                w(f"{rate:.0f} ports/sec\n", "val")

        if service_counts:
            w("\n")
            w(sep, "sep")
            w("  TOP SERVICES\n", "header")
            w(sep, "sep")
            for svc, count in sorted(service_counts.items(), key=lambda x: -x[1])[:15]:
                bar_len = int(count / max(service_counts.values()) * 30)
                bar = "█" * bar_len + "░" * (30 - bar_len)
                w(f"  {svc:<20}", "key")
                w(f"{bar}", "bar_fill")
                w(f"  {count}\n", "val")

        if port_counts:
            w("\n")
            w(sep, "sep")
            w("  TOP OPEN PORTS\n", "header")
            w(sep, "sep")
            w(f"  {'PORT':<8} {'SERVICE':<18} {'COUNT':>6}\n", "key")
            w("  " + "─" * 35 + "\n", "sep")
            for port, count in sorted(port_counts.items(), key=lambda x: -x[1])[:20]:
                svc = self.service_db.get_service_name(port)
                w(f"  {port:<8} {svc:<18} {count:>6}\n", "val")

        # OS distribution
        os_counts = defaultdict(int)
        for r in self.scan_results:
            if r.os_guess:
                os_counts[r.os_guess] += 1

        if os_counts:
            w("\n")
            w(sep, "sep")
            w("  OS DISTRIBUTION\n", "header")
            w(sep, "sep")
            for os_name, count in sorted(os_counts.items(), key=lambda x: -x[1]):
                bar_len = int(count / max(os_counts.values()) * 25)
                bar = "█" * bar_len
                w(f"  {os_name:<25}", "key")
                w(f"{bar}  {count}\n", "val")

        st.configure(state="disabled")

    # ─────────────────────────── FILTER & SORT ───────────────────────────

    def _apply_filter(self, *args):
        self._refresh_results_view()

    def _refresh_results_view(self):
        """Rebuild the treeview from scan_results with current filters/sort."""
        import re

        self.tree.delete(*self.tree.get_children())

        host_filter = self.var_host_filter.get()
        ftext = self.var_filter_text.get().lower()
        use_regex = self.var_filter_regex.get()
        show_filtered = self.var_show_filtered.get()
        show_closed = self.var_show_closed.get()
        sort_val = self.var_sort.get()

        # Compile regex if needed
        regex_pattern = None
        if ftext and use_regex:
            try:
                regex_pattern = re.compile(ftext, re.IGNORECASE)
            except re.error:
                self._log(f"Invalid regex: {ftext}", "error")
                regex_pattern = None

        all_rows = []
        for result in self.scan_results:
            if host_filter != "All" and result.target != host_filter:
                continue
            for p in result.ports:
                if p.state == PortState.OPEN:
                    tag = "open"
                elif p.state in (PortState.FILTERED, PortState.OPEN_FILTERED):
                    if not show_filtered:
                        continue
                    tag = "filtered"
                else:
                    if not show_closed:
                        continue
                    tag = "closed"

                banner_short = p.banner.splitlines()[0][:80] if p.banner else ""
                row_str = f"{result.target} {p.port} {p.protocol} {p.state.value} {p.service} {p.version} {banner_short}".lower()

                # Apply filter
                if ftext:
                    if use_regex and regex_pattern:
                        if not regex_pattern.search(row_str):
                            continue
                    elif not use_regex and ftext not in row_str:
                        continue

                all_rows.append((result.target, p, tag, banner_short))

        # Sort
        if sort_val == "Port ↑":
            all_rows.sort(key=lambda x: x[1].port)
        elif sort_val == "Port ↓":
            all_rows.sort(key=lambda x: -x[1].port)
        elif sort_val == "Service":
            all_rows.sort(key=lambda x: x[1].service)
        elif sort_val == "Response Time":
            all_rows.sort(key=lambda x: x[1].response_time)
        elif sort_val == "State":
            all_rows.sort(key=lambda x: x[1].state.value)

        for i, (target, p, tag, banner_short) in enumerate(all_rows):
            rtt = f"{p.response_time * 1000:.1f}"
            tags = (tag, "alt") if i % 2 == 0 else (tag,)
            self.tree.insert(
                "",
                "end",
                values=(
                    target,
                    p.port,
                    p.protocol.upper(),
                    p.state.value,
                    p.service,
                    p.version,
                    rtt,
                    banner_short,
                ),
                tags=tags,
            )

        self.lbl_result_count.configure(text=f"{len(all_rows)} results")

    def _sort_tree(self, col: str):
        items = [(self.tree.set(iid, col), iid) for iid in self.tree.get_children()]
        try:
            items.sort(key=lambda x: int(x[0]))
        except (ValueError, TypeError):
            items.sort(key=lambda x: x[0].lower())
        for i, (_, iid) in enumerate(items):
            self.tree.move(iid, "", i)

    # ─────────────────────────── EXPORT ───────────────────────────

    def _export_menu(self):
        menu = tk.Menu(
            self,
            tearoff=0,
            bg=C["surface2"],
            fg=C["text"],
            activebackground=C["select"],
            activeforeground=C["white"],
            font=FONT_MONO_SM,
            bd=0,
            relief="solid",
        )
        for label, fmt in [
            ("Export as JSON", "json"),
            ("Export as CSV", "csv"),
            ("Export as HTML Report", "html"),
            ("Export as XML", "xml"),
            ("Export as Text", "txt"),
        ]:
            menu.add_command(label=label, command=lambda f=fmt: self._export(f))

        menu.add_separator()
        menu.add_command(label="Copy visible results", command=self._copy_results)
        try:
            menu.tk_popup(self.winfo_pointerx(), self.winfo_pointery())
        finally:
            menu.grab_release()

    def _export(self, fmt: str):
        if not self.scan_results:
            messagebox.showwarning("No Data", "No scan results to export.")
            return

        ext_map = {"json": ".json", "csv": ".csv", "html": ".html", "xml": ".xml", "txt": ".txt"}
        ft_map = {
            "json": [("JSON files", "*.json")],
            "csv": [("CSV files", "*.csv")],
            "html": [("HTML files", "*.html")],
            "xml": [("XML files", "*.xml")],
            "txt": [("Text files", "*.txt")],
        }

        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default = f"nexscan_{ts}{ext_map[fmt]}"
        path = filedialog.asksaveasfilename(
            defaultextension=ext_map[fmt], filetypes=ft_map[fmt], initialfile=default
        )
        if not path:
            return

        try:
            fn_map = {
                "json": export_json,
                "csv": export_csv,
                "html": export_html,
                "xml": export_xml,
                "txt": export_txt,
            }
            content = fn_map[fmt](self.scan_results)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            self._log(f"Exported {fmt.upper()} report to: {path}", "info")
            messagebox.showinfo("Export Successful", f"Report saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def _copy_results(self):
        rows = []
        for iid in self.tree.get_children():
            values = self.tree.item(iid, "values")
            rows.append("\t".join(str(v) for v in values))
        self.clipboard_clear()
        self.clipboard_append("\n".join(rows))
        self._log(f"Copied {len(rows)} rows to clipboard.", "info")

    # ─────────────────────────── MISC ───────────────────────────

    def _apply_port_preset(self, event=None):
        preset = self.var_port_preset.get()
        ports = self.service_db.get_preset_ports(preset)
        if ports:
            self.txt_ports.delete("1.0", "end")
            self.txt_ports.insert("1.0", ",".join(str(p) for p in ports))
            self._log(f"Applied preset '{preset}': {len(ports)} ports", "info")

    def _count_ports(self):
        port_text = self.txt_ports.get("1.0", "end").strip().replace("\n", ",")
        try:
            ports = parse_ports(port_text)
            self.lbl_port_count.configure(
                text=f"Ports to scan: {len(ports):,}", fg=C["green"] if ports else C["red"]
            )
        except Exception:
            self.lbl_port_count.configure(text="Invalid port range", fg=C["red"])

    def _resolve_targets(self):
        target_text = self.txt_targets.get("1.0", "end").strip()
        targets = parse_targets(target_text)
        self._log(f"Resolving {len(targets)} target(s)...", "info")

        def resolve():
            for t in targets:
                try:
                    ip = socket.gethostbyname(t)
                    try:
                        rdns = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        rdns = ""
                    info = f"{t} → {ip}"
                    if rdns and rdns != t:
                        info += f" ({rdns})"
                    self._log(info, "host")
                except Exception as e:
                    self._log(f"Could not resolve {t}: {e}", "error")

        threading.Thread(target=resolve, daemon=True).start()

    def _clear_results(self):
        if self.is_scanning:
            messagebox.showwarning("Scan Running", "Stop the scan before clearing results.")
            return
        self._clear_results_internal()

    def _clear_results_internal(self):
        self.scan_results = []
        self.tree.delete(*self.tree.get_children())
        self.host_listbox.delete(0, "end")
        self.stat_open.set(0)
        self.stat_filtered.set(0)
        self.stat_hosts_up.set(0)
        self.stat_ports_done.set(0)
        self.progress["value"] = 0
        self.lbl_progress.configure(text="0%")
        self.lbl_timer.configure(text="00:00:00", fg=C["text3"])
        self.lbl_timer_icon.configure(fg=C["text3"])
        self.lbl_result_count.configure(text="0 results")
        self._set_status("IDLE", C["text2"])
        self._set_current("—")

        st = self.stats_text
        st.configure(state="normal")
        st.delete("1.0", "end")
        st.configure(state="disabled")

    def _clear_log(self):
        self.txt_log.configure(state="normal")
        self.txt_log.delete("1.0", "end")
        self.txt_log.configure(state="disabled")

    def _tree_context_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        values = self.tree.item(iid, "values")

        menu = tk.Menu(
            self,
            tearoff=0,
            bg=C["surface2"],
            fg=C["text"],
            activebackground=C["select"],
            activeforeground=C["white"],
            font=FONT_MONO_SM,
            bd=0,
        )

        host, port = values[0], values[1]
        menu.add_command(
            label=f"Copy {host}:{port}", command=lambda: self._copy_text(f"{host}:{port}")
        )
        menu.add_command(label=f"Copy IP {host}", command=lambda: self._copy_text(host))
        menu.add_separator()
        menu.add_command(
            label="Show Port Detail", command=lambda: self._show_port_detail_by_values(values)
        )
        menu.add_command(
            label=f"Filter by port {port}", command=lambda: self.var_filter_text.set(str(port))
        )
        menu.add_command(
            label=f"Filter by host {host}", command=lambda: self.var_filter_text.set(host)
        )
        menu.add_command(label="Clear filter", command=lambda: self.var_filter_text.set(""))

        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _copy_text(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text)

    def _show_port_detail(self, event):
        iid = self.tree.focus()
        if not iid:
            return
        values = self.tree.item(iid, "values")
        self._show_port_detail_by_values(values)

    def _show_port_detail_by_values(self, values):
        host, port_str = values[0], values[1]
        try:
            port = int(port_str)
        except ValueError:
            return

        # Find result
        for r in self.scan_results:
            if r.target == host or r.ip_address == host:
                for p in r.ports:
                    if p.port == port:
                        self._show_port_popup(r, p)
                        return

    def _show_port_popup(self, result: ScanResult, pr: PortResult):
        popup = tk.Toplevel(self)
        popup.title(f"Port Detail — {result.target}:{pr.port}")
        popup.configure(bg=C["bg"])
        popup.geometry("620x500")
        popup.resizable(True, True)

        txt = tk.Text(
            popup,
            bg=C["bg"],
            fg=C["text"],
            font=FONT_MONO_SM,
            state="normal",
            relief="flat",
            padx=16,
            pady=12,
            wrap="word",
        )
        vsb = ttk.Scrollbar(popup, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        txt.pack(fill="both", expand=True)

        for tag, fg_c in [
            ("key", C["text2"]),
            ("val", C["text"]),
            ("open", C["green"]),
            ("head", C["accent"]),
            ("banner", C["orange"]),
            ("ssl", C["accent2"]),
        ]:
            txt.tag_configure(tag, foreground=fg_c)
        txt.tag_configure("bold", font=("Consolas", 10, "bold"))

        def w(t, tag=None):
            txt.insert("end", t, tag)

        w(f"PORT DETAIL\n", "head")
        w("─" * 50 + "\n", "key")
        w(f"Host       : ", "key")
        w(f"{result.target}\n", "val")
        w(f"IP         : ", "key")
        w(f"{result.ip_address}\n", "val")
        w(f"Port       : ", "key")
        w(f"{pr.port}/{pr.protocol.upper()}\n", "open")
        w(f"State      : ", "key")
        w(f"{pr.state.value}\n", "open")
        w(f"Service    : ", "key")
        w(f"{pr.service}\n", "val")
        w(f"Version    : ", "key")
        w(f"{pr.version}\n", "val")
        w(f"CPE        : ", "key")
        w(f"{pr.cpe}\n", "val")
        w(f"RTT        : ", "key")
        w(f"{pr.response_time*1000:.2f}ms\n", "val")
        w("\n")

        if pr.banner:
            w("BANNER\n", "head")
            w("─" * 50 + "\n", "key")
            w(pr.banner[:1000] + "\n", "banner")
            w("\n")

        if pr.ssl_info:
            w("SSL/TLS INFO\n", "head")
            w("─" * 50 + "\n", "key")
            ssl = pr.ssl_info
            for k, v in ssl.items():
                if isinstance(v, list):
                    v = ", ".join(v[:5])
                w(f"{k:<20}: ", "key")
                w(f"{v}\n", "ssl")

        txt.configure(state="disabled")

        # Close button
        self._make_button(
            popup, "  Close  ", popup.destroy, fg=C["text"], bg=C["btn_bg"], hover_bg=C["btn_hover"]
        ).pack(pady=8)

    def _show_about(self):
        popup = tk.Toplevel(self)
        popup.title("About NexScan")
        popup.configure(bg=C["bg"])
        popup.geometry("580x480")
        popup.resizable(False, False)

        txt = tk.Text(
            popup,
            bg=C["bg"],
            fg=C["text"],
            font=FONT_MONO_SM,
            state="normal",
            relief="flat",
            padx=24,
            pady=20,
            wrap="word",
        )
        txt.pack(fill="both", expand=True)

        for tag, fg_c, fnt in [
            ("h1", C["accent"], FONT_TITLE),
            ("h2", C["purple"], FONT_MONO_LG),
            ("key", C["text2"], FONT_MONO_SM),
            ("val", C["text"], FONT_MONO_SM),
        ]:
            txt.tag_configure(tag, foreground=fg_c, font=fnt)

        txt.insert("end", f"◈ NEXSCAN\n", "h1")
        txt.insert("end", f"v{self.VERSION} — Advanced Port Scanner\n\n", "val")
        txt.insert("end", "KEYBOARD SHORTCUTS\n", "h2")
        txt.insert("end", "F5              Start scan\n", "key")
        txt.insert("end", "Escape          Stop/Cancel scan\n", "key")
        txt.insert("end", "Ctrl+E          Export results\n", "key")
        txt.insert("end", "Ctrl+L          Clear results\n", "key")
        txt.insert("end", "Ctrl+F          Focus filter box\n", "key")
        txt.insert("end", "Ctrl+S          Save profile\n", "key")
        txt.insert("end", "Ctrl+O          Load profile\n\n", "key")
        txt.insert("end", "FEATURES\n", "h2")
        txt.insert("end", "✓ Multi-protocol scanning (TCP/UDP/SYN)\n", "val")
        txt.insert("end", "✓ Real-time progress with ETA\n", "val")
        txt.insert("end", "✓ Regex & text filtering\n", "val")
        txt.insert("end", "✓ Service detection & OS fingerprinting\n", "val")
        txt.insert("end", "✓ SSL/TLS certificate inspection\n", "val")
        txt.insert("end", "✓ Multiple export formats\n", "val")
        txt.insert("end", "✓ Live event logging\n\n", "val")
        txt.insert("end", "For authorized use only. Respect applicable laws.\n", "key")

        txt.configure(state="disabled")
        txt.insert("end", f"  Advanced Port Scanner v{self.VERSION}\n\n", "key")
        txt.insert("end", "CAPABILITIES\n", "h2")
        features = [
            "Multi-threaded TCP Connect scanning",
            "UDP scanning with service probes",
            "Banner grabbing & service fingerprinting",
            "SSL/TLS certificate inspection",
            "Heuristic OS detection",
            "CIDR range & multi-host scanning",
            "Real-time live results stream",
            "Export: JSON, CSV, HTML, XML, TXT",
            "Port presets & custom ranges",
            "Host discovery & reverse DNS",
            "Result filtering & sorting",
            "Pause/Resume scan control",
        ]
        for f in features:
            txt.insert("end", f"  ✓ {f}\n", "key")

        txt.insert("end", "\n⚠ LEGAL NOTICE\n", "h2")
        txt.insert(
            "end",
            "  Only scan systems you own or have explicit permission\n"
            "  to scan. Unauthorized port scanning may be illegal.\n",
            "key",
        )

        txt.configure(state="disabled")

        self._make_button(
            popup, "  Close  ", popup.destroy, fg=C["text"], bg=C["btn_bg"], hover_bg=C["btn_hover"]
        ).pack(pady=10)

    def _save_profile(self):
        """Save current scan configuration as a profile."""
        import json

        file = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("NexScan Profile", "*.json"), ("All Files", "*.*")],
            initialfile="nexscan_profile.json",
        )
        if not file:
            return

        profile = {
            "targets": self.txt_targets.get("1.0", "end").strip(),
            "ports": self.txt_ports.get("1.0", "end").strip(),
            "scan_type": self.var_scan_type.get(),
            "threads": self.var_threads.get(),
            "timeout": self.var_timeout.get(),
            "connect_timeout": self.var_connect_timeout.get(),
            "banner_grab": self.var_banner_grab.get(),
            "service_detect": self.var_service_detect.get(),
            "os_detect": self.var_os_detect.get(),
            "ssl_probe": self.var_ssl_probe.get(),
            "host_discovery": self.var_host_discovery.get(),
        }
        try:
            with open(file, "w") as f:
                json.dump(profile, f, indent=2)
            self._log(f"Profile saved to {file}", "info")
            messagebox.showinfo("Success", f"Profile saved to\n{file}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save profile: {e}")

    def _load_profile(self):
        """Load a saved scan configuration profile."""
        import json

        file = filedialog.askopenfilename(
            filetypes=[("NexScan Profile", "*.json"), ("All Files", "*.*")]
        )
        if not file:
            return

        try:
            with open(file, "r") as f:
                profile = json.load(f)

            self.txt_targets.delete("1.0", "end")
            self.txt_targets.insert("1.0", profile.get("targets", ""))

            self.txt_ports.delete("1.0", "end")
            self.txt_ports.insert("1.0", profile.get("ports", ""))

            self.var_scan_type.set(profile.get("scan_type", "TCP Connect"))
            self.var_threads.set(profile.get("threads", 300))
            self.var_timeout.set(profile.get("timeout", 1.5))
            self.var_connect_timeout.set(profile.get("connect_timeout", 3.0))
            self.var_banner_grab.set(profile.get("banner_grab", True))
            self.var_service_detect.set(profile.get("service_detect", True))
            self.var_os_detect.set(profile.get("os_detect", False))
            self.var_ssl_probe.set(profile.get("ssl_probe", True))
            self.var_host_discovery.set(profile.get("host_discovery", True))

            self._log(f"Profile loaded from {file}", "info")
            messagebox.showinfo("Success", f"Profile loaded from\n{file}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load profile: {e}")

    def _setup_bindings(self):
        self.bind("<F5>", lambda e: self._start_scan())
        self.bind("<Escape>", lambda e: self._stop_scan())
        self.bind("<Control-e>", lambda e: self._export_menu())
        self.bind("<Control-l>", lambda e: self._clear_results())
        self.bind("<Control-f>", lambda e: self.entry_filter.focus())
        self.bind("<Control-s>", lambda e: self._save_profile())
        self.bind("<Control-o>", lambda e: self._load_profile())

    def _on_close(self):
        if self.is_scanning:
            ok = messagebox.askyesno(
                "Scan Running", "A scan is currently running. Stop it and exit?", icon="warning"
            )
            if not ok:
                return
            if self.scanner:
                self.scanner.stop()
        self.destroy()


def main():
    app = NexScanApp()
    app.mainloop()


if __name__ == "__main__":
    main()
