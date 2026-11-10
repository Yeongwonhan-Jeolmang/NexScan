"""
NexScan GUI — Main Application Window
Dark terminal-inspired professional port scanner interface.
"""

import datetime
import json
import os
import queue
import re
import socket
import sys
import threading
import time
import tkinter as tk
import webbrowser
from collections import defaultdict
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

# Add parent dir to path (before local imports so `python gui/app.py` works)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scanner import (  # noqa: E402
    RAW_SCAN_TYPES,
    PortResult,
    PortScanner,
    PortState,
    ScanConfig,
    ScanResult,
    ScanType,
    parse_ports,
    parse_targets,
)
from core.service_db import ServiceDatabase  # noqa: E402
from reports.exporter import EXPORTERS  # noqa: E402

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
    "row_even": "#111620",
    "row_odd": "#0e131c",
    "disabled": "#2a3348",
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
FONT_TINY = ("Consolas", 8)

_MONO_CANDIDATES = (
    "Cascadia Mono",
    "Consolas",
    "JetBrains Mono",
    "SF Mono",
    "Menlo",
    "DejaVu Sans Mono",
    "Liberation Mono",
    "Courier New",
)
_UI_CANDIDATES = ("Segoe UI", "SF Pro Text", "Helvetica Neue", "Inter", "Cantarell", "DejaVu Sans")

# Where the GUI remembers its last-used settings between sessions
SETTINGS_DIR = os.path.join(
    os.environ.get("APPDATA")
    or os.environ.get("XDG_CONFIG_HOME")
    or os.path.expanduser("~/.config"),
    "nexscan",
)
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "settings.json")


def _init_fonts(root: tk.Misc):
    """Pick installed font families (Consolas / Segoe UI don't exist on Linux/macOS)."""
    global FONT_MONO, FONT_MONO_SM, FONT_MONO_LG, FONT_MONO_XL, FONT_UI, FONT_UI_BOLD
    global FONT_UI_SM, FONT_TITLE, FONT_STAT, FONT_TINY
    try:
        families = set(tkfont.families(root))
    except tk.TclError:
        return
    mono = next((f for f in _MONO_CANDIDATES if f in families), "TkFixedFont")
    ui = next((f for f in _UI_CANDIDATES if f in families), "TkDefaultFont")
    FONT_MONO = (mono, 10)
    FONT_MONO_SM = (mono, 9)
    FONT_MONO_LG = (mono, 12)
    FONT_MONO_XL = (mono, 14)
    FONT_UI = (ui, 10)
    FONT_UI_BOLD = (ui, 10, "bold")
    FONT_UI_SM = (ui, 9)
    FONT_TITLE = (mono, 16, "bold")
    FONT_STAT = (mono, 22, "bold")
    FONT_TINY = (mono, 8)


class _FlatButton(tk.Label):
    """Flat label-based button with hover, disabled state and keyboard-free styling."""

    def __init__(self, parent, text, command, fg, bg, hover_bg, pad):
        super().__init__(
            parent,
            text=text,
            font=FONT_MONO_SM,
            bg=bg,
            fg=fg,
            cursor="hand2",
            padx=pad[0],
            pady=pad[1],
        )
        self._command = command
        self._fg, self._bg, self._hover_bg = fg, bg, hover_bg
        self._enabled = True
        self.bind("<Button-1>", self._on_click)
        self.bind("<Enter>", lambda e: self._enabled and self.configure(bg=self._hover_bg))
        self.bind("<Leave>", lambda e: self.configure(bg=self._bg))

    def _on_click(self, _event=None):
        if self._enabled:
            self._command()

    def set_enabled(self, enabled: bool):
        self._enabled = enabled
        self.configure(
            fg=self._fg if enabled else C["disabled"],
            cursor="hand2" if enabled else "arrow",
            bg=self._bg,
        )

    def set_text(self, text: str, fg: str = ""):
        if fg:
            self._fg = fg
        self.configure(text=text, fg=self._fg if self._enabled else C["disabled"])


class NexScanApp(tk.Tk):
    VERSION = "3.0"

    def __init__(self):
        super().__init__()
        self.title(f"NexScan v{self.VERSION} — Advanced Port Scanner")
        self.configure(bg=C["bg"])
        self.geometry("1400x900")
        self.minsize(1100, 700)

        # Queue for thread-safe UI updates (created first: widgets may log during build)
        self._ui_queue: queue.Queue = queue.Queue()

        _init_fonts(self)
        self._setup_style()
        self._init_state()
        self._build_ui()
        self._setup_bindings()
        self._load_settings()
        self._count_ports()
        self._count_targets()

        self._poll_queue()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _setup_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        # Base defaults so no widget falls back to clam's light bevels
        style.configure(
            ".",
            background=C["surface2"],
            foreground=C["text"],
            bordercolor=C["border2"],
            darkcolor=C["surface2"],
            lightcolor=C["surface2"],
            troughcolor=C["bg"],
            focuscolor=C["accent2"],
            selectbackground=C["select"],
            selectforeground=C["white"],
            insertcolor=C["accent"],
            font=FONT_MONO_SM,
        )

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
            padding=(6, 5),
        )
        style.map(
            "Treeview",
            background=[("selected", C["select"])],
            foreground=[("selected", C["white"])],
        )
        style.map(
            "Treeview.Heading",
            background=[("active", C["border"])],
            foreground=[("active", C["white"])],
        )
        style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])

        # Scrollbars — slim, borderless, highlight on hover
        for orient in ("Vertical", "Horizontal"):
            style.configure(
                f"{orient}.TScrollbar",
                background=C["border2"],
                troughcolor=C["bg"],
                bordercolor=C["bg"],
                darkcolor=C["border2"],
                lightcolor=C["border2"],
                arrowcolor=C["text3"],
                borderwidth=0,
                arrowsize=10,
                width=10,
                gripcount=0,
            )
            style.map(
                f"{orient}.TScrollbar",
                background=[("active", C["accent2"]), ("pressed", C["accent"])],
                arrowcolor=[("active", C["accent"])],
            )

        # Progressbar
        style.configure(
            "Scan.Horizontal.TProgressbar",
            background=C["accent"],
            troughcolor=C["surface2"],
            bordercolor=C["surface2"],
            darkcolor=C["accent"],
            lightcolor=C["accent"],
            borderwidth=0,
            thickness=8,
        )

        # Notebook tabs
        style.configure("TNotebook", background=C["bg"], borderwidth=0, tabmargins=(0, 4, 0, 0))
        style.configure(
            "TNotebook.Tab",
            background=C["surface2"],
            foreground=C["text2"],
            padding=[14, 7],
            font=FONT_MONO_SM,
            borderwidth=0,
            bordercolor=C["bg"],
            lightcolor=C["surface2"],
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", C["surface"]), ("active", C["border"])],
            foreground=[("selected", C["accent"]), ("active", C["text"])],
            lightcolor=[("selected", C["accent"])],
            expand=[("selected", (0, 2, 0, 0))],
        )
        # Settings notebook inside the left panel sits on surface2
        style.configure("Inner.TNotebook", background=C["surface2"], borderwidth=0)
        style.configure(
            "Inner.TNotebook.Tab",
            background=C["input_bg"],
            foreground=C["text2"],
            padding=[10, 5],
            font=FONT_MONO_SM,
            borderwidth=0,
            bordercolor=C["surface2"],
            lightcolor=C["input_bg"],
        )
        style.map(
            "Inner.TNotebook.Tab",
            background=[("selected", C["surface2"]), ("active", C["border"])],
            foreground=[("selected", C["accent"]), ("active", C["text"])],
            lightcolor=[("selected", C["accent"])],
        )

        # Separators
        style.configure("TSeparator", background=C["border"])

        # Combobox (+ its popdown listbox, which is a plain Tk widget)
        style.configure(
            "TCombobox",
            fieldbackground=C["input_bg"],
            background=C["btn_bg"],
            foreground=C["text"],
            selectbackground=C["input_bg"],
            selectforeground=C["text"],
            bordercolor=C["border2"],
            darkcolor=C["input_bg"],
            lightcolor=C["input_bg"],
            arrowcolor=C["accent"],
            arrowsize=12,
            padding=(4, 2),
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", C["input_bg"])],
            foreground=[("readonly", C["text"])],
            background=[("active", C["btn_hover"]), ("readonly", C["btn_bg"])],
            bordercolor=[("focus", C["accent2"])],
        )
        self.option_add("*TCombobox*Listbox.background", C["surface2"])
        self.option_add("*TCombobox*Listbox.foreground", C["text"])
        self.option_add("*TCombobox*Listbox.selectBackground", C["select"])
        self.option_add("*TCombobox*Listbox.selectForeground", C["white"])
        self.option_add("*TCombobox*Listbox.font", FONT_MONO_SM)
        self.option_add("*TCombobox*Listbox.borderWidth", 0)

        # Spinbox
        style.configure(
            "TSpinbox",
            fieldbackground=C["input_bg"],
            background=C["btn_bg"],
            foreground=C["text"],
            bordercolor=C["border2"],
            darkcolor=C["input_bg"],
            lightcolor=C["input_bg"],
            arrowcolor=C["accent"],
            arrowsize=10,
            padding=(4, 1),
        )
        style.map(
            "TSpinbox",
            background=[("active", C["btn_hover"])],
            bordercolor=[("focus", C["accent2"])],
        )

        # Checkbutton
        style.configure(
            "TCheckbutton",
            background=C["surface2"],
            foreground=C["text"],
            focuscolor=C["surface2"],
            indicatorbackground=C["input_bg"],
            indicatorforeground=C["accent"],
            indicatorrelief="flat",
            indicatormargin=(0, 0, 6, 0),
            padding=(2, 2),
        )
        style.map(
            "TCheckbutton",
            background=[("active", C["surface2"])],
            foreground=[("active", C["white"]), ("disabled", C["text3"])],
            indicatorbackground=[("selected", C["accent_dim"]), ("active", C["btn_hover"])],
        )
        # Variant for toolbars on the darker surface colour
        style.configure("Bar.TCheckbutton", background=C["surface"])
        style.map("Bar.TCheckbutton", background=[("active", C["surface"])])

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
        self._paused_total = 0.0
        self._pause_started = None

        # Live row store: (target, proto, port) -> (target, PortResult). Filled while the
        # scan runs so filtering / sorting works before the scan completes.
        self._rows: dict = {}
        self._live_counts: dict = {}  # target -> {"open": n, "filtered": n}
        self._header_sort = None  # (column, descending) when sorted via a heading click
        self._refresh_job = None
        self._row_counter = 0
        self._vuln_busy = False
        self._raw_ok, self._raw_reason = self._detect_raw_support()

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
        self.var_filter_regex.trace_add("write", self._apply_filter)
        self.var_show_closed.trace_add("write", self._apply_filter)
        self.var_show_filtered.trace_add("write", self._apply_filter)

        # Advanced settings (created here so profiles / settings can always reach them)
        self.var_jitter = tk.DoubleVar(value=0.0)
        self.var_max_banner = tk.DoubleVar(value=2.0)
        self.var_udp_probes = tk.BooleanVar(value=True)
        self.var_quick_resolve = tk.BooleanVar(value=True)

        # History
        self.var_db_path = tk.StringVar(value=os.path.abspath("nexscan_history.db"))
        self.var_autosave = tk.BooleanVar(value=False)

    @staticmethod
    def _detect_raw_support() -> tuple[bool, str]:
        try:
            from core.raw_scan import raw_scans_available

            return raw_scans_available()
        except Exception as e:
            return False, str(e)

    def _build_ui(self):
        # ── Top bar ──
        self._build_topbar()
        # ── Status bar (packed before the expanding main area so it keeps its space) ──
        self._build_statusbar()
        # ── Main paned layout ──
        self._build_main()
        self._update_controls()

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

        # Quick action buttons (kept so their state can follow the scan)
        self.btn_start = self._make_button(
            bar, "▶  START SCAN", self._start_scan, fg=C["green"], pad=(14, 6)
        )
        self.btn_pause = self._make_button(
            bar, "⏸  PAUSE", self._toggle_pause, fg=C["yellow"], pad=(14, 6)
        )
        self.btn_stop = self._make_button(bar, "■  STOP", self._stop_scan, fg=C["red"], pad=(14, 6))
        self.btn_clear = self._make_button(
            bar, "⟳  CLEAR", self._clear_results, fg=C["text2"], pad=(14, 6)
        )
        for btn in (self.btn_start, self.btn_pause, self.btn_stop, self.btn_clear):
            btn.pack(side="left", padx=4, pady=10)

        # Right side: export + settings
        tk.Frame(bar, bg=C["header_bg"]).pack(side="left", fill="x", expand=True)

        for text, cmd, fg in [
            ("✦  ABOUT", self._show_about, C["text2"]),
            ("⬇  EXPORT", self._export_menu, C["purple"]),
            ("◷  HISTORY", lambda: self._select_tab(self.tab_history), C["accent"]),
        ]:
            btn = self._make_button(bar, text, cmd, fg=fg, pad=(14, 6))
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

    def _select_tab(self, tab):
        try:
            self.notebook.select(tab)
        except (tk.TclError, AttributeError):
            pass

    def _update_controls(self):
        """Sync toolbar buttons with the scan state."""
        scanning = self.is_scanning
        self.btn_start.set_enabled(not scanning)
        self.btn_pause.set_enabled(scanning)
        self.btn_stop.set_enabled(scanning)
        self.btn_clear.set_enabled(not scanning)
        if self.is_paused:
            self.btn_pause.set_text("▶  RESUME", fg=C["green"])
        else:
            self.btn_pause.set_text("⏸  PAUSE", fg=C["yellow"])

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
        # Scrollable container: the settings column is taller than small screens
        outer = tk.Frame(parent, bg=C["surface"])
        canvas = tk.Canvas(outer, bg=C["surface"], highlightthickness=0, bd=0)
        vsb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        frame = tk.Frame(canvas, bg=C["surface"])
        win = canvas.create_window((0, 0), window=frame, anchor="nw")
        frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(win, width=e.width))
        self._bind_mousewheel(outer, canvas)

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

        self.txt_targets.bind("<KeyRelease>", lambda e: self._count_targets())

        self.lbl_target_summary = tk.Label(
            sec,
            text="IP, range (192.168.1.1-50), CIDR, or hostname — one per line or comma-separated",
            bg=C["surface2"],
            fg=C["text3"],
            font=FONT_TINY,
            wraplength=300,
            justify="left",
            anchor="w",
        )
        self.lbl_target_summary.pack(fill="x", padx=8, pady=(0, 6))

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
        self.txt_ports.bind("<KeyRelease>", lambda e: self._count_ports())

        self.lbl_port_summary = tk.Label(
            sec2,
            text="e.g.: 22,80,443  or  1-1024  or  80,443,8000-9000",
            bg=C["surface2"],
            fg=C["text3"],
            font=FONT_TINY,
            anchor="w",
        )
        self.lbl_port_summary.pack(fill="x", padx=8, pady=(0, 6))

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
        grid = tk.Frame(sec3, bg=C["surface2"])
        grid.pack(fill="x", padx=6, pady=(2, 0))
        for i, st in enumerate(scan_types):
            needs_root = st.endswith("*")
            usable = self._raw_ok or not needs_root
            rb = tk.Radiobutton(
                grid,
                text=st,
                variable=self.var_scan_type,
                value=st,
                bg=C["surface2"],
                fg=C["text"] if not needs_root else C["text2"],
                disabledforeground=C["disabled"],
                selectcolor=C["input_bg"],
                activebackground=C["surface2"],
                activeforeground=C["white"],
                font=FONT_MONO_SM,
                cursor="hand2" if usable else "arrow",
                indicatoron=True,
                highlightthickness=0,
                bd=0,
                state="normal" if usable else "disabled",
            )
            rb.grid(row=i // 2, column=i % 2, sticky="w", padx=4, pady=2)
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)

        self.lbl_scan_hint = tk.Label(
            sec3,
            text="",
            bg=C["surface2"],
            fg=C["text2"],
            font=FONT_TINY,
            wraplength=300,
            justify="left",
            anchor="w",
        )
        self.lbl_scan_hint.pack(fill="x", padx=8, pady=(4, 0))
        root_note = (
            "* Raw packet scans — privileges OK"
            if self._raw_ok
            else f"* Unavailable: {self._raw_reason}"
        )
        tk.Label(
            sec3,
            text=root_note,
            bg=C["surface2"],
            fg=C["green"] if self._raw_ok else C["text3"],
            font=FONT_TINY,
            wraplength=300,
            justify="left",
        ).pack(anchor="w", padx=8, pady=(2, 6))
        self.var_scan_type.trace_add("write", lambda *a: self._update_scan_type_hint())
        self._update_scan_type_hint()

        # ── Settings tabs ──
        sec4 = self._section(frame, "SETTINGS")
        nb = ttk.Notebook(sec4, style="Inner.TNotebook")
        nb.pack(fill="both", expand=True, padx=6, pady=4)

        self._build_perf_tab(nb)
        self._build_output_tab(nb)
        self._build_advanced_tab(nb)

        return outer

    _SCAN_TYPE_HINTS = {
        "TCP Connect": "Full 3-way handshake. Works unprivileged; enables banners & TLS info.",
        "UDP": "Service-specific payloads. Silence = open|filtered, ICMP unreachable = closed.",
        "SYN Stealth*": "Half-open SYN probe: SYN/ACK = open, RST = closed. Fast and quiet.",
        "ACK*": "Maps firewall rules: RST = unfiltered, no reply = filtered.",
        "FIN*": "FIN probe slips past some stateless filters. RST = closed.",
        "XMAS*": "FIN+PSH+URG probe. RST = closed, silence = open|filtered.",
        "NULL*": "No flags set. RST = closed, silence = open|filtered.",
        "Window*": "ACK probe reading the RST window size (open on some BSD-derived stacks).",
    }

    def _update_scan_type_hint(self):
        if hasattr(self, "lbl_scan_hint"):
            self.lbl_scan_hint.configure(
                text=self._SCAN_TYPE_HINTS.get(self.var_scan_type.get(), "")
            )

    def _bind_mousewheel(self, area: tk.Widget, canvas: tk.Canvas):
        """Scroll *canvas* with the wheel while the pointer is over *area*."""

        def _on_wheel(event):
            if getattr(event, "num", 0) == 4:
                delta = -1
            elif getattr(event, "num", 0) == 5:
                delta = 1
            else:
                delta = -1 if event.delta > 0 else 1
            canvas.yview_scroll(delta * 2, "units")

        def _bind(_e):
            canvas.bind_all("<MouseWheel>", _on_wheel)
            canvas.bind_all("<Button-4>", _on_wheel)
            canvas.bind_all("<Button-5>", _on_wheel)

        def _unbind(_e):
            canvas.unbind_all("<MouseWheel>")
            canvas.unbind_all("<Button-4>")
            canvas.unbind_all("<Button-5>")

        area.bind("<Enter>", _bind)
        area.bind("<Leave>", _unbind)

    def _build_perf_tab(self, notebook):
        tab = tk.Frame(notebook, bg=C["surface2"])
        notebook.add(tab, text="Performance")

        items = [
            ("Threads", self.var_threads, 1, 1000, ""),
            ("Reply Timeout (s)", self.var_timeout, 0.1, 30.0, "UDP/raw"),
            ("Connect Timeout (s)", self.var_connect_timeout, 0.5, 60.0, "TCP"),
            ("Rate Limit (ms)", self.var_rate_limit, 0.0, 5000.0, "0=off"),
            ("Probe Attempts", self.var_retry, 1, 5, "UDP/raw"),
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
                width=19,
                anchor="w",
            ).pack(side="left")
            is_int = isinstance(var, tk.IntVar)
            inc = 1 if is_int else 0.1
            sp = ttk.Spinbox(
                row, from_=mn, to=mx, textvariable=var, width=8, font=FONT_MONO_SM, increment=inc
            )
            sp.pack(side="left", padx=4)
            if hint:
                tk.Label(row, text=hint, bg=C["surface2"], fg=C["text3"], font=FONT_TINY).pack(
                    side="left"
                )

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
        ttk.Checkbutton(tab, text="UDP Service Probes", variable=self.var_udp_probes).pack(
            anchor="w", padx=10, pady=3
        )

        # Quick resolve
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
        self.lbl_rate = tk.Label(
            eta_col, text="", bg=C["bg"], fg=C["text3"], font=FONT_MONO_SM, width=12, anchor="e"
        )
        self.lbl_rate.pack(side="left")

        # ── Notebook: Results / Log / Detail / Stats / Vulns / History ──
        nb = ttk.Notebook(frame)
        nb.pack(fill="both", expand=True, padx=8, pady=(0, 4))
        self.notebook = nb

        self._build_results_tab(nb)
        self._build_log_tab(nb)
        self._build_detail_tab(nb)
        self._build_compare_tab(nb)
        self._build_vuln_tab(nb)
        self._build_history_tab(nb)

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
            tk.Frame(inner, bg=color, height=2).pack(fill="x", side="top")

            val_lbl = tk.Label(inner, textvariable=var, font=FONT_STAT, bg=C["surface2"], fg=color)
            val_lbl.pack(pady=(6, 0))
            tk.Label(inner, text=label, font=FONT_MONO_SM, bg=C["surface2"], fg=C["text3"]).pack()

        # Separator + scan info
        sep = tk.Frame(bar, bg=C["border"], width=1)
        sep.pack(side="left", fill="y", pady=8)

        info_col = tk.Frame(bar, bg=C["surface"])
        info_col.pack(side="left", fill="both", expand=True, padx=2)
        inner2 = tk.Frame(info_col, bg=C["surface2"])
        inner2.pack(fill="both", expand=True, padx=2, pady=4)
        self.status_strip = tk.Frame(inner2, bg=C["text3"], height=2)
        self.status_strip.pack(fill="x", side="top")

        tk.Label(inner2, text="STATUS", font=FONT_MONO_SM, bg=C["surface2"], fg=C["text3"]).pack(
            pady=(6, 0)
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

        ttk.Checkbutton(
            fbar, text="Regex", variable=self.var_filter_regex, style="Bar.TCheckbutton"
        ).pack(side="left", padx=2)

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
        sort_cb.bind("<<ComboboxSelected>>", self._on_sort_preset)

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
        self._col_labels = dict(zip(cols, col_labels))

        for col, lbl, w in zip(cols, col_labels, col_widths):
            self.tree.heading(col, text=lbl, command=lambda c=col: self._sort_tree(c))
            anchor = "center" if col in ("port", "proto", "rtt") else "w"
            self.tree.column(col, width=w, minwidth=40, anchor=anchor, stretch=col == "banner")

        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self.tree.pack(fill="both", expand=True)

        # Row tags: state sets the text colour, striping sets the background
        self.tree.tag_configure("even", background=C["row_even"])
        self.tree.tag_configure("odd", background=C["row_odd"])
        self.tree.tag_configure("open", foreground=C["green"])
        self.tree.tag_configure("filtered", foreground=C["yellow"])
        self.tree.tag_configure("closed", foreground=C["text3"])
        self.tree.tag_configure("warn", foreground=C["orange"])

        # Empty-state hint (hidden as soon as rows appear)
        self.lbl_empty = tk.Label(
            tree_frame,
            text="No results yet\n\nEnter a target and press F5 to start a scan",
            bg=C["surface"],
            fg=C["text3"],
            font=FONT_MONO,
            justify="center",
        )
        self.lbl_empty.place(relx=0.5, rely=0.45, anchor="center")

        # Context menu (Button-2 is the right button on macOS)
        self.tree.bind("<Button-3>", self._tree_context_menu)
        if sys.platform == "darwin":
            self.tree.bind("<Button-2>", self._tree_context_menu)
        self.tree.bind("<Double-Button-1>", self._show_port_detail)
        self.tree.bind("<Return>", self._show_port_detail)
        self.tree.bind("<Control-c>", lambda e: self._copy_selected_rows())

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
                highlightthickness=0,
                bd=0,
                command=self._rerender_log,
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
        ttk.Checkbutton(
            ctrl, text="Auto-scroll", variable=self.var_autoscroll, style="Bar.TCheckbutton"
        ).pack(side="right", padx=4)

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
        self.detail_text.tag_configure("bold", font=(FONT_MONO[0], 10, "bold"))
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
        self.tab_vuln = tab

        ctrl = tk.Frame(tab, bg=C["surface"])
        ctrl.pack(fill="x", padx=4, pady=(4, 2))

        self.btn_cve = self._make_button(
            ctrl, "🔍 Lookup CVEs", self._lookup_cves, fg=C["red"], pad=(8, 3)
        )
        self.btn_cve.pack(side="left", padx=4, pady=4)
        self.btn_geo = self._make_button(
            ctrl, "📍 Geolocation + WHOIS", self._lookup_geolocation, fg=C["accent"], pad=(8, 3)
        )
        self.btn_geo.pack(side="left", padx=4, pady=4)

        self.lbl_vuln_status = tk.Label(
            ctrl, text="", bg=C["surface"], fg=C["text3"], font=FONT_MONO_SM
        )
        self.lbl_vuln_status.pack(side="left", padx=12)
        key_note = (
            "NVD API key: set"
            if os.environ.get("NVD_API_KEY")
            else "Tip: set NVD_API_KEY for 10× faster lookups"
        )
        tk.Label(ctrl, text=key_note, bg=C["surface"], fg=C["text3"], font=FONT_TINY).pack(
            side="right", padx=8
        )

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
            cursor="arrow",
        )

        vuln_vsb = ttk.Scrollbar(vuln_frame, orient="vertical", command=self.vuln_text.yview)
        self.vuln_text.configure(yscrollcommand=vuln_vsb.set)

        vuln_vsb.pack(side="right", fill="y")
        self.vuln_text.pack(fill="both", expand=True)

        # Tags
        for tag, fg_c in [
            ("cve_critical", C["red"]),
            ("cve_high", C["orange"]),
            ("cve_medium", C["yellow"]),
            ("cve_low", C["green"]),
            ("header", C["accent"]),
            ("geo_info", C["accent2"]),
            ("muted", C["text3"]),
            ("link", C["accent"]),
        ]:
            self.vuln_text.tag_configure(tag, foreground=fg_c)
        self.vuln_text.tag_configure("link", underline=True)
        self.vuln_text.tag_bind(
            "link", "<Enter>", lambda e: self.vuln_text.configure(cursor="hand2")
        )
        self.vuln_text.tag_bind(
            "link", "<Leave>", lambda e: self.vuln_text.configure(cursor="arrow")
        )
        self.vuln_text.tag_bind("link", "<Button-1>", self._open_link_under_cursor)
        self._vuln_write(
            "Run a scan, then look up known CVEs for fingerprinted services or\n"
            "geolocate public hosts. Lookups run in the background.\n",
            "muted",
            clear=True,
        )

    def _build_history_tab(self, notebook):
        """Saved scan runs (SQLite) with load / compare / delete."""
        tab = tk.Frame(notebook, bg=C["bg"])
        notebook.add(tab, text="  History  ")
        self.tab_history = tab

        ctrl = tk.Frame(tab, bg=C["surface"])
        ctrl.pack(fill="x", padx=4, pady=(4, 2))
        for text, cmd, fg in [
            ("⟳ Refresh", self._refresh_history, C["text2"]),
            ("💾 Save Current", self._save_current_to_history, C["green"]),
            ("📂 Load", self._load_history_run, C["accent"]),
            ("⇄ Diff vs Current", self._diff_history_vs_current, C["purple"]),
            ("⇄ Diff Selected", self._diff_history_selected, C["purple"]),
            ("✗ Delete", self._delete_history_run, C["red"]),
        ]:
            self._make_button(ctrl, text, cmd, fg=fg, pad=(8, 3)).pack(side="left", padx=3, pady=4)

        ttk.Checkbutton(
            ctrl,
            text="Auto-save each scan",
            variable=self.var_autosave,
            style="Bar.TCheckbutton",
        ).pack(side="right", padx=8)

        path_row = tk.Frame(tab, bg=C["bg"])
        path_row.pack(fill="x", padx=6, pady=(2, 4))
        tk.Label(path_row, text="Database:", bg=C["bg"], fg=C["text3"], font=FONT_MONO_SM).pack(
            side="left"
        )
        tk.Label(
            path_row, textvariable=self.var_db_path, bg=C["bg"], fg=C["text2"], font=FONT_MONO_SM
        ).pack(side="left", padx=6)
        self._make_button(
            path_row, "Change…", self._choose_db_path, fg=C["accent"], pad=(6, 1)
        ).pack(side="left", padx=4)

        pw = tk.PanedWindow(tab, orient="vertical", bg=C["border"], sashwidth=4, handlesize=0)
        pw.pack(fill="both", expand=True, padx=4, pady=(0, 4))

        top = tk.Frame(pw, bg=C["bg"])
        pw.add(top, minsize=120, height=240)
        cols = ("id", "time", "type", "hosts", "up", "open", "targets")
        labels = ("Run", "Timestamp", "Scan Type", "Hosts", "Up", "Open", "Targets")
        widths = (60, 170, 110, 60, 50, 60, 360)
        self.history_tree = ttk.Treeview(top, columns=cols, show="headings", selectmode="extended")
        for col, lbl, w in zip(cols, labels, widths):
            self.history_tree.heading(col, text=lbl)
            anchor = "center" if col in ("id", "hosts", "up", "open") else "w"
            self.history_tree.column(
                col, width=w, minwidth=40, anchor=anchor, stretch=col == "targets"
            )
        self.history_tree.tag_configure("even", background=C["row_even"])
        self.history_tree.tag_configure("odd", background=C["row_odd"])
        hvsb = ttk.Scrollbar(top, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=hvsb.set)
        hvsb.pack(side="right", fill="y")
        self.history_tree.pack(fill="both", expand=True)
        self.history_tree.bind("<Double-Button-1>", lambda e: self._load_history_run())

        bottom = tk.Frame(pw, bg=C["bg"])
        pw.add(bottom, minsize=100)
        self.diff_text = tk.Text(
            bottom,
            bg=C["bg"],
            fg=C["text"],
            font=FONT_MONO_SM,
            state="disabled",
            relief="flat",
            bd=0,
            wrap="none",
            highlightthickness=1,
            highlightbackground=C["border"],
            padx=12,
            pady=8,
        )
        dvsb = ttk.Scrollbar(bottom, orient="vertical", command=self.diff_text.yview)
        self.diff_text.configure(yscrollcommand=dvsb.set)
        dvsb.pack(side="right", fill="y")
        self.diff_text.pack(fill="both", expand=True)
        for tag, fg_c in [
            ("header", C["accent"]),
            ("new", C["green"]),
            ("closed", C["red"]),
            ("changed", C["yellow"]),
            ("info", C["purple"]),
            ("muted", C["text3"]),
        ]:
            self.diff_text.tag_configure(tag, foreground=fg_c)
        self._write_diff("Select a run and choose Diff to see what changed.\n", clear=True)

    # ─────────────────────────── HISTORY ───────────────────────────

    def _choose_db_path(self):
        path = filedialog.asksaveasfilename(
            title="Scan history database",
            defaultextension=".db",
            initialfile=os.path.basename(self.var_db_path.get()),
            filetypes=[("SQLite database", "*.db"), ("All Files", "*.*")],
            confirmoverwrite=False,
        )
        if path:
            self.var_db_path.set(path)
            self._refresh_history()

    def _refresh_history(self):
        from core.db import get_timeline_summary

        tree = self.history_tree
        tree.delete(*tree.get_children())
        try:
            rows = get_timeline_summary(self.var_db_path.get(), limit=500)
        except Exception as e:
            self._toast(f"Could not read history: {e}", "error")
            return
        for i, r in enumerate(rows):
            targets = ", ".join(r["targets"][:6]) + (" …" if len(r["targets"]) > 6 else "")
            tree.insert(
                "",
                "end",
                iid=str(r["id"]),
                values=(
                    r["id"],
                    r["timestamp"][:19].replace("T", " "),
                    r["scan_type"],
                    r["hosts_scanned"],
                    r["hosts_up"],
                    r["total_open_ports"],
                    targets,
                ),
                tags=("even" if i % 2 == 0 else "odd",),
            )

    def _selected_run_ids(self) -> list[int]:
        return [int(i) for i in self.history_tree.selection()]

    def _save_current_to_history(self, quiet: bool = False):
        if not self.scan_results:
            if not quiet:
                self._toast("No scan results to save", "warn")
            return
        from core.db import save_scan_results

        try:
            run_id = save_scan_results(self.var_db_path.get(), self.scan_results)
        except Exception as e:
            self._toast(f"Saving to history failed: {e}", "error")
            return
        self._log(f"Scan saved to history as run #{run_id}", "info")
        if not quiet:
            self._toast(f"Saved as run #{run_id}", "ok")
        self._refresh_history()

    def _load_run(self, run_id: int):
        from core.db import fetch_run_by_id

        row = fetch_run_by_id(self.var_db_path.get(), run_id)
        if not row:
            self._toast(f"Run #{run_id} not found", "error")
            return None
        return row

    def _load_history_run(self):
        if self.is_scanning:
            self._toast("Stop the scan before loading a saved run", "warn")
            return
        ids = self._selected_run_ids()
        if not ids:
            self._toast("Select a run first", "warn")
            return
        row = self._load_run(ids[0])
        if not row:
            return
        results = [ScanResult.from_dict(d) for d in row[2]]
        self._clear_results_internal()
        for res in results:
            self._ingest_host_result(res)
        self._recount_stats()
        self._update_host_list()
        self._update_stats_tab()
        self._refresh_results_view()
        self._set_status(f"RUN #{row[0]}", C["purple"])
        self._set_current(row[1][:19].replace("T", " "))
        self._log(f"Loaded run #{row[0]} ({len(results)} host(s)) from history", "info")
        self._select_tab(self.notebook.tabs()[0])

    def _write_diff(self, text: str, tag=None, clear: bool = False):
        self.diff_text.configure(state="normal")
        if clear:
            self.diff_text.delete("1.0", "end")
        self.diff_text.insert("end", text, tag)
        self.diff_text.configure(state="disabled")

    def _show_diff(self, title: str, before, after):
        from core.compare import compare_scans, generate_diff_report

        report = generate_diff_report(compare_scans(before, after))
        self._write_diff(f"{title}\n\n", "info", clear=True)
        for line in report.splitlines():
            stripped = line.strip()
            if stripped.startswith("✚"):
                tag = "new"
            elif stripped.startswith("✗") or "Status: DOWN" in stripped:
                tag = "closed"
            elif stripped.startswith(("⟳", "ⓘ")):
                tag = "changed"
            elif stripped.startswith(("Host:", "Changes:", "SCAN")):
                tag = "header"
            elif stripped.startswith(("=", "✓")):
                tag = "muted"
            else:
                tag = None
            self._write_diff(line + "\n", tag)

    def _diff_history_vs_current(self):
        ids = self._selected_run_ids()
        if not ids or not self.scan_results:
            self._toast("Select a run and have current results to compare", "warn")
            return
        row = self._load_run(ids[0])
        if row:
            self._show_diff(f"Run #{row[0]}  →  current scan", row[2], self.scan_results)

    def _diff_history_selected(self):
        ids = sorted(self._selected_run_ids())
        if len(ids) != 2:
            self._toast("Select exactly two runs (Ctrl+click)", "warn")
            return
        old, new = self._load_run(ids[0]), self._load_run(ids[1])
        if old and new:
            self._show_diff(f"Run #{old[0]}  →  run #{new[0]}", old[2], new[2])

    def _delete_history_run(self):
        ids = self._selected_run_ids()
        if not ids:
            self._toast("Select run(s) to delete", "warn")
            return
        if not messagebox.askyesno(
            "Delete Runs", f"Permanently delete {len(ids)} run(s) from history?", icon="warning"
        ):
            return
        from core.db import delete_run

        for run_id in ids:
            delete_run(self.var_db_path.get(), run_id)
        self._refresh_history()
        self._toast(f"Deleted {len(ids)} run(s)", "ok")

    def _open_link_under_cursor(self, event):
        idx = self.vuln_text.index(f"@{event.x},{event.y}")
        rng = self.vuln_text.tag_prevrange("link", f"{idx}+1c")
        if rng:
            url = self.vuln_text.get(*rng).strip()
            if url.startswith("http"):
                webbrowser.open(url)

    def _vuln_write(self, text: str, tag=None, clear: bool = False):
        self.vuln_text.configure(state="normal")
        if clear:
            self.vuln_text.delete("1.0", "end")
        self.vuln_text.insert("end", text, tag)
        self.vuln_text.configure(state="disabled")
        self.vuln_text.see("end")

    def _set_vuln_busy(self, busy: bool, status: str = ""):
        self._vuln_busy = busy
        self.btn_cve.set_enabled(not busy)
        self.btn_geo.set_enabled(not busy)
        self.lbl_vuln_status.configure(text=status, fg=C["accent"] if busy else C["text3"])

    def _lookup_cves(self):
        """Look up CVEs for fingerprinted services on a background thread."""
        if self._vuln_busy:
            return
        if not self.scan_results:
            self._toast("Run a scan first to look up CVEs", "warn")
            return

        from core.cve_lookup import build_query

        services: dict = {}
        for result in self.scan_results:
            for port in result.ports:
                if port.state == PortState.OPEN and port.service:
                    services.setdefault((port.service, port.version), []).append(
                        f"{result.target}:{port.port}/{port.protocol}"
                    )
        if not services:
            self._toast("No open services to check", "warn")
            return

        self._select_tab(self.tab_vuln)
        self._vuln_write("CVE VULNERABILITY LOOKUP\n", "header", clear=True)
        self._vuln_write("═" * 64 + "\n", "header")
        skipped = [(k, v) for k, v in services.items() if not build_query(*k)]
        todo = [(k, v) for k, v in services.items() if build_query(*k)]
        for (svc, _ver), where in skipped:
            self._vuln_write(
                f"  · {svc:<16} skipped — no version fingerprint ({', '.join(where[:3])})\n",
                "muted",
            )
        if not todo:
            self._vuln_write("\n  Nothing with a version string to look up.\n", "muted")
            return
        self._set_vuln_busy(True, f"Querying NVD… 0/{len(todo)}")

        def worker():
            from core.cve_lookup import lookup_service_cves

            total = 0
            for i, ((svc, ver), where) in enumerate(todo, 1):
                cves = lookup_service_cves(svc, ver, limit=5)
                total += len(cves)
                self._ui_queue.put(("vuln_cves", svc, ver, where, cves, i, len(todo)))
            self._ui_queue.put(("vuln_done", f"{total} CVE(s) found", total))

        threading.Thread(target=worker, daemon=True).start()

    def _render_cves(self, svc, ver, where, cves, i, n):
        from core.cve_lookup import severity_rank

        self.lbl_vuln_status.configure(text=f"Querying NVD… {i}/{n}")
        self._vuln_write(f"\n{svc} {ver}", "header")
        self._vuln_write(f"   {', '.join(where[:4])}{' …' if len(where) > 4 else ''}\n", "muted")
        if not cves:
            self._vuln_write("  ✓ No known CVEs\n", "cve_low")
            return
        tags = {4: "cve_critical", 3: "cve_high", 2: "cve_medium", 1: "cve_low"}
        for cve in cves:
            tag = tags.get(severity_rank(cve.severity), "muted")
            self._vuln_write(f"  ● {cve.cve_id:<16} {cve.severity:<8} {cve.score:>4}  ", tag)
            self._vuln_write(f"{cve.description}\n", None)
            self._vuln_write("      ")
            self._vuln_write(cve.url, "link")
            self._vuln_write("\n")

    def _lookup_geolocation(self):
        """Lookup geolocation + RDAP/WHOIS for discovered public hosts (background)."""
        if self._vuln_busy:
            return
        if not self.scan_results:
            self._toast("Run a scan first to look up geolocation", "warn")
            return

        from core.geoloc import is_public_ip

        hosts = []
        seen = set()
        for r in self.scan_results:
            if r.host_up and r.ip_address not in seen:
                seen.add(r.ip_address)
                hosts.append(r)

        self._select_tab(self.tab_vuln)
        self._vuln_write("GEOLOCATION & WHOIS\n", "header", clear=True)
        self._vuln_write("═" * 64 + "\n\n", "header")
        public = [r for r in hosts if is_public_ip(r.ip_address)]
        for r in hosts:
            if r not in public:
                self._vuln_write(
                    f"  · {r.target} ({r.ip_address}) — private/reserved address, skipped\n",
                    "muted",
                )
        if not public:
            return
        self._set_vuln_busy(True, f"Looking up… 0/{len(public)}")

        def worker():
            from core.geoloc import (
                format_geolocation_report,
                lookup_geolocation,
                lookup_whois_simple,
            )

            for i, r in enumerate(public, 1):
                geo = lookup_geolocation(r.ip_address)
                whois = lookup_whois_simple(r.ip_address) if geo else {}
                text = (
                    format_geolocation_report(geo, whois)
                    if geo
                    else f"  ✗ {r.target} ({r.ip_address}) — no info"
                )
                self._ui_queue.put(("vuln_text", text + "\n\n", "geo_info" if geo else "muted"))
                self._ui_queue.put(("vuln_status", f"Looking up… {i}/{len(public)}"))
            self._ui_queue.put(("vuln_done", f"{len(public)} host(s) located", -1))

        threading.Thread(target=worker, daemon=True).start()

    def _build_statusbar(self):
        bar = tk.Frame(self, bg=C["header_bg"], height=24)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        tk.Frame(self, bg=C["border"], height=1).pack(fill="x", side="bottom")

        self.lbl_statusbar = tk.Label(
            bar,
            text="Ready — Load a target and click Start Scan",
            bg=C["header_bg"],
            fg=C["text3"],
            font=FONT_MONO_SM,
            anchor="w",
        )
        self.lbl_statusbar.pack(side="left", padx=12)

        tk.Label(
            bar,
            text=f"◈ NexScan v{self.VERSION}",
            bg=C["header_bg"],
            fg=C["text3"],
            font=FONT_MONO_SM,
        ).pack(side="right", padx=12)

        # Right side: local host + privilege info
        self.lbl_hostname = tk.Label(
            bar, text=self._local_host_info(), bg=C["header_bg"], fg=C["text3"], font=FONT_MONO_SM
        )
        self.lbl_hostname.pack(side="right", padx=12)
        tk.Label(
            bar,
            text="● raw sockets" if self._raw_ok else "○ unprivileged",
            bg=C["header_bg"],
            fg=C["green"] if self._raw_ok else C["text3"],
            font=FONT_MONO_SM,
        ).pack(side="right", padx=4)

    @staticmethod
    def _local_host_info() -> str:
        name = socket.gethostname()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("192.0.2.1", 9))  # no packet is sent for UDP connect
                ip = s.getsockname()[0]
        except OSError:
            ip = "127.0.0.1"
        return f"local: {name} ({ip})"

    # ─────────────────────────── HELPERS ───────────────────────────

    def _make_button(self, parent, text, command, fg=None, bg=None, hover_bg=None, pad=(12, 6)):
        return _FlatButton(
            parent,
            text,
            command,
            fg=fg or C["text"],
            bg=bg or C["btn_bg"],
            hover_bg=hover_bg or C["btn_hover"],
            pad=pad,
        )

    def _section(self, parent, title):
        outer = tk.Frame(parent, bg=C["surface"])
        outer.pack(fill="x", padx=4, pady=3)

        # Section header
        hdr = tk.Frame(outer, bg=C["accent_dim"])
        hdr.pack(fill="x")
        tk.Frame(hdr, bg=C["accent"], width=3).pack(side="left", fill="y")
        tk.Label(
            hdr,
            text=f" {title}",
            bg=C["accent_dim"],
            fg=C["accent"],
            font=FONT_MONO_SM,
            anchor="w",
            pady=3,
        ).pack(fill="x", side="left")

        # Content area
        content = tk.Frame(
            outer, bg=C["surface2"], highlightthickness=1, highlightbackground=C["border"]
        )
        content.pack(fill="x", pady=1)
        tk.Frame(content, bg=C["surface2"], height=4).pack(fill="x")
        return content

    _LOG_MAX_LINES = 5000

    def _log_visible(self, tag: str) -> bool:
        level = self.var_log_level.get() if hasattr(self, "var_log_level") else "All"
        if level == "Open":
            return tag in ("open", "banner", "ssl", "host")
        if level == "Error":
            return tag == "error"
        return True

    def _log(self, msg: str, tag: str = "info"):
        """Append to the live log. Safe to call from any thread."""
        if threading.current_thread() is not threading.main_thread():
            self._ui_queue.put(("log", msg, tag))
            return
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        if not hasattr(self, "_log_entries"):
            from collections import deque

            self._log_entries = deque(maxlen=self._LOG_MAX_LINES)
        self._log_entries.append((ts, msg, tag))
        if self._log_visible(tag):
            self._insert_log_line(ts, msg, tag)

    def _insert_log_line(self, ts: str, msg: str, tag: str):
        self.txt_log.configure(state="normal")
        self.txt_log.insert("end", f"[{ts}] ", "timestamp")
        self.txt_log.insert("end", f"{msg}\n", tag)
        lines = int(self.txt_log.index("end-1c").split(".")[0])
        if lines > self._LOG_MAX_LINES:
            self.txt_log.delete("1.0", f"{lines - self._LOG_MAX_LINES}.0")
        if self.var_autoscroll.get():
            self.txt_log.see("end")
        self.txt_log.configure(state="disabled")

    def _rerender_log(self):
        self.txt_log.configure(state="normal")
        self.txt_log.delete("1.0", "end")
        self.txt_log.configure(state="disabled")
        for ts, msg, tag in getattr(self, "_log_entries", []):
            if self._log_visible(tag):
                self._insert_log_line(ts, msg, tag)

    def _set_status(self, text: str, color: str = None):
        color = color or C["text2"]
        self.lbl_status.configure(text=text, fg=color)
        self.status_strip.configure(bg=color)
        self.lbl_statusbar.configure(text=text)

    def _set_current(self, text: str):
        self.lbl_current.configure(text=text)

    def _toast(self, message: str, kind: str = "info", ms: int = 3200):
        """Non-blocking notification in the bottom-right corner."""
        colors = {
            "ok": (C["green"], C["green_dim"]),
            "warn": (C["yellow"], C["yellow_dim"]),
            "error": (C["red"], C["red_dim"]),
            "info": (C["accent"], C["accent_dim"]),
        }
        fg, bg = colors.get(kind, colors["info"])
        icon = {"ok": "✓", "warn": "!", "error": "✗"}.get(kind, "◈")

        old = getattr(self, "_toast_widget", None)
        if old is not None:
            old.destroy()
        toast = tk.Frame(self, bg=fg, padx=1, pady=1)
        tk.Label(
            toast,
            text=f"  {icon}  {message}  ",
            bg=bg,
            fg=fg,
            font=FONT_MONO_SM,
            pady=8,
            padx=6,
        ).pack()
        toast.place(relx=1.0, rely=1.0, x=-18, y=-36, anchor="se")
        toast.lift()
        toast.bind("<Button-1>", lambda e: toast.destroy())
        self._toast_widget = toast
        self.after(ms, lambda: toast.winfo_exists() and toast.destroy())

    # ─────────────────────────── SCAN CONTROL ───────────────────────────

    _SCAN_TYPE_MAP = {
        "TCP Connect": ScanType.TCP_CONNECT,
        "UDP": ScanType.UDP,
        "SYN Stealth*": ScanType.SYN_STEALTH,
        "ACK*": ScanType.ACK,
        "FIN*": ScanType.FIN,
        "XMAS*": ScanType.XMAS,
        "NULL*": ScanType.NULL,
        "Window*": ScanType.WINDOW,
    }

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

        stype = self._SCAN_TYPE_MAP.get(self.var_scan_type.get(), ScanType.TCP_CONNECT)
        if stype in RAW_SCAN_TYPES and not self._raw_ok:
            raise ValueError(self._raw_reason or "Raw scans are not available.")

        try:
            threads = max(1, min(1000, int(self.var_threads.get())))
            return ScanConfig(
                targets=targets,
                ports=ports,
                scan_type=stype,
                threads=threads,
                timeout=max(0.05, float(self.var_timeout.get())),
                connect_timeout=max(0.05, float(self.var_connect_timeout.get())),
                grab_banners=self.var_banner_grab.get(),
                detect_service=self.var_service_detect.get(),
                detect_os=self.var_os_detect.get(),
                ssl_probe=self.var_ssl_probe.get(),
                rate_limit=max(0.0, float(self.var_rate_limit.get())) / 1000.0,
                retry_count=max(1, int(self.var_retry.get())),
                jitter=max(0.0, float(self.var_jitter.get())),
                max_banner_wait=max(0.1, float(self.var_max_banner.get())),
                host_discovery=self.var_host_discovery.get(),
                udp_payload_probes=self.var_udp_probes.get(),
                reverse_dns=self.var_quick_resolve.get(),
            )
        except (tk.TclError, ValueError) as e:
            raise ValueError(f"Invalid numeric setting: {e}") from e

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
        self._paused_total = 0.0
        self._pause_started = None
        self._update_controls()

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
            self._ui_queue.put(("scan_complete", results))
        except Exception as e:
            self._ui_queue.put(("scan_error", str(e)))

    def _toggle_pause(self):
        if not self.is_scanning:
            return
        if self.is_paused:
            self.scanner.resume()
            self.is_paused = False
            if self._pause_started:
                self._paused_total += time.time() - self._pause_started
                self._pause_started = None
            self._set_status("SCANNING", C["green"])
            self._log("Scan resumed.", "info")
        else:
            self.scanner.pause()
            self.is_paused = True
            self._pause_started = time.time()
            self._set_status("PAUSED", C["yellow"])
            self._log("Scan paused.", "info")
        self._update_controls()

    def _stop_scan(self):
        if not self.is_scanning:
            return
        # Ask for confirmation
        ok = messagebox.askyesno(
            "Cancel Scan", "Are you sure you want to cancel the scan?", icon="warning"
        )
        if ok and self.scanner:
            self.scanner.stop()
            self.is_paused = False
            self._set_status("STOPPING...", C["red"])
            self._log("Stop requested...", "error")
            self._update_controls()

    def _active_elapsed(self) -> float:
        """Elapsed scan time excluding time spent paused."""
        if not self.scan_start_time:
            return 0.0
        paused = self._paused_total
        if self._pause_started:
            paused += time.time() - self._pause_started
        return max(0.0, time.time() - self.scan_start_time - paused)

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
        """Process UI queue messages (called from main thread).

        Progress updates arrive once per probed port; only the latest one per
        poll is rendered, and work per tick is time-boxed to keep the UI fluid.
        """
        deadline = time.perf_counter() + 0.04
        last_progress = None
        try:
            while time.perf_counter() < deadline:
                msg = self._ui_queue.get_nowait()
                if msg[0] == "progress":
                    last_progress = msg
                else:
                    self._handle_queue_msg(msg)
        except queue.Empty:
            pass
        if last_progress is not None:
            self._handle_queue_msg(last_progress)
        self.after(30, self._poll_queue)

    def _handle_queue_msg(self, msg):
        kind = msg[0]

        if kind == "port_found":
            _, target, pr = msg
            self._store_row(target, pr)
            counts = self._live_counts.setdefault(target, {"open": 0, "filtered": 0})
            if pr.state == PortState.OPEN:
                counts["open"] += 1
            elif pr.state in (PortState.FILTERED, PortState.OPEN_FILTERED):
                counts["filtered"] += 1
            self._recount_stats()

            log_msg = (
                f"[{target}:{pr.port}/{pr.protocol}] {pr.state.value:<15} "
                f"{pr.service:<18} {pr.version[:30]}"
            )
            if pr.state in (PortState.OPEN, PortState.OPEN_FILTERED):
                self._log(log_msg, "open" if pr.state == PortState.OPEN else "filtered")
            if pr.banner:
                self._log(f"  ↳ Banner: {pr.banner.splitlines()[0][:60]}", "banner")
            if pr.ssl_info and pr.ssl_info.get("version"):
                cn = pr.ssl_info.get("common_name", "")
                note = "  ⚠ EXPIRED" if pr.ssl_info.get("expired") else ""
                self._log(f"  ↳ SSL: {pr.ssl_info['version']}  CN={cn}{note}", "ssl")

        elif kind == "progress":
            _, done, total, target, hdone, htotal = msg
            pct = done / total * 100 if total else 0
            self.progress["value"] = pct
            self.lbl_progress.configure(text=f"{int(pct)}%")
            self.stat_ports_done.set(done)
            self._set_current(f"{target} [{hdone}/{htotal}]")
            self.title(f"NexScan — {int(pct)}% scanning…")

            # ETA / throughput (paused time excluded)
            elapsed = self._active_elapsed()
            if done > 0 and total > 0 and self.is_scanning and elapsed > 0:
                rate = done / elapsed
                remaining = (total - done) / rate if rate > 0 else 0
                self.stat_eta.set(self._fmt_duration(remaining))
                self.lbl_rate.configure(text=f"{rate:,.0f} p/s")
            else:
                self.stat_eta.set("—")

        elif kind == "host_complete":
            _, result = msg
            self._ingest_host_result(result)
            status = "UP" if result.host_up else "DOWN"
            line = (
                f"Host {result.target} ({result.ip_address}) — {status}  "
                f"Open:{result.open_count} Filtered:{result.filtered_count}  "
                f"Duration:{result.scan_duration:.2f}s"
            )
            if result.extra.get("error"):
                line += f"  ({result.extra['error']})"
            self._log(line, "host" if result.host_up else "closed")
            if result.os_guess and result.os_guess != "Unknown":
                self._log(
                    f"  ↳ OS Guess: {result.os_guess} ({result.os_confidence}% confidence)", "info"
                )
            self._recount_stats()
            self._update_host_list()
            self._schedule_stats_refresh()

        elif kind == "scan_complete":
            _, results = msg
            self.scan_results = list(results)
            stopped = self.scanner.is_stopped() if self.scanner else False
            self.is_scanning = False
            self.is_paused = False
            self._update_controls()
            self.title(f"NexScan v{self.VERSION} — Advanced Port Scanner")
            self._set_status(
                "STOPPED" if stopped else "COMPLETE", C["red"] if stopped else C["accent"]
            )
            elapsed = self._active_elapsed()
            self._log(
                f"Scan {'stopped' if stopped else 'complete'} in {elapsed:.1f}s  "
                f"Open:{self.stat_open.get()}  "
                f"Filtered:{self.stat_filtered.get()}  "
                f"Hosts up:{self.stat_hosts_up.get()}",
                "info",
            )
            if not stopped:
                self.progress["value"] = 100
                self.lbl_progress.configure(text="100%")
            self.stat_eta.set("—")
            self._recount_stats()
            self._update_host_list()
            self._update_stats_tab()
            self._refresh_results_view()  # apply sort order to rows streamed live
            if self.var_autosave.get():
                self._save_current_to_history(quiet=True)
            self._toast(
                f"Scan {'stopped' if stopped else 'complete'} — "
                f"{self.stat_open.get()} open port(s) on {self.stat_hosts_up.get()} host(s)",
                "warn" if stopped else "ok",
            )
            self.bell()

        elif kind == "scan_error":
            _, err = msg
            self.is_scanning = False
            self.is_paused = False
            self._update_controls()
            self.title(f"NexScan v{self.VERSION} — Advanced Port Scanner")
            self._set_status("ERROR", C["red"])
            self._log(f"Scan error: {err}", "error")
            messagebox.showerror("Scan Error", str(err))

        elif kind == "log":
            _, text, tag = msg
            self._log(text, tag)

        elif kind == "vuln_cves":
            self._render_cves(*msg[1:])

        elif kind == "vuln_text":
            _, text, tag = msg
            self._vuln_write(text, tag)

        elif kind == "vuln_status":
            self.lbl_vuln_status.configure(text=msg[1])

        elif kind == "vuln_done":
            _, summary, count = msg
            self._set_vuln_busy(False, summary)
            if count >= 0:
                self._vuln_write(f"\n{summary}\n", "header")
            self._toast(summary, "warn" if count > 0 else "ok")

    @staticmethod
    def _fmt_duration(seconds: float) -> str:
        seconds = int(seconds)
        h, rem = divmod(seconds, 3600)
        m, s = divmod(rem, 60)
        if h:
            return f"{h}h {m:02d}m"
        return f"{m}m {s:02d}s" if m else f"{s}s"

    # ── live result store ──

    @staticmethod
    def _row_key(target: str, pr: PortResult) -> str:
        return f"{target}|{pr.protocol}|{pr.port}"

    def _ingest_host_result(self, result: ScanResult):
        """Record a finished host: keep it in scan_results and store all its rows."""
        self.scan_results = [r for r in self.scan_results if r.target != result.target]
        self.scan_results.append(result)
        self._live_counts[result.target] = {
            "open": result.open_count,
            "filtered": result.filtered_count,
            "up": 1 if result.host_up else 0,
        }
        for pr in result.ports:
            self._store_row(result.target, pr)

    def _store_row(self, target: str, pr: PortResult):
        key = self._row_key(target, pr)
        is_new = key not in self._rows
        self._rows[key] = (target, pr)
        if is_new:
            self._add_result_row(target, pr)

    def _recount_stats(self):
        counts = self._live_counts.values()
        self.stat_open.set(sum(c.get("open", 0) for c in counts))
        self.stat_filtered.set(sum(c.get("filtered", 0) for c in counts))
        self.stat_hosts_up.set(sum(c.get("up", 0) for c in counts))

    def _schedule_stats_refresh(self):
        """Statistics are rebuilt at most twice a second while hosts complete."""
        if getattr(self, "_stats_job", None):
            return

        def run():
            self._stats_job = None
            self._update_stats_tab()

        self._stats_job = self.after(500, run)

    def _state_tag(self, pr: PortResult):
        """Tree tag for a port, or None if hidden by the show-filtered/closed toggles."""
        if pr.state == PortState.OPEN:
            if pr.ssl_info and pr.ssl_info.get("expired"):
                return "warn"
            return "open"
        if pr.state in (PortState.FILTERED, PortState.OPEN_FILTERED):
            return "filtered" if self.var_show_filtered.get() else None
        return "closed" if self.var_show_closed.get() else None

    def _compile_filter(self):
        """Return a predicate for the filter box (None = no filter)."""
        ftext = self.var_filter_text.get().strip().lower()
        if not ftext:
            self.entry_filter.configure(highlightbackground=C["border2"])
            return None
        if self.var_filter_regex.get():
            try:
                rx = re.compile(ftext, re.IGNORECASE)
            except re.error:
                self.entry_filter.configure(highlightbackground=C["red"])
                return lambda row: True
            self.entry_filter.configure(highlightbackground=C["accent2"])
            return lambda row: bool(rx.search(row))
        self.entry_filter.configure(highlightbackground=C["accent2"])
        terms = ftext.split()
        return lambda row: all(t in row for t in terms)

    @staticmethod
    def _row_values(target: str, pr: PortResult) -> tuple:
        banner_short = pr.banner.splitlines()[0][:80] if pr.banner else ""
        return (
            target,
            pr.port,
            pr.protocol.upper(),
            pr.state.value,
            pr.service,
            pr.version,
            f"{pr.response_time * 1000:.1f}",
            banner_short,
        )

    def _row_passes(self, target: str, pr: PortResult, predicate) -> bool:
        host_filter = self.var_host_filter.get()
        if host_filter != "All" and target != host_filter:
            return False
        if predicate is None:
            return True
        values = self._row_values(target, pr)
        return predicate(" ".join(str(v) for v in values).lower())

    def _add_result_row(self, target: str, pr: PortResult):
        """Insert one row live (if it passes the current filters)."""
        tag = self._state_tag(pr)
        if tag is None or not self._row_passes(target, pr, self._compile_filter()):
            return
        iid = self._row_key(target, pr)
        if self.tree.exists(iid):
            return
        stripe = "even" if self._row_counter % 2 == 0 else "odd"
        self._row_counter += 1
        self.tree.insert(
            "", "end", iid=iid, values=self._row_values(target, pr), tags=(tag, stripe)
        )
        self._update_result_count()

    def _update_result_count(self):
        n = len(self.tree.get_children())
        self.lbl_result_count.configure(text=f"{n:,} result{'s' if n != 1 else ''}")
        if n:
            self.lbl_empty.place_forget()
        else:
            self.lbl_empty.place(relx=0.5, rely=0.45, anchor="center")

    def _update_timer(self):
        if not self.is_scanning:
            return
        if not self.is_paused:
            elapsed = int(self._active_elapsed())
            h, m, s = elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60
            self.lbl_timer.configure(text=f"{h:02d}:{m:02d}:{s:02d}", fg=C["accent"])
            self.lbl_timer_icon.configure(fg=C["accent"])
        self.after(1000, self._update_timer)

    def _update_host_list(self):
        hosts = ["All"] + [r.target for r in self.scan_results]
        self.cb_host_filter["values"] = hosts

        self.host_listbox.delete(0, "end")
        for i, r in enumerate(self.scan_results):
            status = "▲" if r.host_up else "▼"
            self.host_listbox.insert("end", f"{status} {r.target}  [{r.open_count} open]")
            color = (
                C["green"]
                if r.host_up and r.open_count
                else (C["text"] if r.host_up else C["text3"])
            )
            self.host_listbox.itemconfigure(i, foreground=color)

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
        w("◈ HOST REPORT\n", "header")
        w(sep, "sep")

        w("  Target       : ", "key")
        w(f"{result.target}\n", "value")
        w("  IP Address   : ", "key")
        w(f"{result.ip_address}\n", "value")
        if result.hostname and result.hostname != result.target:
            w("  Hostname     : ", "key")
            w(f"{result.hostname}\n", "value")
        w("  Status       : ", "key")
        if result.host_up:
            w("UP\n", "open")
        else:
            w("DOWN\n", "closed")
        if result.ttl:
            w("  TTL          : ", "key")
            w(f"{result.ttl}\n", "value")
        if result.os_guess:
            w("  OS Guess     : ", "key")
            w(f"{result.os_guess} ({result.os_confidence}% confidence)\n", "value")

        w("  Scan Type    : ", "key")
        w(f"{result.scan_type}\n", "value")
        w("  Duration     : ", "key")
        w(f"{result.scan_duration:.3f}s\n", "value")
        w("  Timestamp    : ", "key")
        w(f"{result.timestamp}\n", "value")
        w("  Open / Filt / Closed : ", "key")
        w(f"{result.open_count}", "open")
        w(" / ", "key")
        w(f"{result.filtered_count}", "filtered")
        w(" / ", "key")
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
                w(f"{p.response_time * 1000:>7.1f}ms\n", "value")
                if p.banner:
                    for line in p.banner.splitlines()[:4]:
                        w(f"          ↳ {line[:65]}\n", "banner_text")
                if p.ssl_info:
                    ssl = p.ssl_info
                    w(
                        f"          ↳ SSL: {ssl.get('version', '')}  Cipher: {ssl.get('cipher', '')} ({ssl.get('cipher_bits', 0)} bits)\n",
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
                ports_str += f" ... (+{len(filt_ports) - 50} more)"
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

        w("  Hosts Scanned     : ", "key")
        w(f"{len(self.scan_results)}\n", "val")
        w("  Hosts Up          : ", "key")
        w(f"{hosts_up}\n", "val")
        w("  Total Ports Tested: ", "key")
        w(f"{total_scanned:,}\n", "val")
        w("  Open Ports Found  : ", "key")
        w(f"{len(all_open)}\n", "val")
        w("  Filtered Ports    : ", "key")
        w(f"{self.stat_filtered.get()}\n", "val")

        if self.scan_results:
            total_dur = sum(r.scan_duration for r in self.scan_results)
            w("  Total Scan Time   : ", "key")
            w(f"{total_dur:.2f}s\n", "val")
            if total_scanned > 0:
                rate = total_scanned / max(total_dur, 0.01)
                w("  Avg Port Rate     : ", "key")
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
        """Debounced: typing in the filter box rebuilds the view once typing pauses."""
        if self._refresh_job is not None:
            self.after_cancel(self._refresh_job)
        self._refresh_job = self.after(120, self._refresh_results_view)

    _SORT_KEYS = {
        "host": lambda t, p: t,
        "port": lambda t, p: p.port,
        "proto": lambda t, p: p.protocol,
        "state": lambda t, p: p.state.value,
        "service": lambda t, p: p.service.lower(),
        "version": lambda t, p: p.version.lower(),
        "rtt": lambda t, p: p.response_time,
        "banner": lambda t, p: p.banner.lower(),
    }

    def _on_sort_preset(self, _event=None):
        self._header_sort = None
        self._refresh_results_view()

    def _refresh_results_view(self):
        """Rebuild the treeview from the live row store with current filters/sort."""
        self._refresh_job = None
        self.tree.delete(*self.tree.get_children())
        predicate = self._compile_filter()

        all_rows = []
        for target, p in self._rows.values():
            tag = self._state_tag(p)
            if tag is None or not self._row_passes(target, p, predicate):
                continue
            all_rows.append((target, p, tag))

        # Sort: heading click wins over the preset combobox
        if self._header_sort:
            col, desc = self._header_sort
            key = self._SORT_KEYS.get(col, self._SORT_KEYS["port"])
            all_rows.sort(key=lambda x: (key(x[0], x[1]), x[1].port), reverse=desc)
        else:
            sort_val = self.var_sort.get()
            if sort_val == "Port ↓":
                all_rows.sort(key=lambda x: (-x[1].port, x[0]))
            elif sort_val == "Service":
                all_rows.sort(key=lambda x: (x[1].service, x[1].port))
            elif sort_val == "Response Time":
                all_rows.sort(key=lambda x: x[1].response_time)
            elif sort_val == "State":
                all_rows.sort(key=lambda x: (x[1].state.value, x[1].port))
            else:  # Port ↑
                all_rows.sort(key=lambda x: (x[1].port, x[0]))

        for i, (target, p, tag) in enumerate(all_rows):
            self.tree.insert(
                "",
                "end",
                iid=self._row_key(target, p),
                values=self._row_values(target, p),
                tags=(tag, "even" if i % 2 == 0 else "odd"),
            )
        self._row_counter = len(all_rows)
        self._update_heading_arrows()
        self._update_result_count()

    def _sort_tree(self, col: str):
        """Heading click: sort by column, clicking again toggles direction."""
        if self._header_sort and self._header_sort[0] == col:
            self._header_sort = (col, not self._header_sort[1])
        else:
            self._header_sort = (col, False)
        self._refresh_results_view()

    def _update_heading_arrows(self):
        for col, label in self._col_labels.items():
            text = label
            if self._header_sort and self._header_sort[0] == col:
                text += "  ▼" if self._header_sort[1] else "  ▲"
            self.tree.heading(col, text=text)

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
        for fmt, (_fn, _ext, label) in EXPORTERS.items():
            menu.add_command(label=f"Export as {label}", command=lambda f=fmt: self._export(f))

        menu.add_separator()
        menu.add_command(label="Copy visible results", command=self._copy_results)
        menu.add_command(label="Save to history", command=self._save_current_to_history)
        try:
            menu.tk_popup(self.winfo_pointerx(), self.winfo_pointery())
        finally:
            menu.grab_release()

    def _export(self, fmt: str):
        if not self.scan_results:
            self._toast("No scan results to export", "warn")
            return

        fn, ext, label = EXPORTERS[fmt]
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=[(f"{label} files", f"*{ext}"), ("All Files", "*.*")],
            initialfile=f"nexscan_{ts}{ext}",
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(fn(self.scan_results))
            self._log(f"Exported {label} report to: {path}", "info")
            self._toast(f"Saved {os.path.basename(path)}", "ok")
            if fmt == "html" and messagebox.askyesno(
                "Export Successful", f"Report saved to:\n{path}\n\nOpen it in your browser?"
            ):
                webbrowser.open(f"file://{os.path.abspath(path)}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def _copy_results(self):
        self._copy_rows(self.tree.get_children(), "visible")

    def _copy_selected_rows(self):
        sel = self.tree.selection()
        self._copy_rows(sel or self.tree.get_children(), "selected" if sel else "visible")

    def _copy_rows(self, iids, what: str):
        header = "\t".join(self._col_labels.values())
        rows = [header]
        for iid in iids:
            values = self.tree.item(iid, "values")
            rows.append("\t".join(str(v) for v in values))
        self.clipboard_clear()
        self.clipboard_append("\n".join(rows))
        self._log(f"Copied {len(rows) - 1} rows to clipboard.", "info")
        self._toast(f"Copied {len(rows) - 1} {what} row(s)", "ok")

    # ─────────────────────────── MISC ───────────────────────────

    def _apply_port_preset(self, event=None):
        preset = self.var_port_preset.get()
        ports = self.service_db.get_preset_ports(preset)
        if ports:
            self.txt_ports.delete("1.0", "end")
            self.txt_ports.insert("1.0", ",".join(str(p) for p in ports))
            self._log(f"Applied preset '{preset}': {len(ports)} ports", "info")
            self._count_ports()

    def _count_ports(self):
        port_text = self.txt_ports.get("1.0", "end").strip().replace("\n", ",")
        try:
            ports = parse_ports(port_text)
            text, color = f"Ports to scan: {len(ports):,}", C["green"] if ports else C["red"]
        except Exception:
            text, color = "Invalid port range", C["red"]
        self.lbl_port_count.configure(text=text, fg=color)
        self.lbl_port_summary.configure(
            text=f"{len(ports):,} port{'s' if len(ports) != 1 else ''} to scan" if ports else text,
            fg=C["text2"] if ports else color,
        )

    def _count_targets(self):
        targets = parse_targets(self.txt_targets.get("1.0", "end").strip())
        n = len(targets)
        if not n:
            self.lbl_target_summary.configure(text="No valid targets", fg=C["red"])
            return
        preview = ", ".join(targets[:3]) + (" …" if n > 3 else "")
        self.lbl_target_summary.configure(
            text=f"{n:,} host{'s' if n != 1 else ''}: {preview}", fg=C["text2"]
        )

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
        self._rows.clear()
        self._live_counts.clear()
        self._row_counter = 0
        self.tree.delete(*self.tree.get_children())
        self.host_listbox.delete(0, "end")
        self.cb_host_filter["values"] = ["All"]
        self.var_host_filter.set("All")
        self.stat_open.set(0)
        self.stat_filtered.set(0)
        self.stat_hosts_up.set(0)
        self.stat_ports_done.set(0)
        self.stat_eta.set("—")
        self.progress["value"] = 0
        self.lbl_progress.configure(text="0%")
        self.lbl_rate.configure(text="")
        self.lbl_timer.configure(text="00:00:00", fg=C["text3"])
        self.lbl_timer_icon.configure(fg=C["text3"])
        self._update_result_count()
        self._set_status("IDLE", C["text2"])
        self._set_current("—")

        for widget in (self.stats_text, self.detail_text):
            widget.configure(state="normal")
            widget.delete("1.0", "end")
            widget.configure(state="disabled")
        self._update_stats_tab()

    def _clear_log(self):
        self.txt_log.configure(state="normal")
        self.txt_log.delete("1.0", "end")
        self.txt_log.configure(state="disabled")

    _WEB_SERVICES = ("http", "https", "http-proxy", "http-alt", "https-alt", "www")

    def _tree_context_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        if iid not in self.tree.selection():
            self.tree.selection_set(iid)
        self.tree.focus(iid)
        entry = self._rows.get(iid)
        if not entry:
            return
        target, pr = entry
        host, port = target, pr.port

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

        menu.add_command(label="Show Port Detail", command=lambda: self._show_port_popup_for(iid))
        if pr.state == PortState.OPEN and (
            pr.service in self._WEB_SERVICES or pr.service.startswith("http")
        ):
            scheme = "https" if pr.ssl_info or "https" in pr.service else "http"
            url = f"{scheme}://{host}:{port}/"
            menu.add_command(label=f"Open {url}", command=lambda: webbrowser.open(url))
        menu.add_separator()
        menu.add_command(
            label=f"Copy {host}:{port}", command=lambda: self._copy_text(f"{host}:{port}")
        )
        menu.add_command(label=f"Copy host {host}", command=lambda: self._copy_text(host))
        if pr.banner:
            menu.add_command(label="Copy banner", command=lambda: self._copy_text(pr.banner))
        sel = len(self.tree.selection())
        menu.add_command(label=f"Copy {sel} selected row(s)", command=self._copy_selected_rows)
        menu.add_separator()
        menu.add_command(
            label=f"Filter by port {port}", command=lambda: self.var_filter_text.set(str(port))
        )
        menu.add_command(
            label=f"Filter by host {host}", command=lambda: self.var_filter_text.set(host)
        )
        if pr.service:
            menu.add_command(
                label=f"Filter by service {pr.service}",
                command=lambda: self.var_filter_text.set(pr.service),
            )
        menu.add_command(label="Clear filter", command=lambda: self.var_filter_text.set(""))

        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _copy_text(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text)
        self._toast("Copied to clipboard", "ok", ms=1500)

    def _show_port_detail(self, event):
        iid = self.tree.focus()
        if iid:
            self._show_port_popup_for(iid)

    def _show_port_popup_for(self, iid: str):
        entry = self._rows.get(iid)
        if not entry:
            return
        target, pr = entry
        result = next((r for r in self.scan_results if r.target == target), None)
        if result is None:  # host still being scanned
            result = ScanResult(target=target, ip_address=target)
        self._show_port_popup(result, pr)

    def _show_port_detail_by_values(self, values):
        host, port_str = values[0], values[1]
        proto = str(values[2]).lower() if len(values) > 2 else "tcp"
        self._show_port_popup_for(f"{host}|{proto}|{port_str}")

    def _show_port_popup(self, result: ScanResult, pr: PortResult):
        popup = tk.Toplevel(self)
        popup.title(f"Port Detail — {result.target}:{pr.port}")
        popup.configure(bg=C["bg"])
        popup.geometry("640x520")
        popup.resizable(True, True)
        popup.transient(self)
        popup.bind("<Escape>", lambda e: popup.destroy())

        # Button row first so it stays visible when the text is long
        btns = tk.Frame(popup, bg=C["bg"])
        btns.pack(side="bottom", fill="x", pady=8)
        self._make_button(btns, "  Close  ", popup.destroy).pack(side="right", padx=8)
        self._make_button(
            btns,
            "Copy JSON",
            lambda: self._copy_text(json.dumps(pr.to_dict(), indent=2)),
            fg=C["accent"],
        ).pack(side="right", padx=4)
        if pr.banner:
            self._make_button(
                btns, "Copy Banner", lambda: self._copy_text(pr.banner), fg=C["orange"]
            ).pack(side="right", padx=4)

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
            ("filtered", C["yellow"]),
            ("closed", C["text3"]),
            ("bad", C["red"]),
        ]:
            txt.tag_configure(tag, foreground=fg_c)
        txt.tag_configure("bold", font=(FONT_MONO[0], 10, "bold"))
        state_tag = {
            PortState.OPEN: "open",
            PortState.FILTERED: "filtered",
            PortState.OPEN_FILTERED: "filtered",
        }.get(pr.state, "closed")

        def w(t, tag=None):
            txt.insert("end", t, tag)

        w("PORT DETAIL\n", "head")
        w("─" * 50 + "\n", "key")
        w("Host       : ", "key")
        w(f"{result.target}\n", "val")
        w("IP         : ", "key")
        w(f"{result.ip_address}\n", "val")
        w("Port       : ", "key")
        w(f"{pr.port}/{pr.protocol.upper()}\n", "open")
        w("State      : ", "key")
        w(f"{pr.state.value}\n", state_tag)
        w("Service    : ", "key")
        w(f"{pr.service}\n", "val")
        w("Version    : ", "key")
        w(f"{pr.version}\n", "val")
        if pr.cpe:
            w("CPE        : ", "key")
            w(f"{pr.cpe}\n", "val")
        w("RTT        : ", "key")
        w(f"{pr.response_time * 1000:.2f}ms\n", "val")
        if pr.extra_info:
            w("Notes      : ", "key")
            w(f"{pr.extra_info}\n", "val")
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
            labels = [
                ("version", "Protocol"),
                ("cipher", "Cipher"),
                ("cipher_bits", "Key bits"),
                ("common_name", "Common name"),
                ("san", "Alt names"),
                ("issuer", "Issuer"),
                ("not_before", "Valid from"),
                ("not_after", "Valid until"),
                ("days_left", "Days left"),
                ("self_signed", "Self-signed"),
            ]
            for key, label in labels:
                if key not in ssl or ssl[key] in ("", None, []):
                    continue
                v = ssl[key]
                if isinstance(v, list):
                    v = ", ".join(v[:6]) + (" …" if len(v) > 6 else "")
                tag = "ssl"
                if key == "days_left" and isinstance(v, int) and v < 30:
                    tag = "bad"
                    v = f"{v}  ({'EXPIRED' if v < 0 else 'expires soon'})"
                if key == "self_signed":
                    v, tag = ("yes", "bad") if v else ("no", "ssl")
                if key == "version" and str(v) in ("SSLv3", "TLSv1", "TLSv1.1"):
                    tag = "bad"
                    v = f"{v}  (deprecated)"
                w(f"{label:<12}: ", "key")
                w(f"{v}\n", tag)

        txt.configure(state="disabled")

    def _show_about(self):
        popup = tk.Toplevel(self)
        popup.title("About NexScan")
        popup.configure(bg=C["bg"])
        popup.geometry("600x560")
        popup.resizable(False, True)
        popup.transient(self)
        popup.bind("<Escape>", lambda e: popup.destroy())

        btns = tk.Frame(popup, bg=C["bg"])
        btns.pack(side="bottom", fill="x", pady=10)
        self._make_button(btns, "  Close  ", popup.destroy).pack()

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
            highlightthickness=0,
        )
        txt.pack(fill="both", expand=True)

        for tag, fg_c, fnt in [
            ("h1", C["accent"], FONT_TITLE),
            ("h2", C["purple"], FONT_MONO_LG),
            ("key", C["text2"], FONT_MONO_SM),
            ("kbd", C["accent"], FONT_MONO_SM),
            ("val", C["text"], FONT_MONO_SM),
        ]:
            txt.tag_configure(tag, foreground=fg_c, font=fnt)
        txt.tag_configure("h2", spacing1=10, spacing3=4)

        txt.insert("end", "◈ NEXSCAN\n", "h1")
        txt.insert("end", f"v{self.VERSION} — Advanced Port Scanner\n", "val")

        txt.insert("end", "KEYBOARD SHORTCUTS\n", "h2")
        for keys, desc in [
            ("F5", "Start scan"),
            ("F6", "Pause / resume"),
            ("Escape", "Stop / cancel scan"),
            ("Ctrl+E", "Export results"),
            ("Ctrl+L", "Clear results"),
            ("Ctrl+F", "Focus filter box"),
            ("Ctrl+C", "Copy selected rows"),
            ("Ctrl+S / Ctrl+O", "Save / load profile"),
            ("Ctrl+H", "Scan history"),
        ]:
            txt.insert("end", f"  {keys:<18}", "kbd")
            txt.insert("end", f"{desc}\n", "key")

        txt.insert("end", "CAPABILITIES\n", "h2")
        features = [
            "TCP Connect, UDP and raw SYN / ACK / FIN / XMAS / NULL / Window scans",
            "Shared worker pool across hosts with parallel host discovery",
            "Protocol-aware banner grabbing & product/version fingerprinting",
            "TLS certificate inspection with expiry warnings",
            "Heuristic OS detection (TTL + port fingerprint)",
            "CIDR, IP ranges and multi-host scanning",
            "Live, filterable results with pause / resume and ETA",
            "Export: JSON, CSV, HTML, XML, Markdown, TXT",
            "Scan history with run-to-run diffs",
            "CVE lookup (NVD) and geolocation / RDAP WHOIS",
        ]
        for f in features:
            txt.insert("end", f"  ✓ {f}\n", "key")

        txt.insert("end", "⚠ LEGAL NOTICE\n", "h2")
        txt.insert(
            "end",
            "  Only scan systems you own or have explicit permission\n"
            "  to scan. Unauthorized port scanning may be illegal.\n",
            "key",
        )
        txt.configure(state="disabled")

    # ─────────────────────────── PROFILES & SETTINGS ───────────────────────────

    def _profile_vars(self) -> dict:
        """Settings captured in profiles and remembered between sessions."""
        return {
            "scan_type": self.var_scan_type,
            "threads": self.var_threads,
            "timeout": self.var_timeout,
            "connect_timeout": self.var_connect_timeout,
            "rate_limit_ms": self.var_rate_limit,
            "attempts": self.var_retry,
            "jitter_ms": self.var_jitter,
            "banner_wait": self.var_max_banner,
            "banner_grab": self.var_banner_grab,
            "service_detect": self.var_service_detect,
            "os_detect": self.var_os_detect,
            "ssl_probe": self.var_ssl_probe,
            "host_discovery": self.var_host_discovery,
            "udp_probes": self.var_udp_probes,
            "reverse_dns": self.var_quick_resolve,
            "show_filtered": self.var_show_filtered,
            "show_closed": self.var_show_closed,
            "port_preset": self.var_port_preset,
        }

    def _collect_profile(self) -> dict:
        profile = {
            "targets": self.txt_targets.get("1.0", "end").strip(),
            "ports": self.txt_ports.get("1.0", "end").strip(),
        }
        for key, var in self._profile_vars().items():
            try:
                profile[key] = var.get()
            except tk.TclError:
                pass
        return profile

    def _apply_profile(self, profile: dict):
        if "targets" in profile:
            self.txt_targets.delete("1.0", "end")
            self.txt_targets.insert("1.0", profile["targets"])
        if "ports" in profile:
            self.txt_ports.delete("1.0", "end")
            self.txt_ports.insert("1.0", profile["ports"])

        # Accept keys written by older versions
        legacy = {"retries": "attempts"}
        for old, new in legacy.items():
            if old in profile and new not in profile:
                profile[new] = max(1, int(profile[old]))

        for key, var in self._profile_vars().items():
            if key in profile:
                try:
                    var.set(profile[key])
                except (tk.TclError, ValueError, TypeError):
                    pass
        if self.var_scan_type.get() not in self._SCAN_TYPE_MAP:
            self.var_scan_type.set("TCP Connect")
        self._update_scan_type_hint()
        self._count_ports()
        self._count_targets()

    def _save_profile(self):
        """Save current scan configuration as a profile."""
        file = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("NexScan Profile", "*.json"), ("All Files", "*.*")],
            initialfile="nexscan_profile.json",
        )
        if not file:
            return
        try:
            with open(file, "w", encoding="utf-8") as f:
                json.dump(self._collect_profile(), f, indent=2)
            self._log(f"Profile saved to {file}", "info")
            self._toast(f"Profile saved: {os.path.basename(file)}", "ok")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save profile: {e}")

    def _load_profile(self):
        """Load a saved scan configuration profile."""
        file = filedialog.askopenfilename(
            filetypes=[("NexScan Profile", "*.json"), ("All Files", "*.*")]
        )
        if not file:
            return
        try:
            with open(file, "r", encoding="utf-8") as f:
                self._apply_profile(json.load(f))
            self._log(f"Profile loaded from {file}", "info")
            self._toast(f"Profile loaded: {os.path.basename(file)}", "ok")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load profile: {e}")

    def _load_settings(self):
        """Restore the last session's settings (silently ignores a missing/corrupt file)."""
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return
        self._apply_profile(data.get("profile", {}))
        if data.get("db_path"):
            self.var_db_path.set(data["db_path"])
        self.var_autosave.set(bool(data.get("autosave", False)))
        geometry = data.get("geometry")
        if isinstance(geometry, str) and re.match(r"^\d+x\d+[+-]-?\d+[+-]-?\d+$", geometry):
            self.geometry(geometry)

    def _save_settings(self):
        data = {
            "profile": self._collect_profile(),
            "db_path": self.var_db_path.get(),
            "autosave": self.var_autosave.get(),
            "geometry": self.geometry(),
        }
        try:
            os.makedirs(SETTINGS_DIR, exist_ok=True)
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except OSError:
            pass

    def _setup_bindings(self):
        self.bind("<F5>", lambda e: self._start_scan())
        self.bind("<F6>", lambda e: self._toggle_pause())
        self.bind("<Escape>", lambda e: self._stop_scan())
        self.bind("<Control-e>", lambda e: self._export_menu())
        self.bind("<Control-l>", lambda e: self._clear_results())
        self.bind("<Control-f>", lambda e: (self.entry_filter.focus(), "break")[1])
        self.bind("<Control-s>", lambda e: self._save_profile())
        self.bind("<Control-o>", lambda e: self._load_profile())
        self.bind("<Control-h>", lambda e: self._select_tab(self.tab_history))
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

    def _on_tab_changed(self, _event=None):
        try:
            current = self.notebook.nametowidget(self.notebook.select())
        except (KeyError, tk.TclError):
            return
        if current is self.tab_history:
            self._refresh_history()

    def _on_close(self):
        if self.is_scanning:
            ok = messagebox.askyesno(
                "Scan Running", "A scan is currently running. Stop it and exit?", icon="warning"
            )
            if not ok:
                return
            if self.scanner:
                self.scanner.stop()
        self._save_settings()
        self.destroy()


def main():
    app = NexScanApp()
    app.mainloop()


if __name__ == "__main__":
    main()
