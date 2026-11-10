"""
NexScan GUI — Main Application Window (PyQt6)
Dark terminal-inspired professional port scanner interface.

Module layout:
    gui/theme.py          palette, fonts, Qt stylesheet
    gui/widgets.py        themed building blocks (buttons, sections, text panes, toast)
    gui/results_model.py  table model behind the Results tab
    gui/dialogs.py        Port Detail and About popups
    gui/app.py            the main window (this file)
"""

from __future__ import annotations

import datetime
import json
import os
import queue
import re
import socket
import sys
import threading
import time
import webbrowser
from collections import defaultdict, deque
from typing import Any, Callable, Optional

# Add parent dir to path (before local imports so `python gui/app.py` works)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt6.QtCore import QByteArray, QPoint, Qt, QTimer  # noqa: E402
from PyQt6.QtGui import QCloseEvent, QColor, QCursor, QKeySequence, QShortcut  # noqa: E402
from PyQt6.QtWidgets import (  # noqa: E402
    QAbstractItemView,
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHeaderView,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QRadioButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QTableView,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QWidget,
)

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
from gui import dialogs  # noqa: E402
from gui.results_model import (  # noqa: E402
    COLUMN_LABELS,
    COLUMN_WIDTHS,
    COLUMNS,
    ResultsModel,
    row_key,
    row_values,
)
from gui.theme import C, Fonts, init_fonts, stylesheet  # noqa: E402
from gui.widgets import (  # noqa: E402
    FlatButton,
    Section,
    StatCard,
    TaggedText,
    Toast,
    frame,
    hbox,
    hline,
    label,
    set_fg,
    vbox,
    vsep,
)
from reports.exporter import EXPORTERS  # noqa: E402

# Where the GUI remembers its last-used settings between sessions
SETTINGS_DIR = os.path.join(
    os.environ.get("APPDATA")
    or os.environ.get("XDG_CONFIG_HOME")
    or os.path.expanduser("~/.config"),
    "nexscan",
)
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "settings.json")

SCAN_TYPES = [
    "TCP Connect",
    "UDP",
    "SYN Stealth*",
    "ACK*",
    "FIN*",
    "XMAS*",
    "NULL*",
    "Window*",
]


class NexScanApp(QMainWindow):
    VERSION = "3.0"

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"NexScan v{self.VERSION} — Advanced Port Scanner")
        self.resize(1400, 900)
        self.setMinimumSize(1100, 700)

        # Queue for thread-safe UI updates (created first: widgets may log during build)
        self._ui_queue: queue.Queue = queue.Queue()

        self._init_state()
        self._build_ui()
        self._setup_bindings()
        self._load_settings()
        self._count_ports()
        self._count_targets()

        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self._poll_queue)
        self._poll_timer.start(30)

    # ─────────────────────────── STATE ───────────────────────────

    def _init_state(self):
        self.service_db = ServiceDatabase()
        self.scanner: Optional[PortScanner] = None
        self.scan_thread: Optional[threading.Thread] = None
        self.scan_results: list[ScanResult] = []
        self.is_scanning = False
        self.is_paused = False
        self.scan_start_time: Optional[float] = None
        self._paused_total = 0.0
        self._pause_started: Optional[float] = None

        # Live row store: "target|proto|port" -> (target, PortResult). Filled while the
        # scan runs so filtering / sorting works before the scan completes.
        self._rows: dict = {}
        self._live_counts: dict = {}  # target -> {"open": n, "filtered": n, "up": n}
        self._header_sort: Optional[tuple[str, bool]] = None  # (column, descending)
        self._vuln_busy = False
        self._raw_ok, self._raw_reason = self._detect_raw_support()
        self._log_entries: deque = deque(maxlen=self._LOG_MAX_LINES)
        self._log_level = "All"
        self._db_path = os.path.abspath("nexscan_history.db")
        self._popups: list = []  # keep references so non-modal dialogs aren't GC'd

        # Debounce timers
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setSingleShot(True)
        self._refresh_timer.timeout.connect(self._refresh_results_view)
        self._stats_timer = QTimer(self)
        self._stats_timer.setSingleShot(True)
        self._stats_timer.timeout.connect(self._update_stats_tab)
        self._elapsed_timer = QTimer(self)
        self._elapsed_timer.timeout.connect(self._update_timer)

    @staticmethod
    def _detect_raw_support() -> tuple[bool, str]:
        try:
            from core.raw_scan import raw_scans_available

            return raw_scans_available()
        except Exception as e:
            return False, str(e)

    # ─────────────────────────── BUILD UI ───────────────────────────

    def _build_ui(self):
        central = frame("bg")
        self.setCentralWidget(central)
        root = vbox(central)

        root.addWidget(self._build_topbar())
        root.addWidget(self._build_main(), 1)
        root.addWidget(hline())
        root.addWidget(self._build_statusbar())

        self._toast_widget = Toast(self)
        self._update_controls()

    def _build_topbar(self) -> QWidget:
        bar = frame("topbar")
        bar.setFixedHeight(52)
        lay = hbox(bar, margins=(20, 10, 12, 10), spacing=8)

        lay.addWidget(label("◈ NEXSCAN", C["accent"], Fonts.title()))
        lay.addWidget(label(f"v{self.VERSION}", C["text3"], Fonts.mono_sm()))
        lay.addSpacing(12)
        lay.addWidget(vsep())
        lay.addSpacing(12)

        # Quick action buttons (kept so their state can follow the scan)
        self.btn_start = self._make_button(
            "▶  START SCAN", self._start_scan, fg=C["green"], pad=(14, 6)
        )
        self.btn_pause = self._make_button(
            "⏸  PAUSE", self._toggle_pause, fg=C["yellow"], pad=(14, 6)
        )
        self.btn_stop = self._make_button("■  STOP", self._stop_scan, fg=C["red"], pad=(14, 6))
        self.btn_clear = self._make_button(
            "⟳  CLEAR", self._clear_results, fg=C["text2"], pad=(14, 6)
        )
        for btn in (self.btn_start, self.btn_pause, self.btn_stop, self.btn_clear):
            lay.addWidget(btn)

        lay.addStretch(1)

        # Scan elapsed timer
        self.lbl_timer_icon = label("⏱", C["text3"], Fonts.mono_sm())
        lay.addWidget(self.lbl_timer_icon)
        self.lbl_timer = label("00:00:00", C["text3"], Fonts.mono_lg())
        lay.addWidget(self.lbl_timer)
        lay.addSpacing(16)

        for text, cmd, fg in [
            ("◷  HISTORY", lambda: self._select_tab(self.tab_history), C["accent"]),
            ("⬇  EXPORT", self._export_menu, C["purple"]),
            ("✦  ABOUT", self._show_about, C["text2"]),
        ]:
            lay.addWidget(self._make_button(text, cmd, fg=fg, pad=(14, 6)))
        return bar

    def _select_tab(self, tab: QWidget):
        try:
            self.notebook.setCurrentWidget(tab)
        except AttributeError:
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

    def _build_main(self) -> QWidget:
        main = QSplitter(Qt.Orientation.Horizontal)
        main.setHandleWidth(4)
        main.setChildrenCollapsible(False)

        left = self._build_left_panel()
        left.setMinimumWidth(320)
        main.addWidget(left)

        right = self._build_right_panel()
        right.setMinimumWidth(600)
        main.addWidget(right)

        main.setStretchFactor(0, 0)
        main.setStretchFactor(1, 1)
        main.setSizes([360, 1040])
        self.main_splitter = main
        return main

    # ── Left panel ──

    def _build_left_panel(self) -> QWidget:
        # Scrollable container: the settings column is taller than small screens
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content = QWidget()
        content.setObjectName("leftContent")
        content.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        content.setStyleSheet(f"QWidget#leftContent {{ background: {C['surface']}; }}")
        col = vbox(content, margins=(4, 3, 4, 3), spacing=6)
        scroll.setWidget(content)

        # ── Target input ──
        sec = Section("TARGET")
        self.txt_targets = self._make_input(lines=4)
        self.txt_targets.setPlainText("192.168.1.1")
        self.txt_targets.textChanged.connect(self._count_targets)
        sec.body.addWidget(self.txt_targets)
        self.lbl_target_summary = label(
            "IP, range (192.168.1.1-50), CIDR, or hostname — one per line or comma-separated",
            C["text3"],
            Fonts.tiny(),
            wrap=True,
        )
        sec.body.addWidget(self.lbl_target_summary)
        col.addWidget(sec)

        # ── Port config ──
        sec2 = Section("PORTS")
        prow = hbox(spacing=6)
        prow.addWidget(label("Preset:", C["text2"]))
        self.cb_preset = QComboBox()
        self.cb_preset.addItems(self.service_db.get_presets())
        self.cb_preset.setCurrentText("Top 100")
        self.cb_preset.setMinimumContentsLength(18)
        self.cb_preset.activated.connect(lambda _i: self._apply_port_preset())
        prow.addWidget(self.cb_preset)
        prow.addWidget(
            self._make_button("Apply", self._apply_port_preset, fg=C["accent"], pad=(8, 2))
        )
        prow.addStretch(1)
        sec2.body.addLayout(prow)

        sec2.body.addWidget(label("Port range / list:", C["text2"]))
        self.txt_ports = self._make_input(lines=3)
        self.txt_ports.setPlainText(
            "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,8080,8443,27017"
        )
        self.txt_ports.textChanged.connect(self._count_ports)
        sec2.body.addWidget(self.txt_ports)
        self.lbl_port_summary = label(
            "e.g.: 22,80,443  or  1-1024  or  80,443,8000-9000", C["text3"], Fonts.tiny()
        )
        sec2.body.addWidget(self.lbl_port_summary)
        col.addWidget(sec2)

        # ── Scan Type ──
        sec3 = Section("SCAN TYPE")
        grid = QGridLayout()
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(2)
        self.scan_type_group = QButtonGroup(self)
        self.scan_type_group.setExclusive(True)
        self._scan_type_buttons: dict[str, QRadioButton] = {}
        for i, st in enumerate(SCAN_TYPES):
            needs_root = st.endswith("*")
            usable = self._raw_ok or not needs_root
            rb = QRadioButton(st)
            rb.setEnabled(usable)
            rb.setCursor(
                Qt.CursorShape.PointingHandCursor if usable else Qt.CursorShape.ArrowCursor
            )
            if needs_root:
                rb.setStyleSheet(
                    f"QRadioButton {{ color: {C['text2']}; }}"
                    f" QRadioButton:hover {{ color: {C['white']}; }}"
                    f" QRadioButton:disabled {{ color: {C['disabled']}; }}"
                )
            self.scan_type_group.addButton(rb, i)
            self._scan_type_buttons[st] = rb
            grid.addWidget(rb, i // 2, i % 2)
        self._scan_type_buttons["TCP Connect"].setChecked(True)
        self.scan_type_group.buttonToggled.connect(
            lambda _b, checked: checked and self._update_scan_type_hint()
        )
        sec3.body.addLayout(grid)

        self.lbl_scan_hint = label("", C["text2"], Fonts.tiny(), wrap=True)
        sec3.body.addWidget(self.lbl_scan_hint)
        root_note = (
            "* Raw packet scans — privileges OK"
            if self._raw_ok
            else f"* Unavailable: {self._raw_reason}"
        )
        sec3.body.addWidget(
            label(root_note, C["green"] if self._raw_ok else C["text3"], Fonts.tiny(), wrap=True)
        )
        self._update_scan_type_hint()
        col.addWidget(sec3)

        # ── Settings tabs ──
        sec4 = Section("SETTINGS")
        nb = QTabWidget()
        nb.setObjectName("inner")
        nb.setDocumentMode(True)
        self._build_perf_tab(nb)
        self._build_output_tab(nb)
        self._build_advanced_tab(nb)
        sec4.body.addWidget(nb)
        col.addWidget(sec4)

        col.addStretch(1)
        return scroll

    def _make_input(self, lines: int) -> QPlainTextEdit:
        box = QPlainTextEdit()
        box.setObjectName("input")
        box.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        box.setFont(Fonts.mono_sm())
        box.setTabChangesFocus(True)
        box.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        box.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        fm = box.fontMetrics()
        box.setFixedHeight(fm.lineSpacing() * lines + 18)
        return box

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

    def _scan_type(self) -> str:
        btn = self.scan_type_group.checkedButton()
        return btn.text() if btn else "TCP Connect"

    def _set_scan_type(self, value: str):
        btn = self._scan_type_buttons.get(str(value))
        if btn is not None and btn.isEnabled():
            btn.setChecked(True)
        else:
            self._scan_type_buttons["TCP Connect"].setChecked(True)

    def _update_scan_type_hint(self):
        if hasattr(self, "lbl_scan_hint"):
            self.lbl_scan_hint.setText(self._SCAN_TYPE_HINTS.get(self._scan_type(), ""))

    def _settings_page(self, notebook: QTabWidget, title: str):
        page = QWidget()
        page.setObjectName("innerPage")
        page.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        lay = vbox(page, margins=(4, 6, 4, 6), spacing=4)
        notebook.addTab(page, title)
        return lay

    def _spin_row(self, lay, text: str, spin: QWidget, hint: str = "", label_chars: int = 20):
        row = hbox(spacing=6)
        lbl = label(text, C["text2"])
        lbl.setFixedWidth(lbl.fontMetrics().horizontalAdvance("x" * label_chars))
        row.addWidget(lbl)
        spin.setFixedWidth(spin.fontMetrics().horizontalAdvance("0" * 8) + 34)
        row.addWidget(spin)
        if hint:
            row.addWidget(label(hint, C["text3"], Fonts.tiny()))
        row.addStretch(1)
        lay.addLayout(row)

    @staticmethod
    def _int_spin(lo: int, hi: int, value: int, step: int = 1) -> QSpinBox:
        sp = QSpinBox()
        sp.setRange(lo, hi)
        sp.setSingleStep(step)
        sp.setValue(value)
        return sp

    @staticmethod
    def _float_spin(lo: float, hi: float, value: float, step: float = 0.1) -> QDoubleSpinBox:
        sp = QDoubleSpinBox()
        sp.setDecimals(2)
        sp.setRange(lo, hi)
        sp.setSingleStep(step)
        sp.setValue(value)
        return sp

    def _build_perf_tab(self, notebook: QTabWidget):
        lay = self._settings_page(notebook, "Performance")
        self.sp_threads = self._int_spin(1, 1000, 300)
        self.sp_timeout = self._float_spin(0.1, 30.0, 1.5)
        self.sp_connect_timeout = self._float_spin(0.5, 60.0, 3.0)
        self.sp_rate_limit = self._float_spin(0.0, 5000.0, 0.0)
        self.sp_retry = self._int_spin(1, 5, 1)
        for text, spin, hint in [
            ("Threads", self.sp_threads, ""),
            ("Reply Timeout (s)", self.sp_timeout, "UDP/raw"),
            ("Connect Timeout (s)", self.sp_connect_timeout, "TCP"),
            ("Rate Limit (ms)", self.sp_rate_limit, "0=off"),
            ("Probe Attempts", self.sp_retry, "UDP/raw"),
        ]:
            self._spin_row(lay, text, spin, hint, label_chars=19)
        lay.addStretch(1)

    def _build_output_tab(self, notebook: QTabWidget):
        lay = self._settings_page(notebook, "Detection")
        self.chk_banner_grab = QCheckBox("Banner Grabbing")
        self.chk_service_detect = QCheckBox("Service Detection")
        self.chk_os_detect = QCheckBox("OS Detection (heuristic)")
        self.chk_ssl_probe = QCheckBox("SSL/TLS Probing")
        self.chk_host_discovery = QCheckBox("Host Discovery")
        self.chk_show_filtered = QCheckBox("Show Filtered Ports")
        self.chk_show_closed = QCheckBox("Show Closed Ports")
        for chk, default in [
            (self.chk_banner_grab, True),
            (self.chk_service_detect, True),
            (self.chk_os_detect, False),
            (self.chk_ssl_probe, True),
            (self.chk_host_discovery, True),
            (self.chk_show_filtered, True),
            (self.chk_show_closed, False),
        ]:
            chk.setChecked(default)
            lay.addWidget(chk)
        self.chk_show_filtered.toggled.connect(lambda _c: self._apply_filter())
        self.chk_show_closed.toggled.connect(lambda _c: self._apply_filter())
        lay.addStretch(1)

    def _build_advanced_tab(self, notebook: QTabWidget):
        lay = self._settings_page(notebook, "Advanced")
        self.sp_jitter = self._float_spin(0.0, 5000.0, 0.0, step=10)
        self.sp_max_banner = self._float_spin(0.1, 10.0, 2.0)
        self._spin_row(lay, "Jitter (ms)", self.sp_jitter)
        self._spin_row(lay, "Banner Wait (s)", self.sp_max_banner)

        self.chk_udp_probes = QCheckBox("UDP Service Probes")
        self.chk_udp_probes.setChecked(True)
        lay.addWidget(self.chk_udp_probes)
        self.chk_quick_resolve = QCheckBox("DNS Reverse Lookup")
        self.chk_quick_resolve.setChecked(True)
        lay.addWidget(self.chk_quick_resolve)

        rrow = hbox()
        rrow.addWidget(
            self._make_button(
                "Resolve Targets Now", self._resolve_targets, fg=C["accent"], pad=(8, 4)
            )
        )
        rrow.addStretch(1)
        lay.addSpacing(4)
        lay.addLayout(rrow)

        crow = hbox(spacing=6)
        self.lbl_port_count = label("Ports to scan: —", C["text3"])
        crow.addWidget(self.lbl_port_count)
        crow.addWidget(self._make_button("Count", self._count_ports, fg=C["text2"], pad=(6, 2)))
        crow.addStretch(1)
        lay.addLayout(crow)

        prow = hbox(spacing=4)
        prow.addWidget(
            self._make_button("💾 Save Profile", self._save_profile, fg=C["accent"], pad=(8, 4))
        )
        prow.addWidget(
            self._make_button("📂 Load Profile", self._load_profile, fg=C["accent"], pad=(8, 4))
        )
        prow.addStretch(1)
        lay.addSpacing(4)
        lay.addLayout(prow)
        lay.addStretch(1)

    # ── Right panel ──

    def _build_right_panel(self) -> QWidget:
        panel = frame("bg")
        lay = vbox(panel)

        # ── Stats bar ──
        stats_wrap = hbox(margins=(8, 8, 8, 4))
        stats_wrap.addWidget(self._build_stats_bar())
        lay.addLayout(stats_wrap)

        # ── Progress bar with ETA ──
        prow = hbox(margins=(12, 0, 12, 6), spacing=4)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1000)
        self.progress.setTextVisible(False)
        prow.addWidget(self.progress, 1)
        self.lbl_progress = label("0%", C["text3"])
        self.lbl_progress.setFixedWidth(
            self.lbl_progress.fontMetrics().horizontalAdvance("100%") + 6
        )
        self.lbl_progress.setAlignment(Qt.AlignmentFlag.AlignCenter)
        prow.addWidget(self.lbl_progress)
        prow.addSpacing(6)
        prow.addWidget(label("ETA:", C["text3"]))
        self.lbl_eta = label("—", C["accent"])
        self.lbl_eta.setFixedWidth(self.lbl_eta.fontMetrics().horizontalAdvance("0" * 10))
        self.lbl_eta.setAlignment(Qt.AlignmentFlag.AlignCenter)
        prow.addWidget(self.lbl_eta)
        self.lbl_rate = label("", C["text3"])
        self.lbl_rate.setFixedWidth(self.lbl_rate.fontMetrics().horizontalAdvance("0" * 12))
        self.lbl_rate.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        prow.addWidget(self.lbl_rate)
        lay.addLayout(prow)

        # ── Notebook: Results / Log / Detail / Stats / Vulns / History ──
        nb_wrap = hbox(margins=(8, 0, 8, 4))
        nb = QTabWidget()
        nb.setObjectName("outer")
        nb.setDocumentMode(True)
        self.notebook = nb
        self._build_results_tab(nb)
        self._build_log_tab(nb)
        self._build_detail_tab(nb)
        self._build_compare_tab(nb)
        self._build_vuln_tab(nb)
        self._build_history_tab(nb)
        nb_wrap.addWidget(nb)
        lay.addLayout(nb_wrap, 1)
        return panel

    def _build_stats_bar(self) -> QWidget:
        bar = frame("surface")
        bar.setFixedHeight(88)
        lay = hbox(bar, margins=(1, 4, 1, 4), spacing=4)

        self.card_open = StatCard("OPEN PORTS", C["green"])
        self.card_filtered = StatCard("FILTERED", C["yellow"])
        self.card_hosts_up = StatCard("HOSTS UP", C["accent"])
        self.card_ports_done = StatCard("PORTS DONE", C["purple"])
        for card in (self.card_open, self.card_filtered, self.card_hosts_up, self.card_ports_done):
            lay.addWidget(card, 1)

        sep_wrap = vbox(margins=(0, 4, 0, 4))
        sep_wrap.addWidget(vsep())
        lay.addLayout(sep_wrap)

        info = frame("surface2")
        il = vbox(info)
        self.status_strip = QFrame()
        self.status_strip.setFixedHeight(2)
        il.addWidget(self.status_strip)
        il.addSpacing(6)
        il.addWidget(label("STATUS", C["text3"], align=Qt.AlignmentFlag.AlignCenter))
        self.lbl_status = label(
            "IDLE", C["text2"], Fonts.mono_lg(), align=Qt.AlignmentFlag.AlignCenter
        )
        il.addWidget(self.lbl_status)
        self.lbl_current = label("—", C["text3"], align=Qt.AlignmentFlag.AlignCenter)
        il.addWidget(self.lbl_current)
        il.addStretch(1)
        self.status_strip.setStyleSheet(f"background: {C['text3']};")
        lay.addWidget(info, 1)
        return bar

    def _bar(self) -> tuple[QFrame, Any]:
        """Dark control strip used at the top of most tabs."""
        bar = frame("surface")
        return bar, hbox(bar, margins=(8, 4, 8, 4), spacing=6)

    def _tab_page(self, notebook: QTabWidget, title: str) -> tuple[QWidget, Any]:
        tab = frame("bg")
        lay = vbox(tab, margins=(4, 4, 4, 4), spacing=2)
        notebook.addTab(tab, title)
        return tab, lay

    def _build_results_tab(self, notebook: QTabWidget):
        tab, lay = self._tab_page(notebook, "  Results  ")
        self.tab_results = tab

        # Filter bar
        fbar, fl = self._bar()
        fl.addWidget(label("🔍 Filter:", C["text2"]))
        self.entry_filter = QLineEdit()
        self.entry_filter.setMinimumWidth(120)
        self.entry_filter.setMaximumWidth(
            self.entry_filter.fontMetrics().horizontalAdvance("x" * 30) + 14
        )
        self.entry_filter.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.entry_filter.textChanged.connect(lambda _t: self._apply_filter())
        fl.addWidget(self.entry_filter)
        self.chk_filter_regex = QCheckBox("Regex")
        self.chk_filter_regex.toggled.connect(lambda _c: self._apply_filter())
        fl.addWidget(self.chk_filter_regex)

        fl.addSpacing(8)
        fl.addWidget(label("Sort:", C["text2"]))
        self.cb_sort = QComboBox()
        self.cb_sort.addItems(["Port ↑", "Port ↓", "Service", "Response Time", "State"])
        self.cb_sort.setMinimumContentsLength(12)
        self.cb_sort.activated.connect(lambda _i: self._on_sort_preset())
        fl.addWidget(self.cb_sort)

        fl.addSpacing(8)
        fl.addWidget(label("Host:", C["text2"]))
        self.cb_host_filter = QComboBox()
        self.cb_host_filter.addItem("All")
        self.cb_host_filter.setMinimumContentsLength(14)
        self.cb_host_filter.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon
        )
        self.cb_host_filter.activated.connect(lambda _i: self._refresh_results_view())
        fl.addWidget(self.cb_host_filter)

        fl.addStretch(1)
        self.lbl_result_count = label("0 results", C["text3"])
        fl.addWidget(self.lbl_result_count)
        lay.addWidget(fbar)

        # Table
        self.results_model = ResultsModel(self)
        tree = QTableView()
        tree.setModel(self.results_model)
        tree.setFont(Fonts.mono_sm())
        tree.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        tree.setAlternatingRowColors(True)
        tree.setShowGrid(False)
        tree.setWordWrap(False)
        tree.setFrameShape(QFrame.Shape.NoFrame)
        tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        tree.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        tree.verticalHeader().setVisible(False)
        tree.verticalHeader().setDefaultSectionSize(26)
        tree.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        hdr = tree.horizontalHeader()
        hdr.setHighlightSections(False)
        hdr.setSectionsClickable(True)
        hdr.setMinimumSectionSize(40)
        hdr.setStretchLastSection(True)  # banner column stretches
        for i, w in enumerate(COLUMN_WIDTHS):
            tree.setColumnWidth(i, w)
        hdr.sectionClicked.connect(lambda idx: self._sort_tree(COLUMNS[idx]))
        tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        tree.customContextMenuRequested.connect(self._tree_context_menu)
        tree.doubleClicked.connect(lambda _idx: self._show_port_detail())
        self.tree = tree

        # Empty-state hint (hidden as soon as rows appear)
        vp_lay = vbox(tree.viewport())
        self.lbl_empty = label(
            "No results yet\n\nEnter a target and press F5 to start a scan",
            C["text3"],
            Fonts.mono_md(),
            align=Qt.AlignmentFlag.AlignCenter,
        )
        self.lbl_empty.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        vp_lay.addStretch(9)
        vp_lay.addWidget(self.lbl_empty)
        vp_lay.addStretch(11)

        lay.addWidget(tree, 1)

    def _build_log_tab(self, notebook: QTabWidget):
        tab, lay = self._tab_page(notebook, "  Live Log  ")

        ctrl, cl = self._bar()
        self.log_level_group = QButtonGroup(self)
        for lbl, val in [("All", "All"), ("Open Only", "Open"), ("Errors", "Error")]:
            rb = QRadioButton(lbl)
            rb.setObjectName("logFilter")
            rb.setCursor(Qt.CursorShape.PointingHandCursor)
            rb.setProperty("level", val)
            rb.setChecked(val == "All")
            self.log_level_group.addButton(rb)
            cl.addWidget(rb)
            cl.addSpacing(8)
        self.log_level_group.buttonClicked.connect(self._on_log_level)
        cl.addStretch(1)
        self.chk_autoscroll = QCheckBox("Auto-scroll")
        self.chk_autoscroll.setChecked(True)
        cl.addWidget(self.chk_autoscroll)
        cl.addWidget(self._make_button("Clear Log", self._clear_log, fg=C["text2"], pad=(8, 3)))
        lay.addWidget(ctrl)

        self.txt_log = TaggedText(padding=(8, 6), max_lines=self._LOG_MAX_LINES)
        for tag, fg in [
            ("open", C["green"]),
            ("filtered", C["yellow"]),
            ("closed", C["text3"]),
            ("info", C["accent"]),
            ("error", C["red"]),
            ("host", C["purple"]),
            ("timestamp", C["text3"]),
            ("ssl", C["accent2"]),
            ("banner", C["orange"]),
        ]:
            self.txt_log.tag_configure(tag, fg)
        lay.addWidget(self.txt_log, 1)

    def _build_detail_tab(self, notebook: QTabWidget):
        tab = frame("bg")
        notebook.addTab(tab, "  Port Detail  ")
        lay = vbox(tab)

        pw = QSplitter(Qt.Orientation.Horizontal)
        pw.setObjectName("thin")
        pw.setHandleWidth(3)
        pw.setChildrenCollapsible(False)

        left = frame("surface")
        ll = vbox(left, margins=(4, 4, 4, 4), spacing=4)
        hosts_lbl = label("HOSTS", C["accent"])
        hosts_lbl.setContentsMargins(4, 0, 0, 0)
        ll.addWidget(hosts_lbl)
        self.host_listbox = QListWidget()
        self.host_listbox.setFont(Fonts.mono_sm())
        self.host_listbox.currentRowChanged.connect(self._on_host_select)
        ll.addWidget(self.host_listbox, 1)
        left.setMinimumWidth(200)
        pw.addWidget(left)

        self.detail_text = TaggedText(bordered=False, padding=(12, 8))
        self.detail_text.setMinimumWidth(400)
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
            self.detail_text.tag_configure(tag, fg_color)
        self.detail_text.tag_configure("bold", font=Fonts.make(10, bold=True))
        self.detail_text.tag_configure("mono_lg", font=Fonts.mono_lg())
        pw.addWidget(self.detail_text)
        pw.setStretchFactor(1, 1)
        pw.setSizes([240, 800])
        lay.addWidget(pw)

    def _build_compare_tab(self, notebook: QTabWidget):
        tab = frame("bg")
        notebook.addTab(tab, "  Statistics  ")
        lay = vbox(tab, margins=(8, 8, 8, 8))
        self.stats_text = TaggedText(bordered=False, padding=(12, 8))
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
            self.stats_text.tag_configure(tag, fg_c)
        lay.addWidget(self.stats_text)

    def _build_vuln_tab(self, notebook: QTabWidget):
        """Tab for CVE/vulnerability info and geolocation."""
        tab, lay = self._tab_page(notebook, "  Vulnerabilities  ")
        self.tab_vuln = tab

        ctrl, cl = self._bar()
        self.btn_cve = self._make_button(
            "🔍 Lookup CVEs", self._lookup_cves, fg=C["red"], pad=(8, 3)
        )
        cl.addWidget(self.btn_cve)
        self.btn_geo = self._make_button(
            "📍 Geolocation + WHOIS", self._lookup_geolocation, fg=C["accent"], pad=(8, 3)
        )
        cl.addWidget(self.btn_geo)
        cl.addSpacing(8)
        self.lbl_vuln_status = label("", C["text3"])
        cl.addWidget(self.lbl_vuln_status)
        cl.addStretch(1)
        key_note = (
            "NVD API key: set"
            if os.environ.get("NVD_API_KEY")
            else "Tip: set NVD_API_KEY for 10× faster lookups"
        )
        cl.addWidget(label(key_note, C["text3"], Fonts.tiny()))
        lay.addWidget(ctrl)

        self.vuln_text = TaggedText(wrap=True, padding=(12, 8))
        for tag, fg_c in [
            ("cve_critical", C["red"]),
            ("cve_high", C["orange"]),
            ("cve_medium", C["yellow"]),
            ("cve_low", C["green"]),
            ("header", C["accent"]),
            ("geo_info", C["accent2"]),
            ("muted", C["text3"]),
        ]:
            self.vuln_text.tag_configure(tag, fg_c)
        self.vuln_text.tag_configure("link", C["accent"], link=True)
        lay.addWidget(self.vuln_text, 1)
        self._vuln_write(
            "Run a scan, then look up known CVEs for fingerprinted services or\n"
            "geolocate public hosts. Lookups run in the background.\n",
            "muted",
            clear=True,
        )

    def _build_history_tab(self, notebook: QTabWidget):
        """Saved scan runs (SQLite) with load / compare / delete."""
        tab, lay = self._tab_page(notebook, "  History  ")
        self.tab_history = tab

        ctrl, cl = self._bar()
        for text, cmd, fg in [
            ("⟳ Refresh", self._refresh_history, C["text2"]),
            ("💾 Save Current", self._save_current_to_history, C["green"]),
            ("📂 Load", self._load_history_run, C["accent"]),
            ("⇄ Diff vs Current", self._diff_history_vs_current, C["purple"]),
            ("⇄ Diff Selected", self._diff_history_selected, C["purple"]),
            ("✗ Delete", self._delete_history_run, C["red"]),
        ]:
            cl.addWidget(self._make_button(text, cmd, fg=fg, pad=(8, 3)))
        cl.addStretch(1)
        self.chk_autosave = QCheckBox("Auto-save each scan")
        cl.addWidget(self.chk_autosave)
        lay.addWidget(ctrl)

        path_row = hbox(margins=(2, 2, 2, 4), spacing=6)
        path_row.addWidget(label("Database:", C["text3"]))
        self.lbl_db_path = label(self._db_path, C["text2"])
        self.lbl_db_path.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        path_row.addWidget(self.lbl_db_path)
        path_row.addWidget(
            self._make_button("Change…", self._choose_db_path, fg=C["accent"], pad=(6, 1))
        )
        path_row.addStretch(1)
        lay.addLayout(path_row)

        pw = QSplitter(Qt.Orientation.Vertical)
        pw.setHandleWidth(4)
        pw.setChildrenCollapsible(False)

        labels = ("Run", "Timestamp", "Scan Type", "Hosts", "Up", "Open", "Targets")
        widths = (60, 170, 110, 60, 50, 60, 360)
        ht = QTreeWidget()
        ht.setColumnCount(len(labels))
        ht.setHeaderLabels(labels)
        ht.setRootIsDecorated(False)
        ht.setUniformRowHeights(True)
        ht.setAlternatingRowColors(True)
        ht.setFont(Fonts.mono_sm())
        ht.setFrameShape(QFrame.Shape.NoFrame)
        ht.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        ht.header().setStretchLastSection(True)
        ht.header().setMinimumSectionSize(40)
        for i, w in enumerate(widths):
            ht.setColumnWidth(i, w)
        ht.itemDoubleClicked.connect(lambda *_: self._load_history_run())
        ht.setMinimumHeight(120)
        self.history_tree = ht
        pw.addWidget(ht)

        self.diff_text = TaggedText(padding=(12, 8))
        self.diff_text.setMinimumHeight(100)
        for tag, fg_c in [
            ("header", C["accent"]),
            ("new", C["green"]),
            ("closed", C["red"]),
            ("changed", C["yellow"]),
            ("info", C["purple"]),
            ("muted", C["text3"]),
        ]:
            self.diff_text.tag_configure(tag, fg_c)
        pw.addWidget(self.diff_text)
        pw.setStretchFactor(1, 1)
        pw.setSizes([240, 300])
        lay.addWidget(pw, 1)
        self._write_diff("Select a run and choose Diff to see what changed.\n", clear=True)

    def _build_statusbar(self) -> QWidget:
        bar = frame("statusbar")
        bar.setFixedHeight(24)
        lay = hbox(bar, margins=(12, 0, 12, 0), spacing=12)

        self.lbl_statusbar = label("Ready — Load a target and click Start Scan", C["text3"])
        lay.addWidget(self.lbl_statusbar)
        lay.addStretch(1)
        lay.addWidget(
            label(
                "● raw sockets" if self._raw_ok else "○ unprivileged",
                C["green"] if self._raw_ok else C["text3"],
            )
        )
        self.lbl_hostname = label(self._local_host_info(), C["text3"])
        lay.addWidget(self.lbl_hostname)
        lay.addWidget(label(f"◈ NexScan v{self.VERSION}", C["text3"]))
        return bar

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

    # ─────────────────────────── HISTORY ───────────────────────────

    def _choose_db_path(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Scan history database",
            self._db_path,
            "SQLite database (*.db);;All Files (*)",
            options=QFileDialog.Option.DontConfirmOverwrite,
        )
        if path:
            if not os.path.splitext(path)[1]:
                path += ".db"
            self._set_db_path(path)
            self._refresh_history()

    def _set_db_path(self, path: str):
        self._db_path = path
        self.lbl_db_path.setText(path)

    def _refresh_history(self):
        from core.db import get_timeline_summary

        tree = self.history_tree
        tree.clear()
        try:
            rows = get_timeline_summary(self._db_path, limit=500)
        except Exception as e:
            self._toast(f"Could not read history: {e}", "error")
            return
        center = Qt.AlignmentFlag.AlignCenter
        items = []
        for r in rows:
            targets = ", ".join(r["targets"][:6]) + (" …" if len(r["targets"]) > 6 else "")
            item = QTreeWidgetItem(
                [
                    str(r["id"]),
                    r["timestamp"][:19].replace("T", " "),
                    str(r["scan_type"]),
                    str(r["hosts_scanned"]),
                    str(r["hosts_up"]),
                    str(r["total_open_ports"]),
                    targets,
                ]
            )
            item.setData(0, Qt.ItemDataRole.UserRole, int(r["id"]))
            for col in (0, 3, 4, 5):
                item.setTextAlignment(col, center)
            items.append(item)
        tree.addTopLevelItems(items)

    def _selected_run_ids(self) -> list[int]:
        return [
            int(it.data(0, Qt.ItemDataRole.UserRole)) for it in self.history_tree.selectedItems()
        ]

    def _save_current_to_history(self, quiet: bool = False):
        if not self.scan_results:
            if not quiet:
                self._toast("No scan results to save", "warn")
            return
        from core.db import save_scan_results

        try:
            run_id = save_scan_results(self._db_path, self.scan_results)
        except Exception as e:
            self._toast(f"Saving to history failed: {e}", "error")
            return
        self._log(f"Scan saved to history as run #{run_id}", "info")
        if not quiet:
            self._toast(f"Saved as run #{run_id}", "ok")
        self._refresh_history()

    def _load_run(self, run_id: int):
        from core.db import fetch_run_by_id

        row = fetch_run_by_id(self._db_path, run_id)
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
        self._select_tab(self.tab_results)

    def _write_diff(self, text: str, tag=None, clear: bool = False):
        if clear:
            self.diff_text.clear_text()
        self.diff_text.write(text, tag)

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
        self.diff_text.scroll_to_top()

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
        if not self._ask_yes_no(
            "Delete Runs", f"Permanently delete {len(ids)} run(s) from history?"
        ):
            return
        from core.db import delete_run

        for run_id in ids:
            delete_run(self._db_path, run_id)
        self._refresh_history()
        self._toast(f"Deleted {len(ids)} run(s)", "ok")

    # ─────────────────────────── VULNERABILITIES ───────────────────────────

    def _vuln_write(self, text: str, tag=None, clear: bool = False):
        if clear:
            self.vuln_text.clear_text()
        self.vuln_text.write(text, tag)
        self.vuln_text.scroll_to_end()

    def _set_vuln_busy(self, busy: bool, status: str = ""):
        self._vuln_busy = busy
        self.btn_cve.set_enabled(not busy)
        self.btn_geo.set_enabled(not busy)
        self.lbl_vuln_status.setText(status)
        set_fg(self.lbl_vuln_status, C["accent"] if busy else C["text3"])

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

        self.lbl_vuln_status.setText(f"Querying NVD… {i}/{n}")
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

    # ─────────────────────────── HELPERS ───────────────────────────

    def _make_button(self, text, command, fg=None, bg=None, hover_bg=None, pad=(12, 6)):
        return FlatButton(
            text,
            command,
            fg=fg or C["text"],
            bg=bg or C["btn_bg"],
            hover_bg=hover_bg or C["btn_hover"],
            pad=pad,
        )

    def _ask_yes_no(self, title: str, text: str, warning: bool = True) -> bool:
        box = QMessageBox(
            QMessageBox.Icon.Warning if warning else QMessageBox.Icon.Question,
            title,
            text,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            self,
        )
        box.setDefaultButton(QMessageBox.StandardButton.Yes)
        return box.exec() == QMessageBox.StandardButton.Yes

    def _show_error(self, title: str, text: str):
        QMessageBox.critical(self, title, text)

    _LOG_MAX_LINES = 5000

    def _log_visible(self, tag: str) -> bool:
        level = self._log_level
        if level == "Open":
            return tag in ("open", "banner", "ssl", "host")
        if level == "Error":
            return tag == "error"
        return True

    def _on_log_level(self, button: QRadioButton):
        self._log_level = button.property("level") or "All"
        self._rerender_log()

    def _log(self, msg: str, tag: str = "info"):
        """Append to the live log. Safe to call from any thread."""
        if threading.current_thread() is not threading.main_thread():
            self._ui_queue.put(("log", msg, tag))
            return
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self._log_entries.append((ts, msg, tag))
        if self._log_visible(tag) and hasattr(self, "txt_log"):
            self._insert_log_line(ts, msg, tag)

    def _insert_log_line(self, ts: str, msg: str, tag: str):
        self.txt_log.write(f"[{ts}] ", "timestamp")
        self.txt_log.write(f"{msg}\n", tag)
        if self.chk_autoscroll.isChecked():
            self.txt_log.scroll_to_end()

    def _rerender_log(self):
        self.txt_log.setUpdatesEnabled(False)
        self.txt_log.clear_text()
        for ts, msg, tag in self._log_entries:
            if self._log_visible(tag):
                self.txt_log.write(f"[{ts}] ", "timestamp")
                self.txt_log.write(f"{msg}\n", tag)
        self.txt_log.setUpdatesEnabled(True)
        if self.chk_autoscroll.isChecked():
            self.txt_log.scroll_to_end()

    def _set_status(self, text: str, color: Optional[str] = None):
        color = color or C["text2"]
        self.lbl_status.setText(text)
        set_fg(self.lbl_status, color)
        self.status_strip.setStyleSheet(f"background: {color};")
        self.lbl_statusbar.setText(text)

    def _set_current(self, text: str):
        self.lbl_current.setText(text)

    def _toast(self, message: str, kind: str = "info", ms: int = 3200):
        """Non-blocking notification in the bottom-right corner."""
        self._toast_widget.show_message(message, kind, ms)

    def _copy_to_clipboard(self, text: str):
        cb = QApplication.clipboard()
        if cb is not None:
            cb.setText(text)

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

    def _targets_text(self) -> str:
        return self.txt_targets.toPlainText().strip()

    def _ports_text(self) -> str:
        return self.txt_ports.toPlainText().strip()

    def _get_scan_config(self) -> ScanConfig:
        """Build ScanConfig from UI state."""
        targets = parse_targets(self._targets_text())
        ports = parse_ports(self._ports_text().replace("\n", ","))

        if not targets:
            raise ValueError("No valid targets specified.")
        if not ports:
            raise ValueError("No valid ports specified.")

        stype = self._SCAN_TYPE_MAP.get(self._scan_type(), ScanType.TCP_CONNECT)
        if stype in RAW_SCAN_TYPES and not self._raw_ok:
            raise ValueError(self._raw_reason or "Raw scans are not available.")

        try:
            threads = max(1, min(1000, int(self.sp_threads.value())))
            return ScanConfig(
                targets=targets,
                ports=ports,
                scan_type=stype,
                threads=threads,
                timeout=max(0.05, float(self.sp_timeout.value())),
                connect_timeout=max(0.05, float(self.sp_connect_timeout.value())),
                grab_banners=self.chk_banner_grab.isChecked(),
                detect_service=self.chk_service_detect.isChecked(),
                detect_os=self.chk_os_detect.isChecked(),
                ssl_probe=self.chk_ssl_probe.isChecked(),
                rate_limit=max(0.0, float(self.sp_rate_limit.value())) / 1000.0,
                retry_count=max(1, int(self.sp_retry.value())),
                jitter=max(0.0, float(self.sp_jitter.value())),
                max_banner_wait=max(0.1, float(self.sp_max_banner.value())),
                host_discovery=self.chk_host_discovery.isChecked(),
                udp_payload_probes=self.chk_udp_probes.isChecked(),
                reverse_dns=self.chk_quick_resolve.isChecked(),
            )
        except (TypeError, ValueError) as e:
            raise ValueError(f"Invalid numeric setting: {e}") from e

    def _start_scan(self):
        if self.is_scanning:
            return

        try:
            config = self._get_scan_config()
        except ValueError as e:
            self._show_error("Configuration Error", str(e))
            return

        # Confirm large scans
        total = len(config.targets) * len(config.ports)
        if total > 500_000:
            ok = self._ask_yes_no(
                "Large Scan",
                f"This scan covers {total:,} port/host combinations.\n"
                "This may take a long time. Continue?",
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

        self._stat_total_ports = total
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
        self._elapsed_timer.start(1000)

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
        ok = self._ask_yes_no("Cancel Scan", "Are you sure you want to cancel the scan?")
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

    # Scanner callbacks (run on the scan thread → queue)
    def _on_port_found(self, target: str, port_result: PortResult):
        self._ui_queue.put(("port_found", target, port_result))

    def _on_progress(
        self, completed: int, total: int, target: str, host_done: int, host_total: int
    ):
        self._ui_queue.put(("progress", completed, total, target, host_done, host_total))

    def _on_host_complete(self, result: ScanResult):
        self._ui_queue.put(("host_complete", result))

    def _poll_queue(self):
        """Process UI queue messages (runs on the GUI thread every 30 ms).

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
            self.progress.setValue(int(pct * 10))
            self.lbl_progress.setText(f"{int(pct)}%")
            self.card_ports_done.set_value(done)
            self._set_current(f"{target} [{hdone}/{htotal}]")
            self.setWindowTitle(f"NexScan — {int(pct)}% scanning…")

            # ETA / throughput (paused time excluded)
            elapsed = self._active_elapsed()
            if done > 0 and total > 0 and self.is_scanning and elapsed > 0:
                rate = done / elapsed
                remaining = (total - done) / rate if rate > 0 else 0
                self.lbl_eta.setText(self._fmt_duration(remaining))
                self.lbl_rate.setText(f"{rate:,.0f} p/s")
            else:
                self.lbl_eta.setText("—")

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
            self._elapsed_timer.stop()
            self._update_controls()
            self.setWindowTitle(f"NexScan v{self.VERSION} — Advanced Port Scanner")
            self._set_status(
                "STOPPED" if stopped else "COMPLETE", C["red"] if stopped else C["accent"]
            )
            elapsed = self._active_elapsed()
            self._log(
                f"Scan {'stopped' if stopped else 'complete'} in {elapsed:.1f}s  "
                f"Open:{self.card_open.get()}  "
                f"Filtered:{self.card_filtered.get()}  "
                f"Hosts up:{self.card_hosts_up.get()}",
                "info",
            )
            if not stopped:
                self.progress.setValue(1000)
                self.lbl_progress.setText("100%")
            self.lbl_eta.setText("—")
            self._recount_stats()
            self._update_host_list()
            self._update_stats_tab()
            self._refresh_results_view()  # apply sort order to rows streamed live
            if self.chk_autosave.isChecked():
                self._save_current_to_history(quiet=True)
            self._toast(
                f"Scan {'stopped' if stopped else 'complete'} — "
                f"{self.card_open.get()} open port(s) on {self.card_hosts_up.get()} host(s)",
                "warn" if stopped else "ok",
            )
            QApplication.beep()

        elif kind == "scan_error":
            _, err = msg
            self.is_scanning = False
            self.is_paused = False
            self._elapsed_timer.stop()
            self._update_controls()
            self.setWindowTitle(f"NexScan v{self.VERSION} — Advanced Port Scanner")
            self._set_status("ERROR", C["red"])
            self._log(f"Scan error: {err}", "error")
            self._show_error("Scan Error", str(err))

        elif kind == "log":
            _, text, tag = msg
            self._log(text, tag)

        elif kind == "vuln_cves":
            self._render_cves(*msg[1:])

        elif kind == "vuln_text":
            _, text, tag = msg
            self._vuln_write(text, tag)

        elif kind == "vuln_status":
            self.lbl_vuln_status.setText(msg[1])

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
        return row_key(target, pr)

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
        key = row_key(target, pr)
        is_new = key not in self._rows
        self._rows[key] = (target, pr)
        if is_new:
            self._add_result_row(target, pr)

    def _recount_stats(self):
        counts = self._live_counts.values()
        self.card_open.set_value(sum(c.get("open", 0) for c in counts))
        self.card_filtered.set_value(sum(c.get("filtered", 0) for c in counts))
        self.card_hosts_up.set_value(sum(c.get("up", 0) for c in counts))

    def _schedule_stats_refresh(self):
        """Statistics are rebuilt at most twice a second while hosts complete."""
        if not self._stats_timer.isActive():
            self._stats_timer.start(500)

    def _state_tag(self, pr: PortResult) -> Optional[str]:
        """Row colour tag for a port, or None if hidden by the show-filtered/closed toggles."""
        if pr.state == PortState.OPEN:
            if pr.ssl_info and pr.ssl_info.get("expired"):
                return "warn"
            return "open"
        if pr.state in (PortState.FILTERED, PortState.OPEN_FILTERED):
            return "filtered" if self.chk_show_filtered.isChecked() else None
        return "closed" if self.chk_show_closed.isChecked() else None

    def _set_filter_border(self, color: Optional[str]):
        self.entry_filter.setStyleSheet(
            "" if color is None else f"QLineEdit {{ border: 1px solid {color}; }}"
        )

    def _compile_filter(self) -> Optional[Callable[[str], bool]]:
        """Return a predicate for the filter box (None = no filter)."""
        ftext = self.entry_filter.text().strip().lower()
        if not ftext:
            self._set_filter_border(None)
            return None
        if self.chk_filter_regex.isChecked():
            try:
                rx = re.compile(ftext, re.IGNORECASE)
            except re.error:
                self._set_filter_border(C["red"])
                return lambda row: True
            self._set_filter_border(C["accent2"])
            return lambda row: bool(rx.search(row))
        self._set_filter_border(C["accent2"])
        terms = ftext.split()
        return lambda row: all(t in row for t in terms)

    @staticmethod
    def _row_values(target: str, pr: PortResult) -> tuple:
        return row_values(target, pr)

    def _row_passes(self, target: str, pr: PortResult, predicate) -> bool:
        host_filter = self.cb_host_filter.currentText() or "All"
        if host_filter != "All" and target != host_filter:
            return False
        if predicate is None:
            return True
        values = row_values(target, pr)
        return predicate(" ".join(str(v) for v in values).lower())

    def _add_result_row(self, target: str, pr: PortResult):
        """Insert one row live (if it passes the current filters)."""
        tag = self._state_tag(pr)
        if tag is None or not self._row_passes(target, pr, self._compile_filter()):
            return
        if self.results_model.append_row(target, pr, tag):
            self._update_result_count()

    def _update_result_count(self):
        n = self.results_model.rowCount()
        self.lbl_result_count.setText(f"{n:,} result{'s' if n != 1 else ''}")
        self.lbl_empty.setVisible(n == 0)

    def _update_timer(self):
        if not self.is_scanning:
            self._elapsed_timer.stop()
            return
        if not self.is_paused:
            elapsed = int(self._active_elapsed())
            h, m, s = elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60
            self.lbl_timer.setText(f"{h:02d}:{m:02d}:{s:02d}")
            set_fg(self.lbl_timer, C["accent"])
            set_fg(self.lbl_timer_icon, C["accent"])

    def _update_host_list(self):
        current = self.cb_host_filter.currentText() or "All"
        self.cb_host_filter.blockSignals(True)
        self.cb_host_filter.clear()
        self.cb_host_filter.addItems(["All"] + [r.target for r in self.scan_results])
        idx = self.cb_host_filter.findText(current)
        self.cb_host_filter.setCurrentIndex(max(0, idx))
        self.cb_host_filter.blockSignals(False)

        selected = self.host_listbox.currentRow()
        self.host_listbox.blockSignals(True)
        self.host_listbox.clear()
        for r in self.scan_results:
            status = "▲" if r.host_up else "▼"
            item = QListWidgetItem(f"{status} {r.target}  [{r.open_count} open]")
            color = (
                C["green"]
                if r.host_up and r.open_count
                else (C["text"] if r.host_up else C["text3"])
            )
            item.setForeground(QColor(color))
            self.host_listbox.addItem(item)
        if 0 <= selected < self.host_listbox.count():
            self.host_listbox.setCurrentRow(selected)
        self.host_listbox.blockSignals(False)

    def _on_host_select(self, idx: int):
        if 0 <= idx < len(self.scan_results):
            self._show_host_detail(self.scan_results[idx])

    def _show_host_detail(self, result: ScanResult):
        """Show detailed info for a host in the detail tab."""
        dt = self.detail_text
        dt.clear_text()
        w = dt.write

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
        dt.scroll_to_top()

    def _update_stats_tab(self):
        """Update the statistics tab with current scan data."""
        st = self.stats_text
        st.clear_text()
        w = st.write

        if not self.scan_results:
            w("  No scan data available yet.\n", "key")
            return

        sep = "─" * 60 + "\n"

        w("◈ SCAN STATISTICS\n", "header")
        w(sep, "sep")

        all_open = []
        service_counts: dict = defaultdict(int)
        port_counts: dict = defaultdict(int)
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
        w(f"{self.card_filtered.get()}\n", "val")

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
        os_counts: dict = defaultdict(int)
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
        st.scroll_to_top()

    # ─────────────────────────── FILTER & SORT ───────────────────────────

    def _apply_filter(self, *args):
        """Debounced: typing in the filter box rebuilds the view once typing pauses."""
        self._refresh_timer.start(120)

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
        """Rebuild the table from the live row store with current filters/sort."""
        self._refresh_timer.stop()
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
            sort_val = self.cb_sort.currentText()
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

        self.results_model.set_rows(all_rows)
        self.results_model.set_sort_indicator(self._header_sort)
        self._update_result_count()

    def _sort_tree(self, col: str):
        """Heading click: sort by column, clicking again toggles direction."""
        if self._header_sort and self._header_sort[0] == col:
            self._header_sort = (col, not self._header_sort[1])
        else:
            self._header_sort = (col, False)
        self._refresh_results_view()

    # ─────────────────────────── EXPORT ───────────────────────────

    def _export_menu(self):
        menu = QMenu(self)
        for fmt, (_fn, _ext, lbl) in EXPORTERS.items():
            menu.addAction(f"Export as {lbl}", lambda f=fmt: self._export(f))
        menu.addSeparator()
        menu.addAction("Copy visible results", self._copy_results)
        menu.addAction("Save to history", self._save_current_to_history)
        menu.exec(QCursor.pos())

    def _export(self, fmt: str):
        if not self.scan_results:
            self._toast("No scan results to export", "warn")
            return

        fn, ext, lbl = EXPORTERS[fmt]
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path, _ = QFileDialog.getSaveFileName(
            self,
            f"Export {lbl}",
            f"nexscan_{ts}{ext}",
            f"{lbl} files (*{ext});;All Files (*)",
        )
        if not path:
            return
        if not os.path.splitext(path)[1]:
            path += ext

        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(fn(self.scan_results))
            self._log(f"Exported {lbl} report to: {path}", "info")
            self._toast(f"Saved {os.path.basename(path)}", "ok")
            if fmt == "html" and self._ask_yes_no(
                "Export Successful",
                f"Report saved to:\n{path}\n\nOpen it in your browser?",
                warning=False,
            ):
                webbrowser.open(f"file://{os.path.abspath(path)}")
        except Exception as e:
            self._show_error("Export Error", str(e))

    def _copy_results(self):
        self._copy_rows(range(self.results_model.rowCount()), "visible")

    def _selected_rows(self) -> list[int]:
        sel = self.tree.selectionModel()
        return sorted(i.row() for i in sel.selectedRows()) if sel else []

    def _copy_selected_rows(self):
        sel = self._selected_rows()
        self._copy_rows(
            sel or range(self.results_model.rowCount()), "selected" if sel else "visible"
        )

    def _copy_rows(self, rows, what: str):
        lines = ["\t".join(COLUMN_LABELS)]
        for r in rows:
            lines.append("\t".join(str(v) for v in self.results_model.values_at(r)))
        self._copy_to_clipboard("\n".join(lines))
        self._log(f"Copied {len(lines) - 1} rows to clipboard.", "info")
        self._toast(f"Copied {len(lines) - 1} {what} row(s)", "ok")

    # ─────────────────────────── MISC ───────────────────────────

    def _apply_port_preset(self, event=None):
        preset = self.cb_preset.currentText()
        ports = self.service_db.get_preset_ports(preset)
        if ports:
            self.txt_ports.setPlainText(",".join(str(p) for p in ports))
            self._log(f"Applied preset '{preset}': {len(ports)} ports", "info")
            self._count_ports()

    def _count_ports(self):
        ports: list = []
        try:
            ports = parse_ports(self._ports_text().replace("\n", ","))
            text, color = f"Ports to scan: {len(ports):,}", C["green"] if ports else C["red"]
        except Exception:
            text, color = "Invalid port range", C["red"]
        self.lbl_port_count.setText(text)
        set_fg(self.lbl_port_count, color)
        self.lbl_port_summary.setText(
            f"{len(ports):,} port{'s' if len(ports) != 1 else ''} to scan" if ports else text
        )
        set_fg(self.lbl_port_summary, C["text2"] if ports else color)

    def _count_targets(self):
        try:
            targets = parse_targets(self._targets_text())
        except Exception:
            targets = []
        n = len(targets)
        if not n:
            self.lbl_target_summary.setText("No valid targets")
            set_fg(self.lbl_target_summary, C["red"])
            return
        preview = ", ".join(targets[:3]) + (" …" if n > 3 else "")
        self.lbl_target_summary.setText(f"{n:,} host{'s' if n != 1 else ''}: {preview}")
        set_fg(self.lbl_target_summary, C["text2"])

    def _resolve_targets(self):
        targets = parse_targets(self._targets_text())
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
            QMessageBox.warning(self, "Scan Running", "Stop the scan before clearing results.")
            return
        self._clear_results_internal()

    def _clear_results_internal(self):
        self.scan_results = []
        self._rows.clear()
        self._live_counts.clear()
        self.results_model.clear()
        self.host_listbox.clear()
        self.cb_host_filter.clear()
        self.cb_host_filter.addItem("All")
        for card in (self.card_open, self.card_filtered, self.card_hosts_up, self.card_ports_done):
            card.set_value(0)
        self.lbl_eta.setText("—")
        self.progress.setValue(0)
        self.lbl_progress.setText("0%")
        self.lbl_rate.setText("")
        self.lbl_timer.setText("00:00:00")
        set_fg(self.lbl_timer, C["text3"])
        set_fg(self.lbl_timer_icon, C["text3"])
        self._update_result_count()
        self._set_status("IDLE", C["text2"])
        self._set_current("—")
        self.detail_text.clear_text()
        self._update_stats_tab()

    def _clear_log(self):
        self.txt_log.clear_text()

    _WEB_SERVICES = ("http", "https", "http-proxy", "http-alt", "https-alt", "www")

    def _tree_context_menu(self, pos: QPoint):
        index = self.tree.indexAt(pos)
        if not index.isValid():
            return
        sel = self.tree.selectionModel()
        if sel is not None and not sel.isRowSelected(index.row(), index.parent()):
            self.tree.selectRow(index.row())
        self.tree.setCurrentIndex(index)
        iid = self.results_model.key_at(index.row())
        entry = self._rows.get(iid)
        if not entry:
            return
        target, pr = entry
        host, port = target, pr.port

        menu = QMenu(self)
        menu.addAction("Show Port Detail", lambda: self._show_port_popup_for(iid))
        if pr.state == PortState.OPEN and (
            pr.service in self._WEB_SERVICES or pr.service.startswith("http")
        ):
            scheme = "https" if pr.ssl_info or "https" in pr.service else "http"
            url = f"{scheme}://{host}:{port}/"
            menu.addAction(f"Open {url}", lambda: webbrowser.open(url))
        menu.addSeparator()
        menu.addAction(f"Copy {host}:{port}", lambda: self._copy_text(f"{host}:{port}"))
        menu.addAction(f"Copy host {host}", lambda: self._copy_text(host))
        if pr.banner:
            menu.addAction("Copy banner", lambda: self._copy_text(pr.banner))
        n_sel = len(self._selected_rows())
        menu.addAction(f"Copy {n_sel} selected row(s)", self._copy_selected_rows)
        menu.addSeparator()
        menu.addAction(f"Filter by port {port}", lambda: self.entry_filter.setText(str(port)))
        menu.addAction(f"Filter by host {host}", lambda: self.entry_filter.setText(host))
        if pr.service:
            menu.addAction(
                f"Filter by service {pr.service}", lambda: self.entry_filter.setText(pr.service)
            )
        menu.addAction("Clear filter", lambda: self.entry_filter.setText(""))
        menu.exec(self.tree.viewport().mapToGlobal(pos))

    def _copy_text(self, text: str):
        self._copy_to_clipboard(text)
        self._toast("Copied to clipboard", "ok", ms=1500)

    def _show_port_detail(self, event=None):
        idx = self.tree.currentIndex()
        if idx.isValid():
            iid = self.results_model.key_at(idx.row())
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

    def _track_popup(self, dlg):
        self._popups.append(dlg)
        dlg.destroyed.connect(lambda *_: self._popups.remove(dlg) if dlg in self._popups else None)

    def _show_port_popup(self, result: ScanResult, pr: PortResult):
        self._track_popup(dialogs.show_port_popup(self, result, pr, self._copy_text))

    def _show_about(self):
        self._track_popup(dialogs.show_about(self, self.VERSION))

    # ─────────────────────────── PROFILES & SETTINGS ───────────────────────────

    def _profile_vars(self) -> dict[str, tuple[Callable[[], Any], Callable[[Any], None]]]:
        """Settings captured in profiles and remembered between sessions: key -> (get, set)."""

        def spin(sp):
            if isinstance(sp, QSpinBox):
                return sp.value, lambda v: sp.setValue(int(float(v)))
            return sp.value, lambda v: sp.setValue(float(v))

        def chk(cb: QCheckBox):
            return cb.isChecked, lambda v: cb.setChecked(bool(v))

        def combo(cb: QComboBox):
            def setter(v):
                idx = cb.findText(str(v))
                if idx >= 0:
                    cb.setCurrentIndex(idx)

            return cb.currentText, setter

        return {
            "scan_type": (self._scan_type, self._set_scan_type),
            "threads": spin(self.sp_threads),
            "timeout": spin(self.sp_timeout),
            "connect_timeout": spin(self.sp_connect_timeout),
            "rate_limit_ms": spin(self.sp_rate_limit),
            "attempts": spin(self.sp_retry),
            "jitter_ms": spin(self.sp_jitter),
            "banner_wait": spin(self.sp_max_banner),
            "banner_grab": chk(self.chk_banner_grab),
            "service_detect": chk(self.chk_service_detect),
            "os_detect": chk(self.chk_os_detect),
            "ssl_probe": chk(self.chk_ssl_probe),
            "host_discovery": chk(self.chk_host_discovery),
            "udp_probes": chk(self.chk_udp_probes),
            "reverse_dns": chk(self.chk_quick_resolve),
            "show_filtered": chk(self.chk_show_filtered),
            "show_closed": chk(self.chk_show_closed),
            "port_preset": combo(self.cb_preset),
        }

    def _collect_profile(self) -> dict:
        profile = {"targets": self._targets_text(), "ports": self._ports_text()}
        for key, (getter, _setter) in self._profile_vars().items():
            profile[key] = getter()
        return profile

    def _apply_profile(self, profile: dict):
        if "targets" in profile:
            self.txt_targets.setPlainText(str(profile["targets"]))
        if "ports" in profile:
            self.txt_ports.setPlainText(str(profile["ports"]))

        # Accept keys written by older versions
        legacy = {"retries": "attempts"}
        for old, new in legacy.items():
            if old in profile and new not in profile:
                try:
                    profile[new] = max(1, int(profile[old]))
                except (TypeError, ValueError):
                    pass

        for key, (_getter, setter) in self._profile_vars().items():
            if key in profile:
                try:
                    setter(profile[key])
                except (ValueError, TypeError):
                    pass
        self._update_scan_type_hint()
        self._count_ports()
        self._count_targets()

    def _save_profile(self):
        """Save current scan configuration as a profile."""
        file, _ = QFileDialog.getSaveFileName(
            self, "Save Profile", "nexscan_profile.json", "NexScan Profile (*.json);;All Files (*)"
        )
        if not file:
            return
        if not os.path.splitext(file)[1]:
            file += ".json"
        try:
            with open(file, "w", encoding="utf-8") as f:
                json.dump(self._collect_profile(), f, indent=2)
            self._log(f"Profile saved to {file}", "info")
            self._toast(f"Profile saved: {os.path.basename(file)}", "ok")
        except Exception as e:
            self._show_error("Error", f"Failed to save profile: {e}")

    def _load_profile(self):
        """Load a saved scan configuration profile."""
        file, _ = QFileDialog.getOpenFileName(
            self, "Load Profile", "", "NexScan Profile (*.json);;All Files (*)"
        )
        if not file:
            return
        try:
            with open(file, "r", encoding="utf-8") as f:
                self._apply_profile(json.load(f))
            self._log(f"Profile loaded from {file}", "info")
            self._toast(f"Profile loaded: {os.path.basename(file)}", "ok")
        except Exception as e:
            self._show_error("Error", f"Failed to load profile: {e}")

    def _load_settings(self):
        """Restore the last session's settings (silently ignores a missing/corrupt file)."""
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return
        self._apply_profile(data.get("profile", {}) or {})
        if data.get("db_path"):
            self._set_db_path(str(data["db_path"]))
        self.chk_autosave.setChecked(bool(data.get("autosave", False)))

        try:
            self._restore_geometry(data)
        except Exception:
            pass  # a bad saved geometry must never stop the app from starting

    def _restore_geometry(self, data: dict):
        qt_geo = data.get("qt_geometry")
        if isinstance(qt_geo, str) and qt_geo:
            self.restoreGeometry(QByteArray.fromBase64(qt_geo.encode("ascii")))
            return
        # Settings written by the old Tk GUI: "WxH+X+Y". Tk writes negative offsets as
        # "+-16" (e.g. a maximised window on Windows), so the sign is "+", "-" or "+-".
        geometry = data.get("geometry")
        if not isinstance(geometry, str):
            return
        m = re.match(r"^(\d+)x(\d+)(\+-?\d+|-\d+)(\+-?\d+|-\d+)$", geometry.strip())
        if not m:
            return
        w, h = int(m.group(1)), int(m.group(2))
        x, y = (int(v.lstrip("+")) for v in m.group(3, 4))
        self.resize(max(w, 1100), max(h, 700))
        # Keep the title bar on a visible screen
        screen = QApplication.screenAt(QPoint(x + 50, y + 50)) or QApplication.primaryScreen()
        if screen is not None:
            area = screen.availableGeometry()
            x = min(max(x, area.left()), max(area.left(), area.right() - 200))
            y = min(max(y, area.top()), max(area.top(), area.bottom() - 100))
        self.move(x, y)

    def _save_settings(self):
        data = {
            "profile": self._collect_profile(),
            "db_path": self._db_path,
            "autosave": self.chk_autosave.isChecked(),
            "qt_geometry": bytes(self.saveGeometry().toBase64().data()).decode("ascii"),
        }
        try:
            os.makedirs(SETTINGS_DIR, exist_ok=True)
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except OSError:
            pass

    def _shortcut(self, keys, fn, widget: Optional[QWidget] = None):
        sc = QShortcut(QKeySequence(keys), widget or self)
        if widget is not None:
            sc.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        sc.activated.connect(fn)
        return sc

    def _setup_bindings(self):
        self._shortcut("F5", self._start_scan)
        self._shortcut("F6", self._toggle_pause)
        self._shortcut("Escape", self._stop_scan)
        self._shortcut("Ctrl+E", self._export_menu)
        self._shortcut("Ctrl+L", self._clear_results)
        self._shortcut("Ctrl+F", self._focus_filter)
        self._shortcut("Ctrl+S", self._save_profile)
        self._shortcut("Ctrl+O", self._load_profile)
        self._shortcut("Ctrl+H", lambda: self._select_tab(self.tab_history))
        # Table-local keys
        self._shortcut(QKeySequence.StandardKey.Copy, self._copy_selected_rows, self.tree)
        self._shortcut("Return", self._show_port_detail, self.tree)
        self._shortcut("Enter", self._show_port_detail, self.tree)
        self.notebook.currentChanged.connect(self._on_tab_changed)

    def _focus_filter(self):
        self._select_tab(self.tab_results)
        self.entry_filter.setFocus()
        self.entry_filter.selectAll()

    def _on_tab_changed(self, _index: int = 0):
        if self.notebook.currentWidget() is self.tab_history:
            self._refresh_history()

    def closeEvent(self, event: QCloseEvent):
        if self.is_scanning:
            ok = self._ask_yes_no("Scan Running", "A scan is currently running. Stop it and exit?")
            if not ok:
                event.ignore()
                return
            if self.scanner:
                self.scanner.stop()
        self._save_settings()
        event.accept()

    # Kept for API compatibility with the Tk version
    def _on_close(self):
        self.close()


def create_app(argv: Optional[list] = None) -> QApplication:
    """Create (or reuse) the QApplication and apply the NexScan theme."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName("NexScan")
    app.setStyle("Fusion")  # consistent base for the stylesheet on every platform
    init_fonts()
    app.setFont(Fonts.mono_sm())
    app.setStyleSheet(stylesheet())
    return app  # type: ignore[return-value]


def main():
    app = create_app()
    window = NexScanApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
