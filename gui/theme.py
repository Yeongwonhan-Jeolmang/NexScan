"""
NexScan GUI — colour palette, fonts and the Qt stylesheet.

The palette is identical to the original Tkinter build so the look carries over 1:1.
"""

from __future__ import annotations

import os

from PyQt6.QtGui import QFont, QFontDatabase

_ASSETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")


def asset(name: str) -> str:
    """Absolute, forward-slashed path to a bundled asset (Qt stylesheets want '/')."""
    return os.path.join(_ASSETS, name).replace(os.sep, "/")


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


class Fonts:
    """Font families resolved once a QApplication exists (see :func:`init_fonts`)."""

    mono: str = "Monospace"
    ui: str = "Sans Serif"

    @classmethod
    def make(cls, size: int = 9, bold: bool = False, mono: bool = True) -> QFont:
        f = QFont(cls.mono if mono else cls.ui)
        f.setPointSize(size)
        f.setBold(bold)
        if mono:
            f.setStyleHint(QFont.StyleHint.Monospace)
            f.setFixedPitch(True)
        return f

    # Same size scale as the Tk version
    @classmethod
    def mono_sm(cls) -> QFont:
        return cls.make(9)

    @classmethod
    def mono_md(cls) -> QFont:
        return cls.make(10)

    @classmethod
    def mono_lg(cls) -> QFont:
        return cls.make(12)

    @classmethod
    def title(cls) -> QFont:
        return cls.make(16, bold=True)

    @classmethod
    def stat(cls) -> QFont:
        return cls.make(22, bold=True)

    @classmethod
    def tiny(cls) -> QFont:
        return cls.make(8)


def init_fonts() -> None:
    """Pick installed font families (Consolas / Segoe UI don't exist on Linux/macOS)."""
    families = set(QFontDatabase.families())
    fixed = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont).family()
    general = QFontDatabase.systemFont(QFontDatabase.SystemFont.GeneralFont).family()
    Fonts.mono = next((f for f in _MONO_CANDIDATES if f in families), fixed)
    Fonts.ui = next((f for f in _UI_CANDIDATES if f in families), general)


def stylesheet() -> str:
    """Global Qt stylesheet reproducing the dark ttk 'clam' theme of the Tk build.

    Fonts are deliberately *not* set here (a stylesheet font would override every
    widget's setFont()); the application default font is set in ``main()`` instead.
    """
    down, up = asset("arrow_down_accent.svg"), asset("arrow_up_accent.svg")
    down_off, up_off = asset("arrow_down_disabled.svg"), asset("arrow_up_disabled.svg")
    return f"""
* {{
    color: {C["text"]};
    outline: 0;
}}
QMainWindow, QDialog {{ background: {C["bg"]}; }}
QToolTip {{
    background: {C["surface2"]}; color: {C["text"]};
    border: 1px solid {C["border2"]}; padding: 4px;
}}

/* ── Containers (objectName based) ── */
QFrame#topbar, QFrame#statusbar {{ background: {C["header_bg"]}; }}
QFrame#bg {{ background: {C["bg"]}; }}
QFrame#surface {{ background: {C["surface"]}; }}
QFrame#surface2 {{ background: {C["surface2"]}; }}
QFrame#sectionHeader {{ background: {C["accent_dim"]}; }}
QFrame#sectionBody {{ background: {C["surface2"]}; border: 1px solid {C["border"]}; }}
QFrame#vsep {{ background: {C["border"]}; }}
QFrame#hline {{ background: {C["border"]}; }}
QLabel {{ background: transparent; }}

/* ── Splitters ── */
QSplitter::handle {{ background: {C["border"]}; }}
QSplitter::handle:horizontal {{ width: 4px; }}
QSplitter::handle:vertical {{ height: 4px; }}
QSplitter#thin::handle:horizontal {{ width: 3px; }}

/* ── Scroll areas & scrollbars ── */
QScrollArea {{ background: {C["surface"]}; border: none; }}
QScrollArea > QWidget > QWidget#leftContent {{ background: {C["surface"]}; }}
QScrollBar:vertical {{ background: {C["bg"]}; width: 10px; margin: 0; border: none; }}
QScrollBar:horizontal {{ background: {C["bg"]}; height: 10px; margin: 0; border: none; }}
QScrollBar::handle {{ background: {C["border2"]}; min-height: 24px; min-width: 24px; }}
QScrollBar::handle:hover {{ background: {C["accent2"]}; }}
QScrollBar::handle:pressed {{ background: {C["accent"]}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; border: none; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}
QAbstractScrollArea::corner {{ background: {C["bg"]}; }}

/* ── Text inputs ── */
QPlainTextEdit#input, QLineEdit {{
    background: {C["input_bg"]};
    color: {C["text"]};
    border: 1px solid {C["border2"]};
    padding: 4px 6px;
    selection-background-color: {C["select"]};
    selection-color: {C["white"]};
}}
QPlainTextEdit#input:focus, QLineEdit:focus {{ border: 1px solid {C["accent2"]}; }}

/* ── Read-only text panes ── */
QPlainTextEdit#pane {{
    background: {C["bg"]};
    color: {C["text"]};
    border: 1px solid {C["border"]};
    selection-background-color: {C["select"]};
    selection-color: {C["white"]};
}}
QPlainTextEdit#paneFlat {{
    background: {C["bg"]};
    color: {C["text"]};
    border: none;
    selection-background-color: {C["select"]};
    selection-color: {C["white"]};
}}

/* ── Tables / trees / lists ── */
QTableView, QTreeWidget {{
    background: {C["row_even"]};
    alternate-background-color: {C["row_odd"]};
    color: {C["text"]};
    border: none;
    gridline-color: {C["border"]};
    selection-background-color: {C["select"]};
    selection-color: {C["white"]};
}}
QTableView::item, QTreeWidget::item {{ padding: 0 6px; border: none; }}
QTableView::item:selected, QTreeWidget::item:selected {{
    background: {C["select"]}; color: {C["white"]};
}}
QHeaderView {{ background: {C["header_bg"]}; border: none; }}
QHeaderView::section {{
    background: {C["header_bg"]};
    color: {C["accent"]};
    border: none;
    padding: 5px 6px;
}}
QHeaderView::section:hover {{ background: {C["border"]}; color: {C["white"]}; }}
QListWidget {{
    background: {C["surface2"]};
    border: none;
    selection-background-color: {C["select"]};
}}
QListWidget::item {{ padding: 2px 4px; }}
QListWidget::item:selected {{ background: {C["select"]}; color: {C["white"]}; }}

/* ── Progress bar ── */
QProgressBar {{
    background: {C["surface2"]};
    border: none;
    max-height: 8px; min-height: 8px;
}}
QProgressBar::chunk {{ background: {C["accent"]}; }}

/* ── Tabs (outer notebook) ── */
QTabWidget::pane {{ border: none; background: {C["surface"]}; top: 0; }}
QTabWidget#outer > QTabBar {{ background: {C["bg"]}; }}
QTabBar::tab {{
    background: {C["surface2"]};
    color: {C["text2"]};
    padding: 7px 14px;
    border: none;
    border-top: 2px solid transparent;
    margin-right: 1px;
    margin-top: 4px;
}}
QTabBar::tab:hover {{ background: {C["border"]}; color: {C["text"]}; }}
QTabBar::tab:selected {{
    background: {C["surface"]};
    color: {C["accent"]};
    border-top: 2px solid {C["accent"]};
    margin-top: 2px;
}}

QTabBar {{ qproperty-drawBase: 0; background: transparent; }}
QTabBar QToolButton {{ background: {C["surface2"]}; border: none; }}
QTabBar QToolButton:hover {{ background: {C["btn_hover"]}; }}

/* ── Tabs (inner settings notebook) ── */
QTabWidget#inner::pane {{ background: {C["surface2"]}; border: none; }}
QTabWidget#inner QTabBar::tab {{
    background: {C["input_bg"]};
    padding: 5px 10px;
    margin-top: 0;
}}
QTabWidget#inner QTabBar::tab:selected {{
    background: {C["surface2"]};
    color: {C["accent"]};
    border-top: 2px solid {C["accent"]};
}}
QTabWidget#inner QTabBar::tab:hover:!selected {{ background: {C["border"]}; color: {C["text"]}; }}
QWidget#innerPage {{ background: {C["surface2"]}; }}

/* ── Combobox ── */
QComboBox {{
    background: {C["input_bg"]};
    color: {C["text"]};
    border: 1px solid {C["border2"]};
    padding: 2px 6px;
    min-height: 18px;
}}
QComboBox:hover {{ background: {C["btn_hover"]}; }}
QComboBox:focus {{ border: 1px solid {C["accent2"]}; }}
QComboBox::drop-down {{
    subcontrol-origin: padding; subcontrol-position: center right;
    width: 18px; border: none; background: {C["btn_bg"]};
}}
QComboBox::down-arrow {{ image: url({down}); width: 9px; height: 9px; }}
QComboBox::down-arrow:disabled {{ image: url({down_off}); }}
QComboBox QAbstractItemView {{
    background: {C["surface2"]};
    color: {C["text"]};
    border: 1px solid {C["border2"]};
    selection-background-color: {C["select"]};
    selection-color: {C["white"]};
    outline: 0;
}}

/* ── Spinboxes ── */
QSpinBox, QDoubleSpinBox {{
    background: {C["input_bg"]};
    color: {C["text"]};
    border: 1px solid {C["border2"]};
    padding: 1px 4px;
    min-height: 18px;
}}
QSpinBox:focus, QDoubleSpinBox:focus {{ border: 1px solid {C["accent2"]}; }}
QSpinBox::up-button, QDoubleSpinBox::up-button,
QSpinBox::down-button, QDoubleSpinBox::down-button {{
    background: {C["btn_bg"]}; border: none; width: 14px;
}}
QSpinBox::up-button:hover, QDoubleSpinBox::up-button:hover,
QSpinBox::down-button:hover, QDoubleSpinBox::down-button:hover {{ background: {C["btn_hover"]}; }}
QSpinBox::up-arrow, QDoubleSpinBox::up-arrow {{ image: url({up}); width: 7px; height: 7px; }}
QSpinBox::down-arrow, QDoubleSpinBox::down-arrow {{ image: url({down}); width: 7px; height: 7px; }}
QSpinBox::up-arrow:disabled, QSpinBox::up-arrow:off,
QDoubleSpinBox::up-arrow:disabled, QDoubleSpinBox::up-arrow:off {{ image: url({up_off}); }}
QSpinBox::down-arrow:disabled, QSpinBox::down-arrow:off,
QDoubleSpinBox::down-arrow:disabled, QDoubleSpinBox::down-arrow:off {{ image: url({down_off}); }}

/* ── Check boxes & radio buttons ── */
QCheckBox, QRadioButton {{ background: transparent; color: {C["text"]}; spacing: 6px; padding: 2px; }}
QCheckBox:hover, QRadioButton:hover {{ color: {C["white"]}; }}
QCheckBox:disabled, QRadioButton:disabled {{ color: {C["disabled"]}; }}
QCheckBox::indicator, QRadioButton::indicator {{
    width: 11px; height: 11px;
    background: {C["input_bg"]};
    border: 1px solid {C["border2"]};
}}
QRadioButton::indicator {{ border-radius: 6px; }}
QCheckBox::indicator:hover, QRadioButton::indicator:hover {{ background: {C["btn_hover"]}; }}
QCheckBox::indicator:checked {{ background: {C["accent"]}; border: 1px solid {C["accent_dim"]}; }}
QRadioButton::indicator:checked {{
    background: qradialgradient(cx:0.5, cy:0.5, radius:0.5, fx:0.5, fy:0.5,
        stop:0 {C["accent"]}, stop:0.45 {C["accent"]}, stop:0.55 {C["input_bg"]}, stop:1 {C["input_bg"]});
    border: 1px solid {C["accent2"]};
}}
QRadioButton::indicator:disabled, QCheckBox::indicator:disabled {{ background: {C["bg"]}; border-color: {C["disabled"]}; }}
QRadioButton#logFilter::indicator {{ width: 9px; height: 9px; }}
QRadioButton#logFilter {{ color: {C["text2"]}; }}
QRadioButton#logFilter:checked {{ color: {C["accent"]}; }}

/* ── Menus ── */
QMenu {{
    background: {C["surface2"]};
    color: {C["text"]};
    border: 1px solid {C["border2"]};
    padding: 2px;
}}
QMenu::item {{ padding: 5px 18px; }}
QMenu::item:selected {{ background: {C["select"]}; color: {C["white"]}; }}
QMenu::separator {{ height: 1px; background: {C["border2"]}; margin: 3px 6px; }}

/* ── Message boxes / file dialogs ── */
QMessageBox {{ background: {C["surface"]}; }}
QMessageBox QLabel {{ color: {C["text"]}; }}
QPushButton {{
    background: {C["btn_bg"]};
    color: {C["text"]};
    border: 1px solid {C["border2"]};
    padding: 5px 14px;
    min-width: 60px;
}}
QPushButton:hover {{ background: {C["btn_hover"]}; }}
QPushButton:default {{ border: 1px solid {C["accent2"]}; }}
QPushButton:disabled {{ color: {C["disabled"]}; }}
"""
