"""
NexScan GUI — reusable themed widgets.

Qt counterparts of the hand-styled Tk widgets used by the original GUI:
flat buttons, section cards, stat tiles, colour-tagged read-only text panes
and the bottom-right toast notification.
"""

from __future__ import annotations

from typing import Callable, Optional

from PyQt6.QtCore import QEvent, QObject, Qt, QTimer, QUrl
from PyQt6.QtGui import QColor, QDesktopServices, QFont, QMouseEvent, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from gui.theme import C, Fonts


def frame(name: str = "", parent: Optional[QWidget] = None) -> QFrame:
    """A plain QFrame whose background comes from the stylesheet via *name*."""
    f = QFrame(parent)
    if name:
        f.setObjectName(name)
    return f


def hbox(widget: Optional[QWidget] = None, margins=(0, 0, 0, 0), spacing: int = 0) -> QHBoxLayout:
    lay = QHBoxLayout(widget) if widget is not None else QHBoxLayout()
    lay.setContentsMargins(*margins)
    lay.setSpacing(spacing)
    return lay


def vbox(widget: Optional[QWidget] = None, margins=(0, 0, 0, 0), spacing: int = 0) -> QVBoxLayout:
    lay = QVBoxLayout(widget) if widget is not None else QVBoxLayout()
    lay.setContentsMargins(*margins)
    lay.setSpacing(spacing)
    return lay


def label(
    text: str = "",
    fg: str = "",
    font: Optional[QFont] = None,
    parent: Optional[QWidget] = None,
    wrap: bool = False,
    align: Optional[Qt.AlignmentFlag] = None,
) -> QLabel:
    lbl = QLabel(text, parent)
    if font is not None:
        lbl.setFont(font)
    if fg:
        set_fg(lbl, fg)
    if wrap:
        lbl.setWordWrap(True)
    if align is not None:
        lbl.setAlignment(align)
    return lbl


def set_fg(widget: QWidget, color: str) -> None:
    """Change a label's text colour (keeps a transparent background)."""
    widget.setStyleSheet(f"color: {color}; background: transparent;")


def vsep(parent: Optional[QWidget] = None, width: int = 1) -> QFrame:
    sep = frame("vsep", parent)
    sep.setFixedWidth(width)
    return sep


def hline(parent: Optional[QWidget] = None, height: int = 1) -> QFrame:
    line = frame("hline", parent)
    line.setFixedHeight(height)
    return line


# ─────────────────────────── FLAT BUTTON ───────────────────────────


class FlatButton(QPushButton):
    """Flat button with hover and disabled colours; does not take keyboard focus."""

    def __init__(
        self,
        text: str,
        command: Callable,
        fg: str = "",
        bg: str = "",
        hover_bg: str = "",
        pad: tuple[int, int] = (12, 6),
        parent: Optional[QWidget] = None,
    ):
        super().__init__(text, parent)
        self._fg = fg or C["text"]
        self._bg = bg or C["btn_bg"]
        self._hover_bg = hover_bg or C["btn_hover"]
        self._pad = pad
        self.setFont(Fonts.mono_sm())
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.clicked.connect(lambda _checked=False: command())
        self._restyle()

    def _restyle(self):
        px, py = self._pad
        self.setStyleSheet(
            f"QPushButton {{ background: {self._bg}; color: {self._fg}; border: none;"
            f" padding: {py}px {px}px; min-width: 0; }}"
            f"QPushButton:hover {{ background: {self._hover_bg}; }}"
            f"QPushButton:disabled {{ color: {C['disabled']}; background: {self._bg}; }}"
        )

    def set_enabled(self, enabled: bool):
        self.setEnabled(enabled)
        self.setCursor(Qt.CursorShape.PointingHandCursor if enabled else Qt.CursorShape.ArrowCursor)

    def set_text(self, text: str, fg: str = ""):
        if fg:
            self._fg = fg
            self._restyle()
        self.setText(text)


# ─────────────────────────── SECTION CARD ───────────────────────────


class Section(QFrame):
    """Left-panel section: accent header strip + bordered content body.

    Add children to :attr:`body` (a QVBoxLayout).
    """

    def __init__(self, title: str, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("surface")
        outer = vbox(self, spacing=1)

        hdr = frame("sectionHeader")
        hl = hbox(hdr)
        bar = QFrame()
        bar.setFixedWidth(3)
        bar.setStyleSheet(f"background: {C['accent']};")
        hl.addWidget(bar)
        title_lbl = label(f" {title}", C["accent"], Fonts.mono_sm())
        title_lbl.setContentsMargins(2, 3, 0, 3)
        hl.addWidget(title_lbl, 1)
        outer.addWidget(hdr)

        content = frame("sectionBody")
        self.body = vbox(content, margins=(8, 5, 8, 6), spacing=4)
        outer.addWidget(content)


# ─────────────────────────── STAT CARD ───────────────────────────


class StatCard(QFrame):
    """Big coloured number with a caption, topped by a 2px colour strip."""

    def __init__(self, caption: str, color: str, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("surface2")
        lay = vbox(self)
        self.strip = QFrame()
        self.strip.setFixedHeight(2)
        self.strip.setStyleSheet(f"background: {color};")
        lay.addWidget(self.strip)
        lay.addSpacing(6)
        self.value = label("0", color, Fonts.stat(), align=Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(self.value)
        self.caption = label(
            caption, C["text3"], Fonts.mono_sm(), align=Qt.AlignmentFlag.AlignCenter
        )
        lay.addWidget(self.caption)
        lay.addStretch(1)
        self._int = 0

    def set_value(self, value: int):
        self._int = int(value)
        self.value.setText(str(self._int))

    def get(self) -> int:
        return self._int


# ─────────────────────────── TAGGED TEXT ───────────────────────────


class TaggedText(QPlainTextEdit):
    """Read-only text pane with named colour 'tags', like a Tk Text widget.

    ``tag_configure("open", fg=C["green"])`` then ``write("text", "open")``.
    Tags marked ``link=True`` are clickable and open their text as a URL.
    """

    def __init__(
        self,
        parent: Optional[QWidget] = None,
        wrap: bool = False,
        bordered: bool = True,
        padding: tuple[int, int] = (12, 8),
        max_lines: int = 0,
    ):
        super().__init__(parent)
        self.setObjectName("pane" if bordered else "paneFlat")
        self.setReadOnly(True)
        self.setFont(Fonts.mono_sm())
        self.setLineWrapMode(
            QPlainTextEdit.LineWrapMode.WidgetWidth if wrap else QPlainTextEdit.LineWrapMode.NoWrap
        )
        self.document().setDocumentMargin(0)
        self.setViewportMargins(padding[0], padding[1], padding[0], padding[1])
        self.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        if max_lines:
            self.setMaximumBlockCount(max_lines)
        self._tags: dict[str, QTextCharFormat] = {}
        self._link_tags: set[str] = set()
        self.viewport().setMouseTracking(True)
        self.viewport().setCursor(Qt.CursorShape.ArrowCursor)
        self.setFrameShape(QFrame.Shape.NoFrame)

    def tag_configure(
        self,
        name: str,
        fg: str = "",
        font: Optional[QFont] = None,
        bold: bool = False,
        underline: bool = False,
        link: bool = False,
    ):
        fmt = QTextCharFormat()
        if fg:
            fmt.setForeground(QColor(fg))
        if font is not None:
            fmt.setFont(font)
        if bold:
            fmt.setFontWeight(QFont.Weight.Bold)
        if underline or link:
            fmt.setFontUnderline(True)
        self._tags[name] = fmt
        if link:
            self._link_tags.add(name)

    def write(self, text: str, tag: Optional[str] = None):
        cursor = QTextCursor(self.document())
        cursor.movePosition(QTextCursor.MoveOperation.End)
        fmt = QTextCharFormat(self._tags[tag]) if tag in self._tags else QTextCharFormat()
        if tag in self._link_tags:
            fmt.setAnchor(True)
            fmt.setAnchorHref(text.strip())
        cursor.insertText(text, fmt)

    def clear_text(self):
        self.clear()

    def scroll_to_end(self):
        sb = self.verticalScrollBar()
        sb.setValue(sb.maximum())

    def scroll_to_top(self):
        self.verticalScrollBar().setValue(0)

    # Clickable links
    def mouseMoveEvent(self, event: QMouseEvent):
        href = self.anchorAt(event.pos())
        self.viewport().setCursor(
            Qt.CursorShape.PointingHandCursor if href else Qt.CursorShape.ArrowCursor
        )
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent):
        href = self.anchorAt(event.pos())
        if (
            href
            and href.startswith("http")
            and event.button() == Qt.MouseButton.LeftButton
            and not self.textCursor().hasSelection()
        ):
            QDesktopServices.openUrl(QUrl(href))
        super().mouseReleaseEvent(event)


# ─────────────────────────── TOAST ───────────────────────────


class Toast(QLabel):
    """Non-blocking notification pinned to the bottom-right corner of *host*."""

    _KINDS = {
        "ok": ("green", "green_dim", "✓"),
        "warn": ("yellow", "yellow_dim", "!"),
        "error": ("red", "red_dim", "✗"),
        "info": ("accent", "accent_dim", "◈"),
    }

    def __init__(self, host: QWidget):
        super().__init__(host)
        self._host = host
        self.setFont(Fonts.mono_sm())
        self.hide()
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.hide)
        host.installEventFilter(self)

    def show_message(self, message: str, kind: str = "info", ms: int = 3200):
        fg, bg, icon = self._KINDS.get(kind, self._KINDS["info"])
        self.setText(f"  {icon}  {message}  ")
        self.setStyleSheet(
            f"background: {C[bg]}; color: {C[fg]}; border: 1px solid {C[fg]}; padding: 8px 6px;"
        )
        self.adjustSize()
        self._reposition()
        self.show()
        self.raise_()
        self._timer.start(ms)

    def _reposition(self):
        x = self._host.width() - self.width() - 18
        y = self._host.height() - self.height() - 36
        self.move(max(0, x), max(0, y))

    def mousePressEvent(self, _event):
        self.hide()

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:
        if obj is self._host and event.type() == QEvent.Type.Resize and self.isVisible():
            self._reposition()
        return False
