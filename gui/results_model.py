"""
NexScan GUI — table model backing the Results tab.

Replaces the ttk.Treeview: rows are (key, target, PortResult, tag) tuples where
*tag* is the state colour ("open", "filtered", "closed", "warn").
"""

from __future__ import annotations

from typing import Any, Optional

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PyQt6.QtGui import QColor

from core.scanner import PortResult
from gui.theme import C

COLUMNS = ("host", "port", "proto", "state", "service", "version", "rtt", "banner")
COLUMN_LABELS = ("Host", "Port", "Proto", "State", "Service", "Version", "RTT ms", "Banner")
COLUMN_WIDTHS = (130, 60, 55, 80, 110, 140, 70, 200)
_CENTERED = {"port", "proto", "rtt"}

_TAG_COLORS = {
    "open": QColor(C["green"]),
    "filtered": QColor(C["yellow"]),
    "closed": QColor(C["text3"]),
    "warn": QColor(C["orange"]),
}


def row_key(target: str, pr: PortResult) -> str:
    return f"{target}|{pr.protocol}|{pr.port}"


def row_values(target: str, pr: PortResult) -> tuple:
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


class ResultsModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows: list[tuple[str, str, PortResult, str, tuple]] = []
        self._index: dict[str, int] = {}
        self._sort: Optional[tuple[str, bool]] = None  # for heading arrows

    # ── Qt model API ──
    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(COLUMNS)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        key, _target, _pr, tag, values = self._rows[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            return str(values[index.column()])
        if role == Qt.ItemDataRole.ForegroundRole:
            return _TAG_COLORS.get(tag)
        if role == Qt.ItemDataRole.TextAlignmentRole:
            if COLUMNS[index.column()] in _CENTERED:
                return Qt.AlignmentFlag.AlignCenter
            return Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft
        if role == Qt.ItemDataRole.UserRole:
            return key
        return None

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ):
        if orientation != Qt.Orientation.Horizontal:
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            text = COLUMN_LABELS[section]
            if self._sort and self._sort[0] == COLUMNS[section]:
                text += "  ▼" if self._sort[1] else "  ▲"
            return text
        if role == Qt.ItemDataRole.TextAlignmentRole:
            if COLUMNS[section] in _CENTERED:
                return Qt.AlignmentFlag.AlignCenter
            return Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft
        return None

    # ── NexScan API ──
    def set_sort_indicator(self, sort: Optional[tuple[str, bool]]):
        self._sort = sort
        self.headerDataChanged.emit(Qt.Orientation.Horizontal, 0, len(COLUMNS) - 1)

    def set_rows(self, rows: list[tuple[str, PortResult, str]]):
        """Replace all rows with (target, PortResult, tag) triples (already filtered/sorted)."""
        self.beginResetModel()
        self._rows = [(row_key(t, p), t, p, tag, row_values(t, p)) for t, p, tag in rows]
        self._index = {r[0]: i for i, r in enumerate(self._rows)}
        self.endResetModel()

    def append_row(self, target: str, pr: PortResult, tag: str) -> bool:
        key = row_key(target, pr)
        if key in self._index:
            return False
        n = len(self._rows)
        self.beginInsertRows(QModelIndex(), n, n)
        self._rows.append((key, target, pr, tag, row_values(target, pr)))
        self._index[key] = n
        self.endInsertRows()
        return True

    def clear(self):
        self.set_rows([])

    def key_at(self, row: int) -> Optional[str]:
        if 0 <= row < len(self._rows):
            return self._rows[row][0]
        return None

    def values_at(self, row: int) -> tuple:
        return self._rows[row][4]

    def all_values(self) -> list[tuple]:
        return [r[4] for r in self._rows]
