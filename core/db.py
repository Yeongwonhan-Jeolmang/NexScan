"""Simple SQLite persistence for scan runs."""

import contextlib
import datetime
import json
import os
import sqlite3
import threading
from typing import Iterable, Iterator, List, Optional, Protocol, Tuple


class _HasToDict(Protocol):
    def to_dict(self) -> dict: ...


# Summary columns kept alongside the JSON payload so listings and target
# searches never need to decode every stored run.
_SUMMARY_COLUMNS = {
    "targets": "TEXT",
    "hosts_scanned": "INTEGER",
    "hosts_up": "INTEGER",
    "open_ports": "INTEGER",
    "scan_type": "TEXT",
}

_ensured: set = set()
_ensure_lock = threading.Lock()


@contextlib.contextmanager
def _connect(path: str) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(path, timeout=10)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _summarize(data: list) -> tuple:
    keys = set()
    for h in data:
        for k in ("target", "ip_address", "hostname"):
            if h.get(k):
                keys.add(str(h[k]))
    targets = "|" + "|".join(sorted(keys)) + "|" if keys else ""
    hosts_up = sum(1 for h in data if h.get("host_up"))
    open_ports = sum(h.get("open_count", 0) for h in data)
    scan_type = data[0].get("scan_type", "") if data else ""
    return targets, len(data), hosts_up, open_ports, scan_type


def _db_key(path: str) -> tuple:
    try:
        st = os.stat(path)
        return (os.path.abspath(path), st.st_dev, st.st_ino)
    except OSError:
        return (os.path.abspath(path), None, None)


def _ensure_db(path: str):
    with _ensure_lock:
        if _db_key(path) in _ensured:
            return
        with _connect(path) as conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scan_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    data TEXT NOT NULL
                )
                """)
            existing = {row[1] for row in cur.execute("PRAGMA table_info(scan_runs)")}
            for col, col_type in _SUMMARY_COLUMNS.items():
                if col not in existing:
                    cur.execute(f"ALTER TABLE scan_runs ADD COLUMN {col} {col_type}")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_runs_ts ON scan_runs(ts)")

            # Backfill summaries for runs saved by older versions
            stale = cur.execute(
                "SELECT id, data FROM scan_runs WHERE hosts_scanned IS NULL"
            ).fetchall()
            for row_id, data_json in stale:
                try:
                    summary = _summarize(json.loads(data_json))
                except (ValueError, TypeError, AttributeError):
                    summary = ("", 0, 0, 0, "")
                cur.execute(
                    "UPDATE scan_runs SET targets=?, hosts_scanned=?, hosts_up=?, open_ports=?, "
                    "scan_type=? WHERE id=?",
                    (*summary, row_id),
                )
        _ensured.add(_db_key(path))


def save_scan_results(path: str, results: Iterable[_HasToDict]) -> int:
    """Persist a scan run. Returns the new run ID."""
    _ensure_db(path)
    data = [r.to_dict() for r in results]
    with _connect(path) as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO scan_runs (ts, data, targets, hosts_scanned, hosts_up, open_ports, "
            "scan_type) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (datetime.datetime.now().isoformat(), json.dumps(data), *_summarize(data)),
        )
        return int(cur.lastrowid or 0)


def fetch_all_runs(path: str) -> List[Tuple[int, str, list]]:
    _ensure_db(path)
    with _connect(path) as conn:
        rows = conn.execute("SELECT id, ts, data FROM scan_runs ORDER BY id DESC").fetchall()
    return [(r[0], r[1], json.loads(r[2])) for r in rows]


def fetch_runs_by_target(path: str, target: str) -> List[Tuple[int, str, list]]:
    """Fetch all scans that included a specific target (name, IP or rDNS)."""
    _ensure_db(path)
    with _connect(path) as conn:
        rows = conn.execute(
            "SELECT id, ts, data FROM scan_runs WHERE instr(targets, ?) > 0 ORDER BY id DESC",
            (f"|{target}|",),
        ).fetchall()
    return [(r[0], r[1], json.loads(r[2])) for r in rows]


def _normalize_end(end_date: str) -> str:
    # A bare date ("2026-11-05") should include the whole day
    if len(end_date) == 10:
        return end_date + "T23:59:59.999999"
    return end_date


def fetch_runs_by_date_range(
    path: str, start_date: str, end_date: str
) -> List[Tuple[int, str, list]]:
    """Fetch scans within a date range (ISO format: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)."""
    _ensure_db(path)
    with _connect(path) as conn:
        rows = conn.execute(
            "SELECT id, ts, data FROM scan_runs WHERE ts BETWEEN ? AND ? ORDER BY ts DESC",
            (start_date, _normalize_end(end_date)),
        ).fetchall()
    return [(r[0], r[1], json.loads(r[2])) for r in rows]


def fetch_run_by_id(path: str, run_id: int) -> Optional[Tuple[int, str, list]]:
    """Fetch a specific scan run by ID."""
    _ensure_db(path)
    with _connect(path) as conn:
        row = conn.execute("SELECT id, ts, data FROM scan_runs WHERE id = ?", (run_id,)).fetchone()
    if row:
        return (row[0], row[1], json.loads(row[2]))
    return None


def delete_run(path: str, run_id: int) -> bool:
    """Delete a scan run. Returns True if a row was removed."""
    _ensure_db(path)
    with _connect(path) as conn:
        cur = conn.execute("DELETE FROM scan_runs WHERE id = ?", (run_id,))
        return cur.rowcount > 0


def get_timeline_summary(
    path: str, limit: int = 10, target: str = "", start_date: str = "", end_date: str = ""
) -> List[dict]:
    """Get summary of recent scan runs for timeline display (optionally filtered)."""
    _ensure_db(path)
    clauses, params = [], []
    if target:
        clauses.append("instr(targets, ?) > 0")
        params.append(f"|{target}|")
    if start_date:
        clauses.append("ts >= ?")
        params.append(start_date)
    if end_date:
        clauses.append("ts <= ?")
        params.append(_normalize_end(end_date))
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    with _connect(path) as conn:
        rows = conn.execute(
            "SELECT id, ts, hosts_scanned, hosts_up, open_ports, scan_type, targets "
            f"FROM scan_runs {where} ORDER BY id DESC LIMIT ?",
            (*params, limit),
        ).fetchall()

    return [
        {
            "id": row_id,
            "timestamp": ts,
            "hosts_scanned": hosts or 0,
            "hosts_up": up or 0,
            "total_open_ports": open_ports or 0,
            "scan_type": scan_type or "",
            "targets": [t for t in (targets or "").split("|") if t],
        }
        for row_id, ts, hosts, up, open_ports, scan_type, targets in rows
    ]
