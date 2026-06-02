"""Simple SQLite persistence for scan runs."""

import json
import sqlite3
import datetime
from typing import Iterable, List, Tuple


def _ensure_db(path: str):
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            data TEXT NOT NULL
        )
        """)
    conn.commit()
    conn.close()


def save_scan_results(path: str, results: Iterable[object]):
    _ensure_db(path)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    payload = json.dumps([r.to_dict() for r in results])
    cur.execute(
        "INSERT INTO scan_runs (ts, data) VALUES (?, ?)",
        (datetime.datetime.now().isoformat(), payload),
    )
    conn.commit()
    conn.close()


def fetch_all_runs(path: str) -> List[Tuple[int, str, list]]:
    _ensure_db(path)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("SELECT id, ts, data FROM scan_runs ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    return [(r[0], r[1], json.loads(r[2])) for r in rows]


def fetch_runs_by_target(path: str, target: str) -> List[Tuple[int, str, list]]:
    """Fetch all scans that included a specific target."""
    _ensure_db(path)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("SELECT id, ts, data FROM scan_runs ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()

    results = []
    for row_id, ts, data_json in rows:
        data = json.loads(data_json)
        # Check if any host in results matches target
        if any(h.get("target") == target or h.get("ip_address") == target for h in data):
            results.append((row_id, ts, data))

    return results


def fetch_runs_by_date_range(
    path: str, start_date: str, end_date: str
) -> List[Tuple[int, str, list]]:
    """Fetch scans within a date range (ISO format: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)."""
    _ensure_db(path)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute(
        "SELECT id, ts, data FROM scan_runs WHERE ts BETWEEN ? AND ? ORDER BY ts DESC",
        (start_date, end_date),
    )
    rows = cur.fetchall()
    conn.close()
    return [(r[0], r[1], json.loads(r[2])) for r in rows]


def fetch_run_by_id(path: str, run_id: int) -> Tuple[int, str, list]:
    """Fetch a specific scan run by ID."""
    _ensure_db(path)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("SELECT id, ts, data FROM scan_runs WHERE id = ?", (run_id,))
    row = cur.fetchone()
    conn.close()
    if row:
        return (row[0], row[1], json.loads(row[2]))
    return None


def get_timeline_summary(path: str, limit: int = 10) -> List[dict]:
    """Get summary of recent scan runs for timeline display."""
    _ensure_db(path)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("SELECT id, ts, data FROM scan_runs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()

    summaries = []
    for row_id, ts, data_json in rows:
        data = json.loads(data_json)
        total_hosts = len(data)
        total_open = sum(h.get("open_count", 0) for h in data)
        hosts_up = sum(1 for h in data if h.get("host_up"))

        summaries.append(
            {
                "id": row_id,
                "timestamp": ts,
                "hosts_scanned": total_hosts,
                "hosts_up": hosts_up,
                "total_open_ports": total_open,
            }
        )

    return summaries
