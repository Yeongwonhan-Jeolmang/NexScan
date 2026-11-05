#!/usr/bin/env python3
"""
NexScan v3.0 — Advanced Port Scanner
Entry point. Run this file to launch the GUI.

Usage:
    python nexscan.py
    python nexscan.py --cli -t 192.168.1.1 -p 1-1024

Keyboard shortcuts:
    F5          Start scan
    Escape      Stop scan
    Ctrl+E      Export menu
    Ctrl+L      Clear results
    Ctrl+F      Focus filter
"""

import argparse
import os
import sys
import threading
import time

# Ensure local packages are importable (must run before any local import)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.logger import get_logger  # noqa: E402

logger = get_logger(__name__)

SCAN_TYPE_CHOICES = ["tcp", "udp", "syn", "ack", "fin", "xmas", "null", "window"]


def launch_gui():
    """Launch the full GUI application"""
    try:
        import tkinter as tk

        tk.Tk().destroy()  # Quick test
    except Exception as e:
        print(f"[!] Tkinter not available: {e}", file=sys.stderr)
        print("    Install: sudo apt-get install python3-tk", file=sys.stderr)
        sys.exit(1)

    from gui.app import main

    main()


def _resolve_ports(port_arg: str) -> str:
    """Allow preset names (e.g. 'top100', 'web', 'database') in place of a port list."""
    from core.service_db import ServiceDatabase

    db = ServiceDatabase()
    wanted = port_arg.replace(" ", "").replace("-", "").replace("_", "").lower()
    for name in db.get_presets():
        key = "".join(ch for ch in name.lower() if ch.isalnum())
        if wanted and key.startswith(wanted) and not wanted.isdigit():
            return ",".join(str(p) for p in db.get_preset_ports(name))
    return port_arg


class _ProgressLine:
    """Single-line progress indicator on stderr (TTY only)."""

    def __init__(self, enabled: bool):
        self.enabled = enabled and sys.stderr.isatty()
        self.start = time.time()
        self._last = 0.0

    def update(self, done, total, target, *_):
        if not self.enabled or not total:
            return
        now = time.time()
        if now - self._last < 0.1 and done < total:
            return
        self._last = now
        pct = done / total
        elapsed = now - self.start
        eta = (elapsed / done) * (total - done) if done else 0
        bar = "█" * int(pct * 24) + "░" * (24 - int(pct * 24))
        sys.stderr.write(
            f"\r  {bar} {pct:5.1%}  {done:,}/{total:,}  ETA {int(eta)}s  {target[:28]:<28}"
        )
        sys.stderr.flush()

    def clear(self):
        if self.enabled:
            sys.stderr.write("\r" + " " * 96 + "\r")
            sys.stderr.flush()


def run_cli(args):
    """CLI scan mode with support for new features."""
    from core import engine
    from core.exceptions import NexScanError
    from core.scanner import PortScanner, PortState, ScanConfig, ScanType

    # History queries don't need targets
    if args.timeline:
        _handle_timeline_query(args)
        return
    if args.diff:
        _handle_diff(args)
        return

    # Load targets from file or CLI arg
    targets_str = args.targets
    if args.target_file:
        try:
            with open(args.target_file, "r", encoding="utf-8") as f:
                file_targets = [
                    line.split("#", 1)[0].strip() for line in f if line.split("#", 1)[0].strip()
                ]
            targets_str = ",".join(filter(None, [targets_str, *file_targets]))
            logger.info(f"Loaded {len(file_targets)} target line(s) from {args.target_file}")
        except OSError as e:
            logger.error(f"Failed to load target file: {e}")
            sys.exit(1)

    try:
        targets = engine.validate_targets(targets_str)
        ports = engine.validate_ports(_resolve_ports(args.ports))
    except NexScanError as e:
        logger.error(f"Invalid input: {e}")
        sys.exit(1)

    scan_type_map = {
        "tcp": ScanType.TCP_CONNECT,
        "udp": ScanType.UDP,
        "syn": ScanType.SYN_STEALTH,
        "ack": ScanType.ACK,
        "fin": ScanType.FIN,
        "xmas": ScanType.XMAS,
        "null": ScanType.NULL,
        "window": ScanType.WINDOW,
    }
    stype = scan_type_map.get(args.scan_type.lower(), ScanType.TCP_CONNECT)

    config = ScanConfig(
        targets=targets,
        ports=ports,
        scan_type=stype,
        threads=args.threads,
        timeout=args.timeout,
        connect_timeout=args.timeout,
        grab_banners=not args.no_banner,
        detect_service=True,
        detect_os=args.os_detect,
        host_discovery=not args.skip_discovery,
        rate_limit=args.rate_limit / 1000.0,
        jitter=args.jitter,
        retry_count=args.retries,
        reverse_dns=not args.no_rdns,
    )

    logger.info("NexScan v3.0 — CLI Mode")
    logger.info(f"Targets: {len(targets)}  Ports: {len(ports)}  Type: {stype.value}")
    logger.info(f"Threads: {config.threads}  Timeout: {config.timeout}s")

    progress = _ProgressLine(enabled=not args.quiet)
    print_lock = threading.Lock()

    def on_port(target, pr):
        if pr.state == PortState.OPEN:
            banner = f"  [{pr.banner.splitlines()[0][:50]}]" if pr.banner else ""
            with print_lock:
                progress.clear()
                print(
                    f"  {target}:{pr.port}/{pr.protocol:<4} OPEN  {pr.service:<18} "
                    f"{pr.version[:25]}{banner}"
                )

    def on_host(result):
        status = "UP" if result.host_up else "DOWN"
        if not result.host_up and args.quiet:
            return
        with print_lock:
            progress.clear()
            print(
                f"\n[+] {result.target} ({result.ip_address}) — {status}  "
                f"Open:{result.open_count} Filt:{result.filtered_count}  "
                f"Time:{result.scan_duration:.2f}s"
            )
            if result.extra.get("error"):
                print(f"    ! {result.extra['error']}")
            if result.os_guess and result.os_guess != "Unknown":
                print(f"    OS: {result.os_guess} ({result.os_confidence}%)")

    try:
        engine._check_privileges_for_scan(stype)
    except NexScanError as e:
        logger.error(str(e))
        sys.exit(1)

    scanner = PortScanner(
        config, callback=on_port, host_callback=on_host, progress_callback=progress.update
    )
    holder: dict = {}

    def _worker():
        try:
            holder["results"] = scanner.run()
        except Exception as e:  # surfaced after join
            holder["error"] = e

    worker = threading.Thread(target=_worker, daemon=True)
    worker.start()
    try:
        while worker.is_alive():
            worker.join(0.2)
    except KeyboardInterrupt:
        progress.clear()
        logger.warning("Interrupted — stopping scan and keeping partial results…")
        scanner.stop()
        worker.join()
    progress.clear()

    if "error" in holder:
        logger.error(f"Scan failed: {holder['error']}")
        sys.exit(1)
    results = holder.get("results") or scanner.results

    logger.info("Scan complete." if not scanner.is_stopped() else "Scan stopped (partial).")
    total_open = sum(r.open_count for r in results)
    hosts_up = sum(1 for r in results if r.host_up)
    logger.info(f"Hosts up: {hosts_up}/{len(results)}  Open ports: {total_open}")

    if args.geoloc:
        _print_geolocation(results)
    if args.cve_lookup:
        _print_cves(results)

    if args.output:
        from reports.exporter import exporter_for_path

        content = exporter_for_path(args.output)(results)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info(f"Results saved to {args.output}")

    db_path = args.save_db if isinstance(args.save_db, str) and args.save_db else ""
    if args.compare > 0:
        _compare_with_run(args.db_path if not db_path else db_path, args.compare, results)

    if db_path:
        from core.db import save_scan_results

        try:
            run_id = save_scan_results(db_path, results)
            logger.info(f"Results persisted to {db_path} as run #{run_id}")
        except Exception as e:
            logger.error(f"Failed saving results to DB: {e}")


def _print_geolocation(results):
    from core.geoloc import format_geolocation_report, lookup_geolocation, lookup_whois_simple

    seen = set()
    for r in results:
        if not r.host_up or r.ip_address in seen:
            continue
        seen.add(r.ip_address)
        geo = lookup_geolocation(r.ip_address)
        if geo:
            print(format_geolocation_report(geo, lookup_whois_simple(r.ip_address)))
        else:
            print(f"  ✗ {r.ip_address}: no geolocation (private/reserved or lookup failed)")


def _print_cves(results):
    from core.cve_lookup import build_query, format_cve_report, lookup_service_cves
    from core.scanner import PortState

    # De-duplicate (service, version) pairs across hosts — NVD is rate limited
    services: dict = {}
    for r in results:
        for p in r.ports:
            if p.state == PortState.OPEN and p.service:
                services.setdefault((p.service, p.version), []).append(f"{r.target}:{p.port}")

    print("\n" + "=" * 70 + "\n  VULNERABILITY LOOKUP\n" + "=" * 70)
    for (service, version), where in services.items():
        if not build_query(service, version):
            print(f"  · {service:<16} skipped (no version fingerprint)  [{', '.join(where[:3])}]")
            continue
        cves = lookup_service_cves(service, version, limit=3)
        print(f"\n  {', '.join(where[:4])}{' …' if len(where) > 4 else ''}")
        print(format_cve_report(service, version, cves))


def _handle_timeline_query(args):
    """
    Handle scan history timeline queries.

    Modes:  list | target:<host> | since:<YYYY-MM-DD> | range:<start>..<end>
    """
    from core.db import get_timeline_summary

    mode, _, value = args.timeline.partition(":")
    kwargs: dict = {}
    if mode == "target":
        kwargs["target"] = value
    elif mode == "since":
        kwargs["start_date"] = value
    elif mode == "range":
        start, _, end = value.partition("..")
        kwargs.update(start_date=start, end_date=end)
    elif mode != "list":
        print("Timeline modes: list | target:<host> | since:<date> | range:<start>..<end>")
        sys.exit(2)

    summary = get_timeline_summary(args.db_path, limit=args.limit, **kwargs)
    print("\n" + "=" * 80)
    print("  SCAN HISTORY TIMELINE")
    print("=" * 80)
    if not summary:
        print("  (no matching scans)")
    for entry in summary:
        print(
            f"  [{entry['id']:>4}] {entry['timestamp'][:19]}  {entry['scan_type'] or '-':<12} "
            f"Hosts:{entry['hosts_scanned']:<4} Up:{entry['hosts_up']:<4} "
            f"Open:{entry['total_open_ports']}"
        )
    print("=" * 80 + "\n")


def _compare_with_run(db_path, run_id, results):
    """Compare the scan that just finished against a stored run."""
    from core.compare import compare_scans, generate_diff_report
    from core.db import fetch_run_by_id

    prev_run = fetch_run_by_id(db_path, run_id)
    if not prev_run:
        logger.error(f"Scan run {run_id} not found in {db_path}")
        return
    print(f"\nComparing run #{run_id} ({prev_run[1][:19]}) → current scan\n")
    print(generate_diff_report(compare_scans(prev_run[2], results)))


def _handle_diff(args):
    """Compare two stored runs without scanning."""
    from core.compare import compare_scans, generate_diff_report
    from core.db import fetch_run_by_id

    old_id, new_id = args.diff
    old_run = fetch_run_by_id(args.db_path, old_id)
    new_run = fetch_run_by_id(args.db_path, new_id)
    if not old_run or not new_run:
        logger.error(f"Run {old_id if not old_run else new_id} not found in {args.db_path}")
        sys.exit(1)
    print(f"\nComparing run #{old_id} ({old_run[1][:19]}) → #{new_id} ({new_run[1][:19]})\n")
    print(generate_diff_report(compare_scans(old_run[2], new_run[2])))


def main():
    parser = argparse.ArgumentParser(
        description="NexScan v3.0 — Advanced Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--cli", action="store_true", help="Run in CLI mode (no GUI)")
    parser.add_argument(
        "-t", "--targets", default="", help="Target(s): IP, hostname, CIDR, or range"
    )
    parser.add_argument(
        "-p",
        "--ports",
        default="1-1024",
        help="Port list/range or preset name, e.g. 1-1024, 22,80,443, top100, web",
    )
    parser.add_argument(
        "-s",
        "--scan-type",
        default="tcp",
        choices=SCAN_TYPE_CHOICES,
        help="Scan type (default: tcp). Raw types (syn/ack/fin/xmas/null/window) need root",
    )
    parser.add_argument("--threads", type=int, default=300, help="Number of threads (default: 300)")
    parser.add_argument(
        "--timeout", type=float, default=1.5, help="Socket timeout in seconds (default: 1.5)"
    )
    parser.add_argument(
        "--rate-limit", type=float, default=0.0, help="Minimum ms between probes (default: 0)"
    )
    parser.add_argument("--jitter", type=float, default=0.0, help="Random per-probe delay, ms")
    parser.add_argument(
        "--retries", type=int, default=1, help="Probe attempts for UDP/raw scans (default: 1)"
    )
    parser.add_argument("--no-banner", action="store_true", help="Disable banner grabbing")
    parser.add_argument("--no-rdns", action="store_true", help="Skip reverse DNS lookups")
    parser.add_argument("--os-detect", action="store_true", help="Enable OS detection")
    parser.add_argument("--skip-discovery", action="store_true", help="Skip host discovery")
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Hide progress bar and down hosts"
    )
    parser.add_argument(
        "-o",
        "--output",
        default="",
        help="Output file (extension sets format: .json/.csv/.html/.txt/.xml/.md)",
    )
    parser.add_argument(
        "--save-db",
        nargs="?",
        const="nexscan_history.db",
        default="",
        help="Persist scan run to SQLite DB (optional path)",
    )
    parser.add_argument(
        "-f",
        "--target-file",
        default="",
        help="Read targets from file (one per line, # comments allowed)",
    )
    parser.add_argument(
        "--cve-lookup",
        action="store_true",
        help="Lookup CVEs for fingerprinted services (set NVD_API_KEY for higher rate limit)",
    )
    parser.add_argument(
        "--geoloc",
        action="store_true",
        help="Perform geolocation + RDAP/WHOIS lookup on public hosts",
    )
    parser.add_argument(
        "--compare",
        type=int,
        default=0,
        metavar="ID",
        help="After scanning, show changes versus stored run ID",
    )
    parser.add_argument(
        "--diff",
        type=int,
        nargs=2,
        metavar=("OLD", "NEW"),
        help="Compare two stored runs (no scan)",
    )
    parser.add_argument(
        "--timeline",
        nargs="?",
        const="list",
        default="",
        help="Show scan history: list | target:<host> | since:<date> | range:<a>..<b>",
    )
    parser.add_argument(
        "--limit", type=int, default=20, help="Rows shown by --timeline (default: 20)"
    )
    parser.add_argument(
        "--db-path",
        default="nexscan_history.db",
        help="Path to scan history database",
    )

    args = parser.parse_args()

    if args.cli:
        if not (args.targets or args.target_file or args.timeline or args.diff):
            parser.error("--cli requires -t/--targets or -f/--target-file")
        run_cli(args)
    else:
        launch_gui()


if __name__ == "__main__":
    main()
