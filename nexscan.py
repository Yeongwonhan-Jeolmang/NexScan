#!/usr/bin/env python3
"""
NexScan v2.0 — Advanced Port Scanner
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
from utils.logger import get_logger

logger = get_logger(__name__)

# Ensure local packages are importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


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


def run_cli(args):
    """CLI scan mode with support for new features."""
    from core.scanner import (
        PortScanner,
        ScanConfig,
        ScanType,
        PortState,
        parse_ports,
        parse_targets,
    )
    from core import engine

    # Load targets from file or CLI arg
    targets_str = args.targets
    if args.target_file:
        try:
            with open(args.target_file, "r") as f:
                targets_str = ",".join(line.strip() for line in f if line.strip())
            logger.info(f"Loaded targets from {args.target_file}")
        except Exception as e:
            logger.error(f"Failed to load target file: {e}")
            sys.exit(1)

    try:
        targets = engine.validate_targets(targets_str)
        ports = engine.validate_ports(args.ports)
    except Exception as e:
        logger.error(f"Invalid input: {e}")
        sys.exit(1)

    # Handle timeline/history queries
    if args.timeline:
        _handle_timeline_query(args)
        return

    # Handle scan comparison
    if args.compare > 0:
        _handle_scan_comparison(args)
        return

    scan_type_map = {
        "tcp": ScanType.TCP_CONNECT,
        "udp": ScanType.UDP,
        "syn": ScanType.SYN_STEALTH,
    }
    stype = scan_type_map.get(args.scan_type.lower(), ScanType.TCP_CONNECT)

    config = ScanConfig(
        targets=targets,
        ports=ports,
        scan_type=stype,
        threads=args.threads,
        timeout=args.timeout,
        grab_banners=not args.no_banner,
        detect_service=True,
        detect_os=args.os_detect,
        host_discovery=not args.skip_discovery,
    )

    logger.info("NexScan v2.0 — CLI Mode")
    logger.info(f"Targets: {len(targets)}  Ports: {len(ports)}  Type: {stype.value}")
    logger.info(f"Threads: {config.threads}  Timeout: {config.timeout}s")

    def on_port(target, pr):
        if pr.state == PortState.OPEN:
            banner = f"  [{pr.banner.splitlines()[0][:50]}]" if pr.banner else ""
            print(
                f"  {target}:{pr.port}/{pr.protocol:<4} OPEN  {pr.service:<18} {pr.version[:25]}{banner}"
            )

    def on_host(result):
        status = "UP" if result.host_up else "DOWN"
        print(
            f"\n[+] {result.target} ({result.ip_address}) — {status}  "
            f"Open:{result.open_count} Filt:{result.filtered_count}  "
            f"Time:{result.scan_duration:.2f}s"
        )
        if result.os_guess:
            print(f"    OS: {result.os_guess} ({result.os_confidence}%)")

        # Geolocation lookup
        if args.geoloc:
            from core.geoloc import lookup_geolocation, format_geolocation_report

            geo = lookup_geolocation(result.ip_address)
            if geo:
                print(format_geolocation_report(geo))

        # CVE lookup for open ports
        if args.cve_lookup:
            from core.cve_lookup import lookup_service_cves, format_cve_report

            for port in result.ports:
                if port.state == PortState.OPEN and port.service:
                    cves = lookup_service_cves(port.service, port.version, limit=3)
                    if cves:
                        print(format_cve_report(port.service, port.version, cves))

    try:
        results = engine.run_scan(config, callback=on_port, host_callback=on_host)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        sys.exit(1)

    logger.info("Scan complete.")
    total_open = sum(r.open_count for r in results)
    hosts_up = sum(1 for r in results if r.host_up)
    logger.info(f"Hosts up: {hosts_up}/{len(results)}  Open ports: {total_open}")

    if args.output:
        from reports.exporter import export_json, export_csv, export_html, export_txt, export_xml

        fmt = os.path.splitext(args.output)[1].lstrip(".")
        fn_map = {
            "json": export_json,
            "csv": export_csv,
            "html": export_html,
            "txt": export_txt,
            "xml": export_xml,
        }
        fn = fn_map.get(fmt, export_txt)
        content = fn(results)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info(f"Results saved to {args.output}")

    if args.save_db:
        from core.db import save_scan_results

        db_path = (
            args.save_db if isinstance(args.save_db, str) and args.save_db else "nexscan_history.db"
        )
        try:
            save_scan_results(db_path, results)
            logger.info(f"Results persisted to {db_path}")
        except Exception as e:
            logger.error(f"Failed saving results to DB: {e}")


def _handle_timeline_query(args):
    """Handle scan history timeline queries."""
    from core.db import fetch_all_runs, get_timeline_summary, fetch_run_by_id, fetch_runs_by_target

    db_path = args.db_path

    if args.timeline == "list":
        # Show recent scans
        summary = get_timeline_summary(db_path, limit=20)
        print("\n" + "=" * 80)
        print("  SCAN HISTORY TIMELINE")
        print("=" * 80)
        for entry in summary:
            print(
                f"  [{entry['id']}] {entry['timestamp']}  "
                f"Hosts:{entry['hosts_scanned']}  Up:{entry['hosts_up']}  Open:{entry['total_open_ports']}"
            )
        print("=" * 80 + "\n")
    else:
        # Parse additional args for target/date filtering
        print("Timeline feature requires list/date/target query mode")


def _handle_scan_comparison(args):
    """Handle scan comparison."""
    from core.db import fetch_run_by_id
    from core.compare import compare_scans, generate_diff_report
    from core.scanner import ScanResult

    db_path = args.db_path

    # Get current scan results from latest DB entry
    all_runs = __import__("core.db", fromlist=["fetch_all_runs"]).fetch_all_runs(db_path)
    if not all_runs:
        logger.error("No previous scans in database")
        sys.exit(1)

    # Get the specified run to compare against
    prev_run = fetch_run_by_id(db_path, args.compare)
    if not prev_run:
        logger.error(f"Scan run {args.compare} not found in database")
        sys.exit(1)

    # Most recent scan for comparison
    latest_run = all_runs[0]

    print(f"\nComparing scan {args.compare} ({prev_run[1]}) vs {latest_run[0]} ({latest_run[1]})\n")

    # Convert dicts back to ScanResult objects (simplified)
    diffs = compare_scans(prev_run[2], latest_run[2])
    report = generate_diff_report(diffs)
    print(report)


def main():
    parser = argparse.ArgumentParser(
        description="NexScan v2.0 — Advanced Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--cli", action="store_true", help="Run in CLI mode (no GUI)")
    parser.add_argument(
        "-t", "--targets", default="", help="Target(s): IP, hostname, CIDR, or range"
    )
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (default: 1-1024)")
    parser.add_argument(
        "-s",
        "--scan-type",
        default="tcp",
        choices=["tcp", "udp", "syn"],
        help="Scan type (default: tcp)",
    )
    parser.add_argument("--threads", type=int, default=300, help="Number of threads (default: 300)")
    parser.add_argument(
        "--timeout", type=float, default=1.5, help="Socket timeout in seconds (default: 1.5)"
    )
    parser.add_argument("--no-banner", action="store_true", help="Disable banner grabbing")
    parser.add_argument("--os-detect", action="store_true", help="Enable OS detection")
    parser.add_argument("--skip-discovery", action="store_true", help="Skip host discovery")
    parser.add_argument(
        "-o",
        "--output",
        default="",
        help="Output file (extension determines format: .json/.csv/.html/.txt/.xml)",
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
        help="Read targets from file (one per line)",
    )
    parser.add_argument(
        "--cve-lookup",
        action="store_true",
        help="Lookup CVEs for detected services",
    )
    parser.add_argument(
        "--geoloc",
        action="store_true",
        help="Perform geolocation lookup on discovered hosts",
    )
    parser.add_argument(
        "--compare",
        type=int,
        default=0,
        help="Compare against previous scan run ID from DB",
    )
    parser.add_argument(
        "--timeline",
        nargs="?",
        const="list",
        default="",
        help="Show scan history timeline (list/search/date-range)",
    )
    parser.add_argument(
        "--db-path",
        default="nexscan_history.db",
        help="Path to scan history database",
    )

    args = parser.parse_args()

    if args.cli:
        if not args.targets and not args.target_file:
            parser.error("--cli requires -t/--targets or -f/--target-file")
        run_cli(args)
    else:
        launch_gui()


if __name__ == "__main__":
    main()
