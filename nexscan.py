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
    """Minimal CLI scan mode (no GUI)."""
    from core.scanner import (
        PortScanner,
        ScanConfig,
        ScanType,
        PortState,
        parse_ports,
        parse_targets,
    )

    targets = parse_targets(args.targets)
    ports = parse_ports(args.ports)

    if not targets:
        print("[!] No valid targets.", file=sys.stderr)
        sys.exit(1)
    if not ports:
        print("[!] No valid ports.", file=sys.stderr)
        sys.exit(1)

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

    print(f"[*] NexScan v2.0 — CLI Mode")
    print(f"[*] Targets: {len(targets)}  Ports: {len(ports)}  Type: {stype.value}")
    print(f"[*] Threads: {config.threads}  Timeout: {config.timeout}s")
    print()

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

    scanner = PortScanner(config, callback=on_port, host_callback=on_host)
    results = scanner.run()

    print(f"\n[*] Scan complete.")
    total_open = sum(r.open_count for r in results)
    hosts_up = sum(1 for r in results if r.host_up)
    print(f"[*] Hosts up: {hosts_up}/{len(results)}  Open ports: {total_open}")

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
        print(f"[*] Results saved to {args.output}")


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

    args = parser.parse_args()

    if args.cli:
        if not args.targets:
            parser.error("--cli requires -t/--targets")
        run_cli(args)
    else:
        launch_gui()


if __name__ == "__main__":
    main()
