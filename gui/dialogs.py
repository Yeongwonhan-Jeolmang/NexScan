"""
NexScan GUI — popup windows (Port Detail, About).
"""

from __future__ import annotations

import json
from typing import Callable

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QDialog, QWidget

from core.scanner import PortResult, PortState, ScanResult
from gui.theme import C, Fonts
from gui.widgets import FlatButton, TaggedText, frame, hbox, vbox


def _base_dialog(parent: QWidget, title: str, w: int, h: int) -> QDialog:
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
    dlg.setModal(False)
    dlg.resize(w, h)
    return dlg


def show_port_popup(
    parent: QWidget, result: ScanResult, pr: PortResult, copy_text: Callable[[str], None]
) -> QDialog:
    dlg = _base_dialog(parent, f"Port Detail — {result.target}:{pr.port}", 640, 520)
    lay = vbox(dlg)

    txt = TaggedText(wrap=True, bordered=False, padding=(16, 12))
    lay.addWidget(txt, 1)

    btns = frame("bg")
    bl = hbox(btns, margins=(8, 8, 8, 8), spacing=8)
    bl.addStretch(1)
    if pr.banner:
        bl.addWidget(FlatButton("Copy Banner", lambda: copy_text(pr.banner), fg=C["orange"]))
    bl.addWidget(
        FlatButton(
            "Copy JSON", lambda: copy_text(json.dumps(pr.to_dict(), indent=2)), fg=C["accent"]
        )
    )
    bl.addWidget(FlatButton("  Close  ", dlg.close))
    lay.addWidget(btns)

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
        txt.tag_configure(tag, fg_c)
    state_tag = {
        PortState.OPEN: "open",
        PortState.FILTERED: "filtered",
        PortState.OPEN_FILTERED: "filtered",
    }.get(pr.state, "closed")

    w = txt.write
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
        for key, lbl in labels:
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
            w(f"{lbl:<12}: ", "key")
            w(f"{v}\n", tag)

    txt.scroll_to_top()
    dlg.show()
    return dlg


def show_about(parent: QWidget, version: str) -> QDialog:
    dlg = _base_dialog(parent, "About NexScan", 600, 560)
    dlg.setFixedWidth(600)
    lay = vbox(dlg)

    txt = TaggedText(wrap=True, bordered=False, padding=(24, 20))
    lay.addWidget(txt, 1)
    btns = frame("bg")
    bl = hbox(btns, margins=(0, 10, 0, 10))
    bl.addStretch(1)
    bl.addWidget(FlatButton("  Close  ", dlg.close))
    bl.addStretch(1)
    lay.addWidget(btns)

    txt.tag_configure("h1", C["accent"], Fonts.title())
    txt.tag_configure("h2", C["purple"], Fonts.mono_lg())
    txt.tag_configure("key", C["text2"])
    txt.tag_configure("kbd", C["accent"])
    txt.tag_configure("val", C["text"])

    w = txt.write
    w("◈ NEXSCAN\n", "h1")
    w(f"v{version} — Advanced Port Scanner\n", "val")

    w("\nKEYBOARD SHORTCUTS\n", "h2")
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
        w(f"  {keys:<18}", "kbd")
        w(f"{desc}\n", "key")

    w("\nCAPABILITIES\n", "h2")
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
        w(f"  ✓ {f}\n", "key")

    w("\n⚠ LEGAL NOTICE\n", "h2")
    w(
        "  Only scan systems you own or have explicit permission\n"
        "  to scan. Unauthorized port scanning may be illegal.\n",
        "key",
    )
    txt.scroll_to_top()
    dlg.show()
    return dlg
