"""
Tests for the scanner engine rework, fingerprinting, raw-packet helpers,
history DB, CVE parsing and exporters.
"""

import json
import os
import socket
import sqlite3
import struct
import tempfile
import threading
import time
import xml.etree.ElementTree as ET

import pytest

from core import db as core_db
from core import fingerprint
from core.scanner import (
    PortResult,
    PortScanner,
    PortState,
    ScanConfig,
    ScanResult,
    ScanType,
    parse_ports,
    parse_targets,
)

# ─────────────────────────── Fixtures ───────────────────────────


@pytest.fixture
def tcp_server():
    """Local TCP server that sends a banner. Yields its port."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def loop():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            try:
                conn.sendall(b"SSH-2.0-OpenSSH_9.6p1 Debian-2\r\n")
                time.sleep(0.05)
            finally:
                conn.close()

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    yield port
    stop.set()
    t.join(1)
    srv.close()


def _free_port(kind=socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def db_path():
    fd, path = tempfile.mkstemp(prefix="nexscan_test_", suffix=".db")
    os.close(fd)
    yield path
    try:
        os.remove(path)
    except OSError:
        pass


# ─────────────────────────── Target / port parsing ───────────────────────────


class TestParsingExtras:
    def test_last_octet_range(self):
        assert parse_targets("10.0.0.1-3") == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    def test_full_range_and_reversed(self):
        assert parse_targets("10.0.0.3-10.0.0.1") == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    def test_range_crossing_octet(self):
        assert parse_targets("10.0.0.255-10.0.1.1") == ["10.0.0.255", "10.0.1.0", "10.0.1.1"]

    def test_hyphenated_hostname_is_not_a_range(self):
        assert parse_targets("my-host.local") == ["my-host.local"]

    def test_comments_ignored(self):
        assert parse_targets("# lab\n10.0.0.1") == ["10.0.0.1"]

    def test_huge_networks_are_cheap(self):
        start = time.perf_counter()
        assert len(parse_targets("10.0.0.0/8")) == 256
        assert len(parse_targets("2001:db8::/64")) == 256
        assert time.perf_counter() - start < 1.0

    def test_reversed_port_range(self):
        assert parse_ports("25-22") == [22, 23, 24, 25]

    def test_port_range_clamped(self):
        assert parse_ports("65530-70000")[-1] == 65535


# ─────────────────────────── Fingerprinting ───────────────────────────


class TestFingerprint:
    @pytest.mark.parametrize(
        "banner,service,version",
        [
            ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1", "ssh", "OpenSSH 8.9p1"),
            ("SSH-2.0-dropbear_2020.81", "ssh", "dropbear 2020.81"),
            ("HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n", "http", "Apache 2.4.41"),
            ("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n", "http", "nginx 1.18.0"),
            ("HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n", "http", "Microsoft-IIS 10.0"),
            ("220 (vsFTPd 3.0.3)", "ftp", "vsFTPd 3.0.3"),
            ("220 mail.example.com ESMTP Postfix (Ubuntu)", "smtp", "Postfix"),
            ("* OK [CAPABILITY IMAP4rev1] Dovecot ready.", "imap", "Dovecot"),
            ("+PONG", "redis", "Redis"),
            ("RFB 003.008", "vnc", "VNC (RFB) 003.008"),
        ],
    )
    def test_identify(self, banner, service, version):
        assert fingerprint.identify(banner) == (service, version)

    def test_generic_fallback(self):
        assert fingerprint.identify("FooServer version 1.2.3 ready")[1] == "1.2.3"

    def test_empty(self):
        assert fingerprint.identify("") == ("", "")

    def test_decode_garbage_cert(self):
        assert fingerprint.decode_der_cert(b"not a certificate") == {}


# ─────────────────────────── Live scanning (localhost) ───────────────────────────


class TestLiveScan:
    def test_tcp_open_closed_and_version(self, tcp_server):
        closed = _free_port()
        cfg = ScanConfig(
            targets=["127.0.0.1"],
            ports=[tcp_server, closed],
            host_discovery=False,
            max_banner_wait=0.5,
        )
        result = PortScanner(cfg).run()[0]
        states = {p.port: p for p in result.ports}
        assert states[tcp_server].state == PortState.OPEN
        assert states[tcp_server].version == "OpenSSH 9.6p1"
        assert states[tcp_server].service == "ssh"  # identified from banner on a random port
        assert states[closed].state == PortState.CLOSED
        assert result.open_count == 1 and result.closed_count == 1

    def test_udp_closed_port_detected(self):
        closed = _free_port(socket.SOCK_DGRAM)
        cfg = ScanConfig(
            targets=["127.0.0.1"],
            ports=[closed],
            scan_type=ScanType.UDP,
            host_discovery=False,
            timeout=0.5,
        )
        result = PortScanner(cfg).run()[0]
        assert result.ports[0].state == PortState.CLOSED

    def test_multiple_hosts_share_pool_and_keep_order(self, tcp_server):
        cfg = ScanConfig(
            targets=["127.0.0.2", "127.0.0.1", "localhost"],
            ports=[tcp_server],
            host_discovery=False,
            max_banner_wait=0.3,
        )
        seen = []
        results = PortScanner(cfg, host_callback=lambda r: seen.append(r.target)).run()
        assert [r.target for r in results] == ["127.0.0.2", "127.0.0.1", "localhost"]
        assert sorted(seen) == sorted(r.target for r in results)
        assert results[1].open_count == 1

    def test_progress_reaches_total_with_down_hosts(self):
        cfg = ScanConfig(
            targets=["192.0.2.123"],  # TEST-NET, never routable
            ports=[1, 2, 3],
            host_discovery=True,
            host_discovery_timeout=0.2,
        )
        progress = []
        scanner = PortScanner(cfg, progress_callback=lambda c, t, *a: progress.append((c, t)))
        results = scanner.run()
        if not results[0].host_up:
            assert progress[-1] == (3, 3)

    def test_unresolvable_target_marked_down(self):
        cfg = ScanConfig(targets=["nonexistent.invalid"], ports=[80], host_discovery=False)
        result = PortScanner(cfg).run()[0]
        assert result.host_up is False
        assert "resolve" in result.extra.get("error", "")

    def test_pause_blocks_workers_and_stop_exits(self):
        closed = _free_port()
        cfg = ScanConfig(
            targets=["127.0.0.1"],
            ports=[closed] * 1 + list(range(40000, 42000)),
            host_discovery=False,
            threads=20,
            rate_limit=0.002,
        )
        done = []
        scanner = PortScanner(cfg, progress_callback=lambda c, *a: done.append(c))
        t = threading.Thread(target=scanner.run)
        t.start()
        time.sleep(0.3)
        scanner.pause()
        time.sleep(0.2)
        frozen = len(done)
        time.sleep(0.4)
        assert len(done) - frozen <= cfg.threads  # only in-flight probes may finish
        scanner.stop()
        t.join(5)
        assert not t.is_alive()
        assert len(done) < 2001

    def test_rate_limit_spaces_probes(self):
        cfg = ScanConfig(
            targets=["127.0.0.1"],
            ports=list(range(41000, 41011)),
            host_discovery=False,
            threads=50,
            rate_limit=0.02,
        )
        start = time.perf_counter()
        PortScanner(cfg).run()
        assert time.perf_counter() - start >= 0.18  # 10 gaps × 20 ms


# ─────────────────────────── Raw scan helpers ───────────────────────────


class TestRawHelpers:
    def test_tcp_checksum_valid(self):
        from core.raw_scan import SYN, _checksum, build_tcp_packet

        pkt = build_tcp_packet("10.0.0.1", "10.0.0.2", 40000, 80, SYN, 12345)
        pseudo = struct.pack(
            "!4s4sBBH",
            socket.inet_aton("10.0.0.1"),
            socket.inet_aton("10.0.0.2"),
            0,
            socket.IPPROTO_TCP,
            len(pkt),
        )
        assert _checksum(pseudo + pkt) == 0
        sport, dport, seq, _ack, _off, flags = struct.unpack("!HHIIBB", pkt[:14])
        assert (sport, dport, seq, flags) == (40000, 80, 12345, SYN)

    @pytest.mark.parametrize(
        "scan_type,kind,flags,window,expected",
        [
            ("syn_stealth", "tcp", 0x12, 0, "open"),
            ("syn_stealth", "tcp", 0x14, 0, "closed"),
            ("syn_stealth", "none", 0, 0, "filtered"),
            ("syn_stealth", "icmp", 0, 0, "filtered"),
            ("fin", "none", 0, 0, "open|filtered"),
            ("xmas", "tcp", 0x04, 0, "closed"),
            ("ack", "tcp", 0x04, 0, "unfiltered"),
            ("ack", "none", 0, 0, "filtered"),
            ("window", "tcp", 0x04, 512, "open"),
            ("window", "tcp", 0x04, 0, "closed"),
        ],
    )
    def test_interpret(self, scan_type, kind, flags, window, expected):
        from core.raw_scan import RawReply, interpret

        assert interpret(scan_type, RawReply(kind=kind, flags=flags, window=window)) == expected

    @pytest.mark.skipif(os.name == "nt" or os.geteuid() != 0, reason="needs root")
    def test_syn_scan_localhost(self, tcp_server):
        closed = _free_port()
        cfg = ScanConfig(
            targets=["127.0.0.1"],
            ports=[tcp_server, closed],
            scan_type=ScanType.SYN_STEALTH,
            host_discovery=False,
            timeout=0.5,
        )
        result = PortScanner(cfg).run()[0]
        states = {p.port: p.state for p in result.ports}
        assert states == {tcp_server: PortState.OPEN, closed: PortState.CLOSED}
        assert result.ttl == 64


# ─────────────────────────── Serialization ───────────────────────────


def test_scan_result_round_trip():
    r = ScanResult(target="h", ip_address="10.0.0.1", host_up=True, open_count=1)
    r.ports = [
        PortResult(port=22, state=PortState.OPEN, service="ssh", ssl_info={"version": "TLSv1.3"})
    ]
    again = ScanResult.from_dict(json.loads(json.dumps(r.to_dict())))
    assert again.to_dict() == r.to_dict()
    assert again.ports[0].state is PortState.OPEN


# ─────────────────────────── History DB ───────────────────────────


def _result(target, open_ports=(22,)):
    r = ScanResult(target=target, ip_address=target, host_up=True, scan_type="tcp_connect")
    r.ports = [PortResult(port=p, state=PortState.OPEN) for p in open_ports]
    r.open_count = len(open_ports)
    return r


class TestHistoryDB:
    def test_save_returns_id_and_summary(self, db_path):
        first = core_db.save_scan_results(db_path, [_result("10.0.0.1")])
        second = core_db.save_scan_results(db_path, [_result("10.0.0.2", (22, 80))])
        assert second == first + 1
        summary = core_db.get_timeline_summary(db_path)
        assert summary[0]["total_open_ports"] == 2
        assert summary[0]["scan_type"] == "tcp_connect"
        assert "10.0.0.2" in summary[0]["targets"]

    def test_target_filter_is_exact(self, db_path):
        core_db.save_scan_results(db_path, [_result("10.0.0.1")])
        core_db.save_scan_results(db_path, [_result("10.0.0.11")])
        assert len(core_db.fetch_runs_by_target(db_path, "10.0.0.1")) == 1
        assert len(core_db.get_timeline_summary(db_path, target="10.0.0.11")) == 1

    def test_end_date_includes_whole_day(self, db_path):
        core_db.save_scan_results(db_path, [_result("10.0.0.1")])
        today = time.strftime("%Y-%m-%d")
        assert len(core_db.fetch_runs_by_date_range(db_path, today, today)) == 1

    def test_delete_run(self, db_path):
        run_id = core_db.save_scan_results(db_path, [_result("10.0.0.1")])
        assert core_db.delete_run(db_path, run_id) is True
        assert core_db.fetch_run_by_id(db_path, run_id) is None

    def test_migrates_legacy_database(self, db_path):
        conn = sqlite3.connect(db_path)
        conn.execute(
            "CREATE TABLE scan_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, "
            "data TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO scan_runs (ts, data) VALUES (?, ?)",
            ("2025-01-01T00:00:00", json.dumps([_result("10.9.9.9").to_dict()])),
        )
        conn.commit()
        conn.close()
        summary = core_db.get_timeline_summary(db_path)
        assert summary[0]["hosts_scanned"] == 1
        assert len(core_db.fetch_runs_by_target(db_path, "10.9.9.9")) == 1


# ─────────────────────────── CVE lookup ───────────────────────────


class TestCVE:
    def test_build_query(self):
        from core.cve_lookup import build_query

        assert build_query("ssh", "") == ""
        assert build_query("ssh", "OpenSSH 8.9p1") == "OpenSSH 8.9p1"
        assert build_query("http", "Apache 2.4.41") == "Apache HTTP Server 2.4.41"
        assert build_query("redis", "6.2.1") == "redis 6.2.1"

    def test_extract_cvss_versions(self):
        from core.cve_lookup import _extract_cvss

        v31 = {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}
        v2 = {"cvssMetricV2": [{"baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5}}]}
        assert _extract_cvss(v31) == ("CRITICAL", 9.8)
        assert _extract_cvss(v2) == ("HIGH", 7.5)
        assert _extract_cvss({}) == ("UNKNOWN", 0.0)

    def test_offline_fallback(self, monkeypatch):
        from core import cve_lookup

        def boom(*a, **k):
            raise OSError("offline")

        monkeypatch.setattr(cve_lookup, "_query_nvd", boom)
        cves = cve_lookup.lookup_service_cves("ftp", "vsFTPd 2.3.4")
        assert cves and cves[0].cve_id == "CVE-2011-2523"
        assert "offline" in cves[0].description

    def test_results_cached(self, monkeypatch):
        from core import cve_lookup

        calls = []

        def fake(query, limit):
            calls.append(query)
            return [cve_lookup.CVEInfo("CVE-1", "d", "LOW", 1.0, "u")]

        monkeypatch.setattr(cve_lookup, "_query_nvd", fake)
        cve_lookup._cache.clear()
        cve_lookup.lookup_service_cves("x", "Prod 1.0")
        cve_lookup.lookup_service_cves("x", "Prod 1.0")
        assert calls == ["Prod 1.0"]


def test_geolocation_skips_private_ips():
    from core.geoloc import is_public_ip, lookup_geolocation, lookup_whois_simple

    assert not is_public_ip("192.168.1.10")
    assert is_public_ip("8.8.8.8")
    assert lookup_geolocation("10.0.0.1") is None
    assert lookup_whois_simple("127.0.0.1") == {}


# ─────────────────────────── Exporters ───────────────────────────


def _nasty_results():
    r = ScanResult(target='a"<b>&c', ip_address="10.0.0.1", hostname="h&<", host_up=True)
    r.ports = [
        PortResult(
            port=3306, state=PortState.OPEN, service="mysql|x", banner="J\x00\x0a5.7]]>\x01oops"
        )
    ]
    r.open_count = 1
    return [r]


def test_xml_export_escapes_everything():
    from reports.exporter import export_xml

    root = ET.fromstring(export_xml(_nasty_results()))
    host = root.find("host")
    assert host is not None and host.get("target") == 'a"<b>&c'
    banner = root.find(".//banner")
    assert banner is not None and "]]>" in (banner.text or "")


def test_markdown_export_and_registry():
    from reports.exporter import EXPORTERS, export_markdown, exporter_for_path

    md = export_markdown(_nasty_results())
    assert "| 3306 |" in md and "mysql\\|x" in md
    assert exporter_for_path("report.md") is export_markdown
    assert exporter_for_path("REPORT.HTM") is EXPORTERS["html"][0]
    assert exporter_for_path("noext") is EXPORTERS["txt"][0]


def test_diff_report_hides_unchanged_status():
    from core.compare import compare_scans, generate_diff_report

    report = generate_diff_report(compare_scans([_result("h", (22,))], [_result("h", (22, 80))]))
    assert "NEW: 80/tcp" in report
    assert "UNCHANGED" not in report


def test_cli_port_presets():
    from nexscan import _resolve_ports

    assert _resolve_ports("22,80") == "22,80"
    assert _resolve_ports("1-1024") == "1-1024"
    assert "3306" in _resolve_ports("database").split(",")
    top = _resolve_ports("top100").split(",")
    assert len(top) == len(set(top)) >= 100
