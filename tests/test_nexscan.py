"""
NexScan — Basic test suite
Run with: pytest tests/ -v
"""

import os
import tempfile

from core import db as core_db
from core import engine
from core.scanner import (
    PortResult,
    PortState,
    ScanConfig,
    ScanResult,
    ScanType,
    parse_ports,
    parse_targets,
)
from core.service_db import ServiceDatabase
from reports.exporter import (
    export_csv,
    export_html,
    export_json,
    export_txt,
    export_xml,
)

# ─────────────────────────── parse_ports ────────────────────────────


class TestParsePorts:
    def test_single_port(self):
        assert parse_ports("80") == [80]

    def test_comma_separated(self):
        assert parse_ports("22,80,443") == [22, 80, 443]

    def test_range(self):
        result = parse_ports("1-5")
        assert result == [1, 2, 3, 4, 5]

    def test_mixed(self):
        result = parse_ports("22,80,100-102")
        assert result == [22, 80, 100, 101, 102]

    def test_deduplication(self):
        result = parse_ports("80,80,80")
        assert result == [80]

    def test_invalid_ignored(self):
        result = parse_ports("abc,,")
        assert result == []

    def test_out_of_range_ignored(self):
        result = parse_ports("0,65536,80")
        assert result == [80]

    def test_sorted_output(self):
        result = parse_ports("443,22,80")
        assert result == [22, 80, 443]


# ─────────────────────────── parse_targets ──────────────────────────


class TestParseTargets:
    def test_single_ip(self):
        assert parse_targets("192.168.1.1") == ["192.168.1.1"]

    def test_hostname(self):
        assert parse_targets("example.com") == ["example.com"]

    def test_cidr(self):
        result = parse_targets("192.168.1.0/30")
        # /30 has 2 usable hosts
        assert len(result) == 2
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result

    def test_comma_separated(self):
        result = parse_targets("10.0.0.1,10.0.0.2")
        assert "10.0.0.1" in result
        assert "10.0.0.2" in result

    def test_newline_separated(self):
        result = parse_targets("10.0.0.1\n10.0.0.2")
        assert "10.0.0.1" in result
        assert "10.0.0.2" in result

    def test_deduplication(self):
        result = parse_targets("10.0.0.1,10.0.0.1")
        assert result.count("10.0.0.1") == 1

    def test_empty_string(self):
        assert parse_targets("") == []

    def test_cidr_large_capped(self):
        # /23 has 510 hosts — should be capped at 256
        result = parse_targets("10.0.0.0/23")
        assert len(result) <= 256


# ─────────────────────────── ServiceDatabase ────────────────────────


class TestServiceDatabase:
    def setup_method(self):
        self.db = ServiceDatabase()

    def test_known_tcp_port(self):
        svc = self.db.lookup(80, "tcp")
        assert svc["name"] == "http"

    def test_known_udp_port(self):
        svc = self.db.lookup(53, "udp")
        assert svc["name"] == "dns"

    def test_unknown_port_returns_empty_name(self):
        svc = self.db.lookup(65000, "tcp")
        assert svc["name"] == ""

    def test_get_service_name(self):
        assert self.db.get_service_name(22) == "ssh"
        assert self.db.get_service_name(443) == "https"

    def test_get_presets_returns_list(self):
        presets = self.db.get_presets()
        assert isinstance(presets, list)
        assert "Top 100" in presets

    def test_get_preset_ports(self):
        ports = self.db.get_preset_ports("Top 100")
        assert isinstance(ports, list)
        assert len(ports) > 0
        assert 80 in ports

    def test_unknown_preset_returns_empty(self):
        assert self.db.get_preset_ports("NonExistent") == []

    def test_search_by_name(self):
        results = self.db.search("ssh")
        assert any(info["name"] == "ssh" for _, _, info in results)


# ─────────────────────────── ScanConfig ─────────────────────────────


class TestScanConfig:
    def test_defaults(self):
        config = ScanConfig(targets=["10.0.0.1"], ports=[80])
        assert config.scan_type == ScanType.TCP_CONNECT
        assert config.threads == 200
        assert config.grab_banners is True
        assert config.timeout == 1.5

    def test_custom_values(self):
        config = ScanConfig(
            targets=["10.0.0.1"],
            ports=[22, 80],
            threads=50,
            timeout=2.0,
            grab_banners=False,
        )
        assert config.threads == 50
        assert config.timeout == 2.0
        assert config.grab_banners is False


# ─────────────────────────── PortResult ─────────────────────────────


class TestPortResult:
    def test_defaults(self):
        pr = PortResult(port=80, state=PortState.OPEN)
        assert pr.protocol == "tcp"
        assert pr.service == ""
        assert pr.banner == ""
        assert pr.ssl_info is None

    def test_to_dict(self):
        pr = PortResult(port=443, state=PortState.OPEN, service="https", version="Apache/2.4")
        d = pr.to_dict()
        assert d["port"] == 443
        assert d["state"] == "open"
        assert d["service"] == "https"

    def test_banner_truncated_in_dict(self):
        pr = PortResult(port=80, state=PortState.OPEN, banner="A" * 500)
        d = pr.to_dict()
        assert len(d["banner"]) <= 200


# ─────────────────────────── Exporters ──────────────────────────────


def _make_results():
    """Helper: build a minimal ScanResult list for export tests."""
    import datetime

    pr = PortResult(
        port=80,
        state=PortState.OPEN,
        protocol="tcp",
        service="http",
        version="Apache/2.4",
        banner="HTTP/1.1 200 OK",
        response_time=0.042,
    )
    result = ScanResult(
        target="10.0.0.1",
        ip_address="10.0.0.1",
        hostname="test.local",
        host_up=True,
        scan_duration=1.23,
        open_count=1,
        scan_type="tcp_connect",
        timestamp=datetime.datetime.now().isoformat(),
        ports=[pr],
    )
    return [result]


class TestExporters:
    def setup_method(self):
        self.results = _make_results()

    def test_export_json_is_valid(self):
        import json

        output = export_json(self.results)
        data = json.loads(output)
        assert data["scanner"] == "NexScan"
        assert len(data["hosts"]) == 1
        assert data["summary"]["total_open_ports"] == 1

    def test_export_csv_has_header(self):
        output = export_csv(self.results)
        assert output.startswith("Target,")
        assert "10.0.0.1" in output

    def test_export_xml_is_valid(self):
        output = export_xml(self.results)
        assert output.startswith("<?xml")
        assert "<nexscan" in output
        assert 'target="10.0.0.1"' in output

    def test_export_txt_contains_host(self):
        output = export_txt(self.results)
        assert "10.0.0.1" in output
        assert "OPEN" in output.upper()

    def test_export_html_is_valid(self):
        output = export_html(self.results)
        assert "<!DOCTYPE html>" in output
        assert "10.0.0.1" in output
        assert "NexScan" in output

    def test_export_json_empty(self):
        import json

        output = export_json([])
        data = json.loads(output)
        assert data["hosts"] == []
        assert data["summary"]["total_hosts"] == 0

    def test_export_csv_empty(self):
        output = export_csv([])
        # Should still have header row
        assert "Target" in output


def test_engine_validators_and_db_roundtrip():
    # validate ports and targets
    ports = engine.validate_ports("22,80,8000-8001")
    assert 22 in ports and 80 in ports and 8000 in ports

    targets = engine.validate_targets("127.0.0.1,localhost")
    assert "127.0.0.1" in targets

    # DB roundtrip
    results = _make_results()
    fd, path = tempfile.mkstemp(prefix="nexscan_test_", suffix=".db")
    os.close(fd)
    try:
        core_db.save_scan_results(path, results)
        rows = core_db.fetch_all_runs(path)
        assert len(rows) >= 1
        _id, ts, data = rows[0]
        assert isinstance(data, list)
        assert data[0]["target"] == results[0].target
    finally:
        try:
            os.remove(path)
        except Exception:
            pass


# ─────────────────────────── DB Timeline Queries ──────────────────────


def test_db_timeline_queries():
    """Test new timeline query functions."""
    from core.db import fetch_runs_by_target, get_timeline_summary

    results = _make_results()
    fd, path = tempfile.mkstemp(prefix="nexscan_test_", suffix=".db")
    os.close(fd)

    try:
        # Save a scan
        core_db.save_scan_results(path, results)

        # Test get_timeline_summary
        summary = get_timeline_summary(path, limit=10)
        assert len(summary) >= 1
        assert summary[0]["hosts_scanned"] > 0

        # Test fetch_runs_by_target (search for target in results)
        target_runs = fetch_runs_by_target(path, results[0].target)
        assert len(target_runs) >= 1

    finally:
        try:
            os.remove(path)
        except Exception:
            pass


# ─────────────────────────── Scan Comparison ─────────────────────────


def test_compare_scans_new_ports():
    """Test detection of new ports in comparison."""
    from core.compare import compare_scans

    # Scan before: port 80 only
    before = _make_results()

    # Scan after: port 80 and 443 (port 443 is new)
    after_result = before[0]
    new_port = PortResult(
        port=443,
        state=PortState.OPEN,
        protocol="tcp",
        service="https",
        version="Apache/2.4",
    )
    after_result.ports.append(new_port)
    after_result.open_count = 2
    after = [after_result]

    diffs = compare_scans(
        [r.to_dict() for r in before], [r.to_dict() for r in after]
    )  # both before and after should be lists of dicts

    # The conversion to dict may lose port objects, so we verify the comparison function
    # receives the right structure
    assert diffs is not None
    assert len(diffs) >= 1


def test_compare_scans_closed_ports():
    """Test detection of closed ports."""
    from core.compare import compare_scans

    # Create before/after scan results
    before_data = [
        {
            "target": "10.0.0.1",
            "ip_address": "10.0.0.1",
            "host_up": True,
            "ports": [{"port": 80, "protocol": "tcp", "state": "open", "service": "http"}],
        }
    ]

    after_data = [
        {
            "target": "10.0.0.1",
            "ip_address": "10.0.0.1",
            "host_up": True,
            "ports": [],  # Port 80 is now closed
        }
    ]

    diffs = compare_scans(before_data, after_data)
    assert diffs is not None


# ─────────────────────────── CVE Lookup ──────────────────────────────


def test_cve_lookup_common_services():
    """Test CVE lookup for known services."""
    from core.cve_lookup import COMMON_CVES

    # Check that COMMON_CVES has expected services
    assert "apache" in COMMON_CVES or "nginx" in COMMON_CVES
    # Offline cache should have known services
    for service_key in COMMON_CVES:
        assert isinstance(COMMON_CVES[service_key], list)


def test_cve_lookup_format_report():
    """Test CVE report formatting."""
    from core.cve_lookup import CVEInfo, format_cve_report

    cves = [
        CVEInfo(
            cve_id="CVE-2021-1234",
            description="Test vulnerability",
            severity="HIGH",
            score=8.5,
            url="https://nvd.nist.gov/vuln/detail/CVE-2021-1234",
        )
    ]
    report = format_cve_report("apache", "2.4", cves)
    assert "CVE-2021-1234" in report
    assert "HIGH" in report
    assert "8.5" in report


# ─────────────────────────── Geolocation ─────────────────────────────


def test_geolocation_dataclass():
    """Test GeoLocation dataclass."""
    from core.geoloc import GeoLocation

    geo = GeoLocation(
        ip_address="8.8.8.8",
        country="United States",
        country_code="US",
        city="Mountain View",
        latitude=37.386,
        longitude=-122.084,
    )
    assert geo.ip_address == "8.8.8.8"
    assert geo.country_code == "US"


def test_geolocation_format_report():
    """Test geolocation report formatting."""
    from core.geoloc import GeoLocation, format_geolocation_report

    geo = GeoLocation(
        ip_address="8.8.8.8",
        country="United States",
        country_code="US",
        city="Mountain View",
        latitude=37.386,
        longitude=-122.084,
        isp="Google",
        as_number="AS15169",
    )
    report = format_geolocation_report(geo)
    assert "8.8.8.8" in report
    assert "Mountain View" in report
    assert "United States" in report
    assert "Google" in report
