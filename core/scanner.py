"""
NexScan - Core Scanner Engine
Handles TCP connect, SYN (raw), UDP scanning with threading, banner grabbing,
service fingerprinting, and OS detection.
"""

import concurrent.futures
from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import queue
import select
import socket
import ssl
import struct
import threading
import time
from typing import Callable, Optional

from core.service_db import ServiceDatabase
from utils.logger import get_logger

logger = get_logger(__name__)


class ScanType(Enum):
    TCP_CONNECT = "tcp_connect"
    SYN_STEALTH = "syn_stealth"
    UDP = "udp"
    ACK = "ack"
    FIN = "fin"
    XMAS = "xmas"
    NULL = "null"
    WINDOW = "window"


class PortState(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    UNRESPONSIVE = "unresponsive"


@dataclass
class PortResult:
    port: int
    state: PortState
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    banner: str = ""
    response_time: float = 0.0
    ssl_info: Optional[dict] = None
    cpe: str = ""
    extra_info: str = ""

    def to_dict(self):
        return {
            "port": self.port,
            "state": self.state.value,
            "protocol": self.protocol,
            "service": self.service,
            "version": self.version,
            "banner": self.banner[:200] if self.banner else "",
            "response_time": round(self.response_time, 4),
            "ssl_info": self.ssl_info,
            "cpe": self.cpe,
            "extra_info": self.extra_info,
        }


@dataclass
class ScanConfig:
    targets: list = field(default_factory=list)
    ports: list = field(default_factory=list)
    scan_type: ScanType = ScanType.TCP_CONNECT
    threads: int = 200
    timeout: float = 1.5
    connect_timeout: float = 3.0
    grab_banners: bool = True
    detect_service: bool = True
    detect_os: bool = False
    ssl_probe: bool = True
    rate_limit: float = 0.0  # seconds between packets (0 = no limit)
    retry_count: int = 1
    jitter: float = 0.0  # random delay jitter ms
    max_banner_wait: float = 2.0
    udp_payload_probes: bool = True
    follow_redirects: bool = False
    host_discovery: bool = True
    host_discovery_timeout: float = 1.0


@dataclass
class ScanResult:
    target: str
    hostname: str = ""
    ip_address: str = ""
    mac_address: str = ""
    os_guess: str = ""
    os_confidence: int = 0
    host_up: bool = True
    scan_duration: float = 0.0
    ports: list = field(default_factory=list)
    open_count: int = 0
    filtered_count: int = 0
    closed_count: int = 0
    scan_type: str = ""
    timestamp: str = ""
    ttl: int = 0
    extra: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "target": self.target,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "os_guess": self.os_guess,
            "os_confidence": self.os_confidence,
            "host_up": self.host_up,
            "scan_duration": round(self.scan_duration, 3),
            "ports": [p.to_dict() for p in self.ports],
            "open_count": self.open_count,
            "filtered_count": self.filtered_count,
            "closed_count": self.closed_count,
            "scan_type": self.scan_type,
            "timestamp": self.timestamp,
            "ttl": self.ttl,
        }


class PortScanner:
    """Main scanning engine with pluggable scan strategies."""

    COMMON_BANNERS = {
        21: b"",
        22: b"",
        25: b"EHLO nexscan.local\r\n",
        80: b"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NexScan/2.0\r\nConnection: close\r\n\r\n",
        110: b"",
        143: b"",
        443: b"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NexScan/2.0\r\nConnection: close\r\n\r\n",
        3306: b"",
        5432: b"",
        6379: b"PING\r\n",
        27017: b"",
    }

    def __init__(
        self,
        config: ScanConfig,
        callback: Optional[Callable] = None,
        progress_callback: Optional[Callable] = None,
        host_callback: Optional[Callable] = None,
    ):
        self.config = config
        self.callback = callback
        self.progress_callback = progress_callback
        self.host_callback = host_callback
        self.service_db = ServiceDatabase()
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()
        self._lock = threading.Lock()
        self._completed = 0
        self._total = 0
        self.results = []

    def stop(self):
        self._stop_event.set()

    def pause(self):
        self._pause_event.clear()

    def resume(self):
        self._pause_event.set()

    def is_stopped(self):
        return self._stop_event.is_set()

    def resolve_target(self, target: str) -> tuple[str, str]:
        """Resolve hostname to IP. Returns (ip, hostname)."""
        try:
            ip = socket.gethostbyname(target)
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = target if target != ip else ""
            return ip, hostname
        except socket.gaierror:
            return target, target

    def check_host_up(self, ip: str) -> tuple[bool, int]:
        """Quick TCP probe to check if host responds. Returns (up, ttl)."""
        probe_ports = [80, 443, 22, 21, 8080, 3389, 25, 53]
        for port in probe_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.config.host_discovery_timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result in (0, 111):  # connected or refused = host up
                    return True, 64
            except Exception:
                pass

        # ICMP ping fallback
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(self.config.host_discovery_timeout)
            # ICMP echo request
            packet = struct.pack("!BBHHH4s", 8, 0, 0, 1, 1, b"\x00" * 4)
            checksum = self._icmp_checksum(packet)
            packet = struct.pack("!BBHHH", 8, 0, checksum, 1, 1)
            sock.sendto(packet, (ip, 0))
            data, _ = sock.recvfrom(1024)
            sock.close()
            if len(data) >= 20:
                ttl = data[8]
                return True, ttl
        except Exception:
            pass

        return False, 0

    def _icmp_checksum(self, data: bytes) -> int:
        s = 0
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                s += (data[i] << 8) + data[i + 1]
            else:
                s += data[i]
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF

    def scan_port_tcp(self, host: str, port: int) -> PortResult:
        """TCP connect scan."""
        result = PortResult(port=port, state=PortState.FILTERED, protocol="tcp")
        start = time.perf_counter()

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.config.connect_timeout)
                ret = sock.connect_ex((host, port))
                elapsed = time.perf_counter() - start
                result.response_time = elapsed

                if ret == 0:
                    result.state = PortState.OPEN
                    if self.config.grab_banners:
                        result.banner = self._grab_banner(sock, host, port)
                    if self.config.ssl_probe and port in (443, 8443, 465, 993, 995, 636):
                        result.ssl_info = self._probe_ssl(host, port)
                elif ret in (111, 10061):  # connection refused
                    result.state = PortState.CLOSED
                else:
                    result.state = PortState.FILTERED
        except socket.timeout:
            result.state = PortState.FILTERED
        except ConnectionRefusedError:
            result.state = PortState.CLOSED
        except OSError:
            result.state = PortState.FILTERED

        if self.config.detect_service and result.state == PortState.OPEN:
            svc = self.service_db.lookup(port, "tcp")
            result.service = svc.get("name", "")
            result.version = self._detect_version(result.banner, svc)
            result.cpe = svc.get("cpe", "")

        return result

    def scan_port_udp(self, host: str, port: int) -> PortResult:
        """UDP scan with service-specific probes."""
        result = PortResult(port=port, state=PortState.OPEN_FILTERED, protocol="udp")
        start = time.perf_counter()

        probe = self._get_udp_probe(port)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.config.timeout)
                sock.sendto(probe, (host, port))

                try:
                    data, _ = sock.recvfrom(1024)
                    result.state = PortState.OPEN
                    result.banner = data[:200].decode("utf-8", errors="replace").strip()
                    result.response_time = time.perf_counter() - start
                except socket.timeout:
                    # No response could mean open|filtered
                    result.state = PortState.OPEN_FILTERED
                    result.response_time = time.perf_counter() - start
        except OSError as e:
            if "ICMP" in str(e) or getattr(e, "errno", None) in (111, 10054):
                result.state = PortState.CLOSED
            else:
                result.state = PortState.OPEN_FILTERED
            result.response_time = time.perf_counter() - start

        if self.config.detect_service:
            svc = self.service_db.lookup(port, "udp")
            result.service = svc.get("name", "")

        return result

    def _get_udp_probe(self, port: int) -> bytes:
        probes = {
            53: b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x07version\x04bind\x00\x00\x10\x00\x03",  # DNS version
            161: b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00"
            b"\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09"
            b"\x06\x05\x2b\x06\x01\x02\x01\x05\x00",  # SNMP
            123: b"\x1b" + b"\x00" * 47,  # NTP
            137: b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",
            500: b"\x00" * 28,  # IKE
        }
        return probes.get(port, b"\x00\x00")

    def _grab_banner(self, sock: socket.socket, host: str, port: int) -> str:
        """Grab service banner with protocol-aware probes."""
        try:
            sock.settimeout(self.config.max_banner_wait)

            # Try reading immediately (servers that send banner first)
            try:
                r, _, _ = select.select([sock], [], [], 0.5)
                if r:
                    data = sock.recv(1024)
                    if data:
                        return data.decode("utf-8", errors="replace").strip()[:500]
            except Exception:
                pass

            # Send protocol probe
            probe = self.COMMON_BANNERS.get(port, b"")
            if probe:
                probe = probe.replace(b"{host}", host.encode())
                try:
                    sock.sendall(probe)
                    r, _, _ = select.select([sock], [], [], self.config.max_banner_wait)
                    if r:
                        data = sock.recv(2048)
                        return data.decode("utf-8", errors="replace").strip()[:500]
                except Exception:
                    pass

            # Generic probe
            try:
                sock.sendall(b"\r\n")
                r, _, _ = select.select([sock], [], [], 0.8)
                if r:
                    data = sock.recv(1024)
                    return data.decode("utf-8", errors="replace").strip()[:500]
            except Exception:
                pass

        except Exception:
            pass
        return ""

    def _probe_ssl(self, host: str, port: int) -> Optional[dict]:
        """Retrieve SSL/TLS certificate information."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = ctx.wrap_socket(
                socket.create_connection((host, port), timeout=3), server_hostname=host
            )
            cert = conn.getpeercert()
            cipher = conn.cipher()
            version = conn.version()
            conn.close()

            info = {
                "version": version,
                "cipher": cipher[0] if cipher else "",
                "cipher_bits": cipher[2] if cipher else 0,
            }
            if cert:
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                info.update(
                    {
                        "common_name": subject.get("commonName", ""),
                        "issuer": issuer.get("organizationName", ""),
                        "not_before": cert.get("notBefore", ""),
                        "not_after": cert.get("notAfter", ""),
                        "san": [v for _, v in cert.get("subjectAltName", [])],
                    }
                )
            return info
        except Exception:
            return None

    def _detect_version(self, banner: str, service_info: dict) -> str:
        """Extract version string from banner."""
        if not banner:
            return ""
        import re

        patterns = [
            r"(\d+\.\d+\.\d+[-.\w]*)",
            r"v(\d+\.\d+[-.\w]*)",
            r"version (\d+\.\d+[-.\w]*)",
        ]
        for p in patterns:
            m = re.search(p, banner, re.IGNORECASE)
            if m:
                return m.group(0)
        return ""

    def guess_os(self, ttl: int, open_ports: list) -> tuple[str, int]:
        """Heuristic OS fingerprinting based on TTL and open ports."""
        os_hints = []
        confidence = 0

        # TTL-based
        if ttl > 0:
            if 60 <= ttl <= 70:
                os_hints.append("Linux/Unix")
                confidence = 55
            elif 120 <= ttl <= 130:
                os_hints.append("Windows")
                confidence = 55
            elif 250 <= ttl <= 255:
                os_hints.append("Cisco/Network Device")
                confidence = 60
            elif 30 <= ttl <= 50:
                os_hints.append("BSD/macOS")
                confidence = 40

        # Port-based hints
        ports_set = set(open_ports)
        if {135, 139, 445}.issubset(ports_set):
            os_hints.append("Windows")
            confidence = min(85, confidence + 30)
        if {22, 111}.issubset(ports_set):
            os_hints.append("Linux/Unix")
            confidence = min(75, confidence + 20)
        if 548 in ports_set:
            os_hints.append("macOS")
            confidence = min(70, confidence + 15)
        if {23, 179}.issubset(ports_set):
            os_hints.append("Network Device")
            confidence = min(70, confidence + 15)

        if not os_hints:
            return "Unknown", 0

        # Most common guess
        from collections import Counter

        most_common = Counter(os_hints).most_common(1)[0][0]
        return most_common, confidence

    def scan_target(self, target: str) -> ScanResult:
        """Full scan of a single target."""
        import datetime

        result = ScanResult(
            target=target,
            timestamp=datetime.datetime.now().isoformat(),
            scan_type=self.config.scan_type.value,
        )

        # Resolve target
        ip, hostname = self.resolve_target(target)
        result.ip_address = ip
        result.hostname = hostname

        # Host discovery
        if self.config.host_discovery:
            up, ttl = self.check_host_up(ip)
            result.host_up = up
            result.ttl = ttl
            if not up:
                if self.host_callback:
                    self.host_callback(result)
                return result
        else:
            result.host_up = True
            result.ttl = 64

        start_time = time.perf_counter()

        # Choose scan function
        if self.config.scan_type == ScanType.UDP:
            scan_fn = lambda p: self.scan_port_udp(ip, p)
        else:
            scan_fn = lambda p: self.scan_port_tcp(ip, p)

        port_results = []
        total_ports = len(self.config.ports)
        done = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            future_to_port = {executor.submit(scan_fn, port): port for port in self.config.ports}

            for future in concurrent.futures.as_completed(future_to_port):
                if self._stop_event.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                # Pause support
                self._pause_event.wait()

                try:
                    pr = future.result()
                    port_results.append(pr)

                    if pr.state == PortState.OPEN:
                        result.open_count += 1
                    elif pr.state == PortState.FILTERED or pr.state == PortState.OPEN_FILTERED:
                        result.filtered_count += 1
                    else:
                        result.closed_count += 1

                    # Fire callback for open ports immediately
                    if self.callback and pr.state in (PortState.OPEN, PortState.OPEN_FILTERED):
                        self.callback(target, pr)

                except Exception as e:
                    logger.error(f"Port scan error: {e}")

                done += 1
                with self._lock:
                    self._completed += 1

                if self.progress_callback:
                    self.progress_callback(self._completed, self._total, target, done, total_ports)

                # Rate limiting
                if self.config.rate_limit > 0:
                    time.sleep(self.config.rate_limit)

        result.scan_duration = time.perf_counter() - start_time
        result.ports = sorted(port_results, key=lambda x: x.port)

        # OS detection
        if self.config.detect_os:
            open_ports = [p.port for p in port_results if p.state == PortState.OPEN]
            result.os_guess, result.os_confidence = self.guess_os(result.ttl, open_ports)

        if self.host_callback:
            self.host_callback(result)

        return result

    def run(self) -> list[ScanResult]:
        """Run full scan across all targets."""
        self._total = len(self.config.targets) * len(self.config.ports)
        self._completed = 0
        self.results = []

        for target in self.config.targets:
            if self._stop_event.is_set():
                break
            res = self.scan_target(target)
            self.results.append(res)

        return self.results


def parse_ports(port_str: str) -> list[int]:
    """Parse port string like '22,80,443,1-1024,8080-8090'."""
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                ports.update(range(int(start), int(end) + 1))
            except ValueError:
                pass
        elif part.isdigit():
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def parse_targets(target_str: str) -> list[str]:
    """Parse target string, expanding CIDR ranges."""
    targets = []
    for part in target_str.replace("\n", ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            net = ipaddress.ip_network(part, strict=False)
            if net.num_addresses > 256:
                # Limit to prevent accidental huge scans
                targets.extend(str(h) for h in list(net.hosts())[:256])
            else:
                targets.extend(str(h) for h in net.hosts())
        except ValueError:
            targets.append(part)
    return list(dict.fromkeys(targets))  # deduplicate preserving order
