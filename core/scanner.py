"""
NexScan - Core Scanner Engine
Handles TCP connect, raw (SYN / ACK / FIN / XMAS / NULL / Window) and UDP
scanning with a shared worker pool, banner grabbing, service fingerprinting,
and OS detection.
"""

import concurrent.futures
import datetime
import errno
import ipaddress
import itertools
import random
import selectors
import socket
import ssl
import struct
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from core import fingerprint
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
    UNFILTERED = "unfiltered"
    UNRESPONSIVE = "unresponsive"


RAW_SCAN_TYPES = {
    ScanType.SYN_STEALTH,
    ScanType.ACK,
    ScanType.FIN,
    ScanType.XMAS,
    ScanType.NULL,
    ScanType.WINDOW,
}

# errno values meaning "connection refused" (Linux 111, macOS/BSD 61, Windows 10061)
_REFUSED = {errno.ECONNREFUSED, 111, 61, 10061}
# Transient local resource errors worth retrying instead of reporting "filtered"
_RESOURCE_ERRORS = {errno.EMFILE, errno.ENFILE, errno.ENOBUFS, errno.EADDRNOTAVAIL}

TLS_PORTS = {443, 465, 636, 853, 990, 992, 993, 994, 995, 5986, 6443, 8443, 9443}
_HTTPS_PORTS = {443, 6443, 8443, 9443, 5986}
_HTTP_PORTS = {80, 81, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8888, 9000, 9090}

_HTTP_PROBE = (
    b"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NexScan/3.0\r\nConnection: close\r\n\r\n"
)

# Maximum hosts produced by a single CIDR / range expression
MAX_EXPANDED_HOSTS = 256


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

    @classmethod
    def from_dict(cls, data: dict) -> "PortResult":
        """Rebuild a PortResult from :meth:`to_dict` output (e.g. scan history)."""
        try:
            state = PortState(data.get("state", "filtered"))
        except ValueError:
            state = PortState.FILTERED
        return cls(
            port=int(data.get("port", 0)),
            state=state,
            protocol=data.get("protocol", "tcp"),
            service=data.get("service", "") or "",
            version=data.get("version", "") or "",
            banner=data.get("banner", "") or "",
            response_time=float(data.get("response_time", 0.0) or 0.0),
            ssl_info=data.get("ssl_info"),
            cpe=data.get("cpe", "") or "",
            extra_info=data.get("extra_info", "") or "",
        )


@dataclass
class ScanConfig:
    targets: list = field(default_factory=list)
    ports: list = field(default_factory=list)
    scan_type: ScanType = ScanType.TCP_CONNECT
    threads: int = 200
    timeout: float = 1.5  # UDP / raw reply wait
    connect_timeout: float = 3.0  # TCP connect timeout
    grab_banners: bool = True
    detect_service: bool = True
    detect_os: bool = False
    ssl_probe: bool = True
    rate_limit: float = 0.0  # seconds between packets (0 = no limit)
    retry_count: int = 1  # attempts per probe for UDP / raw scans (min 1)
    jitter: float = 0.0  # random delay jitter ms
    max_banner_wait: float = 2.0
    udp_payload_probes: bool = True
    follow_redirects: bool = False
    host_discovery: bool = True
    host_discovery_timeout: float = 1.0
    reverse_dns: bool = True


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
        data = {
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
        if self.extra:
            data["extra"] = self.extra
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "ScanResult":
        """Rebuild a ScanResult from :meth:`to_dict` output (e.g. scan history)."""
        known = {f for f in cls.__dataclass_fields__ if f != "ports"}
        kwargs = {k: v for k, v in data.items() if k in known}
        kwargs.setdefault("target", data.get("ip_address", ""))
        result = cls(**kwargs)
        result.ports = [PortResult.from_dict(p) for p in data.get("ports", [])]
        return result


@dataclass
class _HostJob:
    """Book-keeping for one host while its ports are in flight."""

    index: int
    result: ScanResult
    sni: Optional[str]
    remaining: int
    done: int = 0
    start: float = 0.0
    port_results: list = field(default_factory=list)


def _raise_fd_limit() -> int:
    """Raise the soft open-file limit as far as allowed. Returns the new soft limit."""
    try:
        import resource
    except ImportError:  # Windows
        return 8192
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    target = hard if hard != resource.RLIM_INFINITY else 65536
    target = min(target, 65536)
    if soft < target:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
            soft = target
        except (ValueError, OSError):
            pass
    return soft


def _family_for(ip: str) -> int:
    return socket.AF_INET6 if ":" in ip else socket.AF_INET


class PortScanner:
    """Main scanning engine with pluggable scan strategies."""

    COMMON_BANNERS = {
        25: b"EHLO nexscan.local\r\n",
        80: _HTTP_PROBE,
        443: _HTTP_PROBE,
        6379: b"PING\r\n",
    }

    # Services that wait for the client to speak first (skip the passive read)
    _CLIENT_FIRST = _HTTP_PORTS | {6379, 11211}

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
        self._rate_lock = threading.Lock()
        self._next_slot = 0.0
        self._completed = 0
        self._total = 0
        self._raw = None
        self.results = []

        # Every worker may hold a socket (plus one for TLS) — keep within fd limits.
        fd_limit = _raise_fd_limit()
        max_threads = max(1, (fd_limit - 64) // 2)
        if config.threads > max_threads:
            logger.warning(
                f"Reducing threads from {config.threads} to {max_threads} (open-file limit)"
            )
            config.threads = max_threads

    def stop(self):
        self._stop_event.set()
        self._pause_event.set()  # release paused workers so they can exit

    def pause(self):
        self._pause_event.clear()

    def resume(self):
        self._pause_event.set()

    def is_stopped(self):
        return self._stop_event.is_set()

    @property
    def is_paused(self) -> bool:
        return not self._pause_event.is_set()

    # ─────────────────────────── DISCOVERY ───────────────────────────

    def resolve_target(self, target: str, reverse: Optional[bool] = None) -> tuple[str, str]:
        """Resolve hostname to IP. Returns (ip, hostname)."""
        reverse = self.config.reverse_dns if reverse is None else reverse
        try:
            ipaddress.ip_address(target)
            ip = target
        except ValueError:
            try:
                infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
            except socket.gaierror:
                return target, target
            infos.sort(key=lambda i: 0 if i[0] == socket.AF_INET else 1)
            ip = str(infos[0][4][0])

        hostname = target if target != ip else ""
        if reverse:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except (OSError, UnicodeError):
                pass
        return ip, hostname

    def check_host_up(self, ip: str) -> tuple[bool, int]:
        """
        Probe common ports in parallel (non-blocking) to check if a host responds,
        falling back to an ICMP echo when privileged. Returns (up, ttl);
        ttl is 0 when it could not be measured.
        """
        probe_ports = [80, 443, 22, 21, 8080, 3389, 25, 53, 445, 139]
        timeout = self.config.host_discovery_timeout
        family = _family_for(ip)
        sel = selectors.DefaultSelector()
        socks = []
        up = False

        try:
            for port in probe_ports:
                try:
                    s = socket.socket(family, socket.SOCK_STREAM)
                except OSError:
                    continue
                s.setblocking(False)
                socks.append(s)
                try:
                    err = s.connect_ex((ip, port))
                except OSError:
                    continue
                if err == 0 or err in _REFUSED:
                    up = True
                    break
                sel.register(s, selectors.EVENT_WRITE)

            deadline = time.perf_counter() + timeout
            while not up and sel.get_map():
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    break
                for key, _ in sel.select(remaining):
                    probe: socket.socket = key.fileobj  # type: ignore[assignment]
                    err = probe.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    sel.unregister(probe)
                    if err == 0 or err in _REFUSED:
                        up = True
                        break
        finally:
            sel.close()
            for s in socks:
                s.close()

        ttl = 0
        if family == socket.AF_INET and (not up or self.config.detect_os):
            icmp_up, ttl = self._icmp_ping(ip, timeout if not up else min(timeout, 0.6))
            up = up or icmp_up
        return up, ttl

    def _icmp_ping(self, ip: str, timeout: float) -> tuple[bool, int]:
        """ICMP echo (needs root). Returns (got_reply, ttl)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except OSError:
            return False, 0

        ident = random.randint(1, 0xFFFF)
        payload = b"NexScan!"
        header = struct.pack("!BBHHH", 8, 0, 0, ident, 1)
        packet = struct.pack("!BBHHH", 8, 0, self._icmp_checksum(header + payload), ident, 1)
        packet += payload

        try:
            sock.settimeout(timeout)
            sock.sendto(packet, (ip, 0))
            deadline = time.perf_counter() + timeout
            while time.perf_counter() < deadline:
                sock.settimeout(max(0.01, deadline - time.perf_counter()))
                data, addr = sock.recvfrom(1024)
                ihl = (data[0] & 0x0F) * 4
                if addr[0] != ip or len(data) < ihl + 8:
                    continue
                icmp_type = data[ihl]
                recv_id = struct.unpack("!H", data[ihl + 4 : ihl + 6])[0]
                if icmp_type == 0 and recv_id == ident:
                    return True, data[8]
        except OSError:
            pass
        finally:
            sock.close()
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

    # ─────────────────────────── PACING ───────────────────────────

    def _throttle(self) -> bool:
        """Honour pause / rate-limit / jitter before a probe. Returns False if stopped."""
        self._pause_event.wait()
        if self._stop_event.is_set():
            return False

        if self.config.rate_limit > 0:
            with self._rate_lock:
                now = time.perf_counter()
                slot = max(now, self._next_slot)
                self._next_slot = slot + self.config.rate_limit
            if slot > now:
                time.sleep(slot - now)

        if self.config.jitter > 0:
            time.sleep(random.uniform(0, self.config.jitter / 1000.0))
        return not self._stop_event.is_set()

    # ─────────────────────────── PROBES ───────────────────────────

    def scan_port_tcp(self, host: str, port: int, sni: Optional[str] = None) -> PortResult:
        """TCP connect scan."""
        result = PortResult(port=port, state=PortState.FILTERED, protocol="tcp")
        family = _family_for(host)
        start = time.perf_counter()

        for attempt in range(20):
            try:
                with socket.socket(family, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.config.connect_timeout)
                    start = time.perf_counter()
                    ret = sock.connect_ex((host, port))
                    result.response_time = time.perf_counter() - start

                    if ret in _RESOURCE_ERRORS:
                        time.sleep(0.05 * (attempt + 1))
                        continue
                    if ret == 0:
                        result.state = PortState.OPEN
                        if self.config.grab_banners and not (
                            self.config.ssl_probe and port in TLS_PORTS
                        ):
                            result.banner = self._grab_banner(sock, sni or host, port)
                    elif ret in _REFUSED:
                        result.state = PortState.CLOSED
                    else:
                        result.state = PortState.FILTERED
                break
            except socket.timeout:
                result.state = PortState.FILTERED
                break
            except ConnectionRefusedError:
                result.state = PortState.CLOSED
                break
            except OSError as e:
                if e.errno in _RESOURCE_ERRORS:
                    time.sleep(0.05 * (attempt + 1))
                    continue
                result.state = PortState.FILTERED
                break

        if result.state == PortState.OPEN and self.config.ssl_probe and port in TLS_PORTS:
            info, tls_banner = self._tls_probe(host, port, sni, http=port in _HTTPS_PORTS)
            result.ssl_info = info
            if self.config.grab_banners:
                result.banner = tls_banner

        if self.config.detect_service and result.state == PortState.OPEN:
            self._apply_service_info(result, "tcp")

        return result

    def scan_port_udp(self, host: str, port: int) -> PortResult:
        """UDP scan with service-specific probes (ICMP unreachable ⇒ closed)."""
        result = PortResult(port=port, state=PortState.OPEN_FILTERED, protocol="udp")
        probe = self._get_udp_probe(port) if self.config.udp_payload_probes else b""
        attempts = max(1, self.config.retry_count)
        start = time.perf_counter()

        try:
            with socket.socket(_family_for(host), socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.config.timeout)
                # A connected UDP socket surfaces ICMP port-unreachable as ECONNREFUSED
                sock.connect((host, port))
                for _ in range(attempts):
                    start = time.perf_counter()
                    try:
                        sock.send(probe)
                        data = sock.recv(2048)
                        result.state = PortState.OPEN
                        result.banner = data[:200].decode("utf-8", errors="replace").strip()
                        break
                    except socket.timeout:
                        result.state = PortState.OPEN_FILTERED
                    except ConnectionRefusedError:
                        result.state = PortState.CLOSED
                        break
                result.response_time = time.perf_counter() - start
        except ConnectionRefusedError:
            result.state = PortState.CLOSED
            result.response_time = time.perf_counter() - start
        except OSError as e:
            if getattr(e, "errno", None) in _REFUSED | {10054}:
                result.state = PortState.CLOSED
            else:
                result.state = PortState.OPEN_FILTERED
            result.response_time = time.perf_counter() - start

        if self.config.detect_service:
            svc = self.service_db.lookup(port, "udp")
            result.service = svc.get("name", "")

        return result

    def scan_port_raw(self, host: str, port: int) -> PortResult:
        """Raw-packet scan (SYN / ACK / FIN / XMAS / NULL / Window)."""
        from core.raw_scan import interpret

        result = PortResult(port=port, state=PortState.FILTERED, protocol="tcp")
        if self._raw is None:
            return result
        reply = self._raw.probe(host, port)
        result.state = PortState(interpret(self.config.scan_type.value, reply))
        result.response_time = reply.rtt
        if reply.ttl:
            result.extra_info = f"ttl={reply.ttl}"

        if self.config.detect_service and result.state in (PortState.OPEN, PortState.OPEN_FILTERED):
            svc = self.service_db.lookup(port, "tcp")
            result.service = svc.get("name", "")
            result.cpe = svc.get("cpe", "")
        return result

    def _apply_service_info(self, result: PortResult, proto: str):
        svc = self.service_db.lookup(result.port, proto)
        db_name = svc.get("name", "")
        hint, version = fingerprint.identify(result.banner, result.port)
        result.service = db_name
        result.version = version
        result.cpe = svc.get("cpe", "")
        if hint and not db_name:
            result.service = hint
        elif hint and hint not in db_name and db_name not in hint and hint != "http":
            # e.g. SSH answering on port 80
            result.service = hint
            result.extra_info = f"non-standard port (expected {db_name})"

    def _get_udp_probe(self, port: int) -> bytes:
        probes = {
            53: b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x07version\x04bind\x00\x00\x10\x00\x03",  # DNS version
            69: b"\x00\x01nexscan\x00octet\x00",  # TFTP read request
            123: b"\x1b" + b"\x00" * 47,  # NTP
            137: b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",
            161: b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00"
            b"\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09"
            b"\x06\x05\x2b\x06\x01\x02\x01\x05\x00",  # SNMP
            500: b"\x00" * 28,  # IKE
            1900: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
            b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n',  # SSDP
            5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01",  # mDNS
            11211: b"\x00\x01\x00\x00\x00\x01\x00\x00stats\r\n",  # memcached
        }
        return probes.get(port, b"\x00\x00")

    def _grab_banner(self, sock: socket.socket, host: str, port: int) -> str:
        """Grab service banner with protocol-aware probes."""
        wait = max(0.1, self.config.max_banner_wait)

        def _recv(timeout: float) -> bytes:
            sock.settimeout(timeout)
            try:
                return sock.recv(4096)
            except (socket.timeout, OSError):
                return b""

        try:
            # Servers that talk first (SSH, FTP, SMTP, …)
            if port not in self._CLIENT_FIRST:
                data = _recv(min(0.6, wait))
                if data:
                    return data.decode("utf-8", errors="replace").strip()[:500]

            probe = self.COMMON_BANNERS.get(port)
            if probe is None:
                probe = _HTTP_PROBE if port in _HTTP_PORTS else b"\r\n"
            sock.sendall(probe.replace(b"{host}", _host_bytes(host)))
            data = _recv(wait)
            return data.decode("utf-8", errors="replace").strip()[:500]
        except Exception:
            return ""

    def _probe_ssl(self, host: str, port: int) -> Optional[dict]:
        """Retrieve SSL/TLS certificate information."""
        info, _ = self._tls_probe(host, port, None, http=False)
        return info

    def _tls_probe(
        self, host: str, port: int, sni: Optional[str], http: bool
    ) -> tuple[Optional[dict], str]:
        """TLS handshake → (cert / cipher info, optional HTTP banner over TLS)."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = socket.create_connection((host, port), timeout=self.config.connect_timeout)
            server_name = sni if sni and not _is_ip(sni) else None
            with ctx.wrap_socket(raw, server_hostname=server_name) as conn:
                cipher = conn.cipher()
                info = {
                    "version": conn.version(),
                    "cipher": cipher[0] if cipher else "",
                    "cipher_bits": cipher[2] if cipher else 0,
                }
                info.update(fingerprint.decode_der_cert(conn.getpeercert(binary_form=True)))

                banner = ""
                if http and self.config.grab_banners:
                    try:
                        conn.settimeout(max(0.1, self.config.max_banner_wait))
                        conn.sendall(_HTTP_PROBE.replace(b"{host}", _host_bytes(sni or host)))
                        banner = conn.recv(4096).decode("utf-8", errors="replace").strip()[:500]
                    except (OSError, UnicodeError):
                        pass
                return info, banner
        except Exception:
            return None, ""

    def _detect_version(self, banner: str, service_info: dict) -> str:
        """Extract version string from banner."""
        return fingerprint.identify(banner)[1]

    # ─────────────────────────── OS GUESS ───────────────────────────

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
        if {135, 139, 445}.issubset(ports_set) or 3389 in ports_set:
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

        most_common = Counter(os_hints).most_common(1)[0][0]
        return most_common, confidence

    # ─────────────────────────── ORCHESTRATION ───────────────────────────

    def _prepare_host(self, index: int, target: str) -> _HostJob:
        """Resolve + discover a target. Runs on the discovery pool."""
        result = ScanResult(
            target=target,
            timestamp=datetime.datetime.now().isoformat(),
            scan_type=self.config.scan_type.value,
        )
        ip, hostname = self.resolve_target(target)
        result.ip_address = ip
        result.hostname = hostname
        sni = target if not _is_ip(target) else (hostname or None)

        if not _is_ip(ip):
            result.host_up = False
            result.extra["error"] = f"Could not resolve {target}"
        elif self.config.scan_type in RAW_SCAN_TYPES and ":" in ip:
            result.host_up = False
            result.extra["error"] = "Raw scans support IPv4 targets only"
        elif self.config.host_discovery:
            result.host_up, result.ttl = self.check_host_up(ip)
        else:
            result.host_up = True
            if self.config.detect_os and ":" not in ip:
                _, result.ttl = self._icmp_ping(ip, min(self.config.host_discovery_timeout, 0.6))

        return _HostJob(index=index, result=result, sni=sni, remaining=len(self.config.ports))

    def _probe(self, job: _HostJob, port: int) -> Optional[PortResult]:
        if not self._throttle():
            return None
        ip = job.result.ip_address
        if self.config.scan_type == ScanType.UDP:
            return self.scan_port_udp(ip, port)
        if self.config.scan_type in RAW_SCAN_TYPES:
            return self.scan_port_raw(ip, port)
        return self.scan_port_tcp(ip, port, sni=job.sni)

    def _finalize(self, job: _HostJob):
        result = job.result
        result.scan_duration = time.perf_counter() - job.start if job.start else 0.0
        result.ports = sorted(job.port_results, key=lambda x: x.port)

        if not result.ttl:
            ttls = [int(p.extra_info[4:]) for p in result.ports if p.extra_info.startswith("ttl=")]
            if ttls:
                result.ttl = max(ttls)

        if self.config.detect_os and result.host_up:
            open_ports = [p.port for p in result.ports if p.state == PortState.OPEN]
            result.os_guess, result.os_confidence = self.guess_os(result.ttl, open_ports)

        if self.host_callback:
            self.host_callback(result)

    def _record(self, job: _HostJob, pr: PortResult):
        job.port_results.append(pr)
        if pr.state == PortState.OPEN:
            job.result.open_count += 1
        elif pr.state in (PortState.FILTERED, PortState.OPEN_FILTERED):
            job.result.filtered_count += 1
        else:
            job.result.closed_count += 1

        if self.callback and pr.state in (PortState.OPEN, PortState.OPEN_FILTERED):
            self.callback(job.result.target, pr)

    def _report_progress(self, target: str, done: int, total: int):
        if self.progress_callback:
            self.progress_callback(self._completed, self._total, target, done, total)

    def _discover(self, targets: list[str]) -> list[_HostJob]:
        """Resolve and discover all targets concurrently, preserving order."""
        if len(targets) == 1:
            return [self._prepare_host(0, targets[0])]
        workers = min(64, len(targets), max(4, self.config.threads // 4))
        jobs: list[Optional[_HostJob]] = [None] * len(targets)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(self._prepare_host, i, t): i for i, t in enumerate(targets)}
            for fut in concurrent.futures.as_completed(futs):
                if self._stop_event.is_set():
                    ex.shutdown(wait=False, cancel_futures=True)
                    break
                try:
                    jobs[futs[fut]] = fut.result()
                except Exception as e:
                    logger.error(f"Discovery error: {e}")
        return [j for j in jobs if j is not None]

    def _scan_jobs(self, jobs: list[_HostJob]) -> list[ScanResult]:
        """Scan every (host, port) pair of the given jobs on one shared worker pool."""
        ports = self.config.ports
        total_ports = len(ports)
        up_jobs = []

        for job in jobs:
            if job.result.host_up:
                up_jobs.append(job)
                continue
            # Down hosts count as done so progress can reach 100%
            with self._lock:
                self._completed += total_ports
            self._report_progress(job.result.target, total_ports, total_ports)
            if self.host_callback:
                self.host_callback(job.result)

        work = ((job, port) for job in up_jobs for port in ports)
        max_inflight = max(1, self.config.threads) * 2
        inflight: dict[concurrent.futures.Future, _HostJob] = {}
        started: set[int] = set()

        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, self.config.threads)) as ex:
            while True:
                while len(inflight) < max_inflight and not self._stop_event.is_set():
                    item = next(work, None)
                    if item is None:
                        break
                    job, port = item
                    if job.index not in started:
                        started.add(job.index)
                        job.start = time.perf_counter()
                    inflight[ex.submit(self._probe, job, port)] = job

                if not inflight:
                    break

                done, _ = concurrent.futures.wait(
                    inflight, timeout=0.25, return_when=concurrent.futures.FIRST_COMPLETED
                )
                for fut in done:
                    job = inflight.pop(fut)
                    try:
                        pr = fut.result()
                        if pr is not None:
                            self._record(job, pr)
                    except Exception as e:
                        logger.error(f"Port scan error: {e}")

                    job.done += 1
                    job.remaining -= 1
                    with self._lock:
                        self._completed += 1
                    self._report_progress(job.result.target, job.done, total_ports)
                    if job.remaining == 0:
                        self._finalize(job)

                if self._stop_event.is_set():
                    for fut in inflight:
                        fut.cancel()
                    ex.shutdown(wait=True, cancel_futures=True)
                    for fut, job in inflight.items():
                        if fut.done() and not fut.cancelled():
                            try:
                                pr = fut.result()
                                if pr is not None:
                                    self._record(job, pr)
                            except Exception:
                                pass
                    break

        # Hosts interrupted by stop: report partial results
        for job in up_jobs:
            if job.index in started and job.remaining > 0:
                self._finalize(job)

        down = [j for j in jobs if not j.result.host_up]
        scanned = [j for j in up_jobs if j.index in started]
        return [j.result for j in sorted(down + scanned, key=lambda j: j.index)]

    def _open_raw_engine(self):
        if self.config.scan_type in RAW_SCAN_TYPES and self._raw is None:
            from core.raw_scan import RawScanEngine

            self._raw = RawScanEngine(
                self.config.scan_type.value,
                timeout=self.config.timeout,
                retries=max(1, self.config.retry_count) - 1,
            )

    def _close_raw_engine(self):
        if self._raw is not None:
            self._raw.close()
            self._raw = None

    def scan_target(self, target: str) -> ScanResult:
        """Full scan of a single target."""
        self._open_raw_engine()
        try:
            job = self._prepare_host(0, target)
            results = self._scan_jobs([job])
        finally:
            self._close_raw_engine()
        return results[0] if results else job.result

    def run(self) -> list[ScanResult]:
        """Run full scan across all targets."""
        self._total = len(self.config.targets) * len(self.config.ports)
        self._completed = 0
        self.results = []

        self._open_raw_engine()
        try:
            jobs = self._discover(list(self.config.targets))
            if not self._stop_event.is_set():
                self.results = self._scan_jobs(jobs)
            else:
                self.results = [j.result for j in jobs]
        finally:
            self._close_raw_engine()

        return self.results


def _host_bytes(host: str) -> bytes:
    """Encode a host for an HTTP Host header (IDNA for names, ASCII fallback)."""
    try:
        return host.encode("idna")
    except UnicodeError:
        return host.encode("ascii", errors="ignore")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_ports(port_str: str) -> list[int]:
    """Parse port string like '22,80,443,1-1024,8080-8090'."""
    ports = set()
    for part in port_str.replace("\n", ",").split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = (int(x) for x in part.split("-", 1))
            except ValueError:
                continue
            lo, hi = min(start, end), max(start, end)
            ports.update(range(max(1, lo), min(65535, hi) + 1))
        elif part.isdigit():
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def _expand_ip_range(part: str) -> Optional[list[str]]:
    """Expand '10.0.0.1-50' or '10.0.0.1-10.0.0.50'. Returns None if not a range."""
    left, _, right = part.partition("-")
    try:
        start = ipaddress.IPv4Address(left.strip())
    except ValueError:
        return None
    right = right.strip()
    try:
        if right.isdigit() and int(right) <= 255:
            end = ipaddress.IPv4Address(f"{left.rsplit('.', 1)[0]}.{right}")
        else:
            end = ipaddress.IPv4Address(right)
    except ValueError:
        return None
    if end < start:
        start, end = end, start
    count = int(end) - int(start) + 1
    if count > MAX_EXPANDED_HOSTS:
        logger.warning(f"Range {part} has {count} hosts — truncated to {MAX_EXPANDED_HOSTS}")
        count = MAX_EXPANDED_HOSTS
    return [str(start + i) for i in range(count)]


def parse_targets(target_str: str) -> list[str]:
    """Parse target string, expanding CIDR blocks and IP ranges."""
    targets: list[str] = []
    for part in target_str.replace("\n", ",").replace(";", ",").split(","):
        part = part.strip()
        if not part or part.startswith("#"):
            continue

        if "-" in part and "/" not in part:
            expanded = _expand_ip_range(part)
            if expanded is not None:
                targets.extend(expanded)
                continue

        try:
            net = ipaddress.ip_network(part, strict=False)
        except ValueError:
            targets.append(part)
            continue

        hosts = net.hosts()
        if net.num_addresses > MAX_EXPANDED_HOSTS + 2:
            # Limit to prevent accidental huge scans (islice keeps /8 or IPv6 /64 cheap)
            logger.warning(f"{part} truncated to the first {MAX_EXPANDED_HOSTS} hosts")
        targets.extend(str(h) for h in itertools.islice(hosts, MAX_EXPANDED_HOSTS))
    return list(dict.fromkeys(targets))  # deduplicate preserving order
