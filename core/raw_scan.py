"""
NexScan - Raw TCP Scan Engine
Crafts TCP probes on a raw socket for SYN / ACK / FIN / XMAS / NULL / Window
scans and matches replies (TCP and ICMP unreachable) back to their probes.

Requires root on Linux/macOS. Raw TCP sends are blocked on Windows.
IPv4 only.
"""

import os
import random
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from core.exceptions import PrivilegeError
from utils.logger import get_logger

logger = get_logger(__name__)

# TCP flag bits
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20

# ICMP destination-unreachable codes that mean "filtered" (same set nmap uses)
_ICMP_FILTER_CODES = {1, 2, 3, 9, 10, 13}

# Size of the source-port window used for probes
_SPORT_SPAN = 4096

# Probe flags per raw scan type (keys match ScanType values)
PROBE_FLAGS = {
    "syn_stealth": SYN,
    "ack": ACK,
    "fin": FIN,
    "xmas": FIN | PSH | URG,
    "null": 0,
    "window": ACK,
}


@dataclass
class RawReply:
    """What came back for one probe."""

    kind: str = "none"  # "tcp", "icmp" or "none"
    flags: int = 0
    window: int = 0
    ttl: int = 0
    rtt: float = 0.0


@dataclass
class _Pending:
    event: threading.Event = field(default_factory=threading.Event)
    sent_at: float = 0.0
    reply: Optional[RawReply] = None


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def build_tcp_packet(
    src_ip: str, dst_ip: str, sport: int, dport: int, flags: int, seq: int
) -> bytes:
    """Build a 20-byte TCP header (no options) with a valid checksum."""
    offset = 5 << 4
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, offset, flags, 1024, 0, 0)
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        socket.IPPROTO_TCP,
        len(header),
    )
    csum = _checksum(pseudo + header)
    return header[:16] + struct.pack("!H", csum) + header[18:]


def raw_scans_available() -> tuple[bool, str]:
    """Return ``(available, reason)`` for raw TCP scanning on this machine."""
    if os.name == "nt":
        return False, "Raw TCP scans are not supported on Windows — use TCP Connect instead"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.close()
        return True, ""
    except PermissionError:
        return False, "Raw scans require root privileges (try: sudo python nexscan.py)"
    except OSError as e:
        return False, f"Raw sockets unavailable: {e}"


class RawScanEngine:
    """Shared raw socket + receiver thread used by every worker during a scan."""

    def __init__(self, scan_type: str, timeout: float = 1.5, retries: int = 1):
        ok, reason = raw_scans_available()
        if not ok:
            raise PrivilegeError(reason)

        self.scan_type = scan_type
        self.flags = PROBE_FLAGS[scan_type]
        self.timeout = timeout
        self.retries = max(0, retries)
        # Each probe gets its own source port so concurrent probes to the same
        # (ip, port) — e.g. "localhost" and "127.0.0.1" in one scan — never collide.
        self.sport_base = random.randint(32768, 60999 - _SPORT_SPAN)
        self._sport_next = 0

        self._tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self._tcp_sock.settimeout(0.2)
        try:
            self._icmp_sock: Optional[socket.socket] = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
            )
            self._icmp_sock.settimeout(0.2)
        except OSError:
            self._icmp_sock = None

        self._pending: dict[tuple[str, int, int], _Pending] = {}
        self._lock = threading.Lock()
        self._src_cache: dict[str, str] = {}
        self._closed = threading.Event()

        self._threads = [threading.Thread(target=self._recv_tcp, daemon=True)]
        if self._icmp_sock:
            self._threads.append(threading.Thread(target=self._recv_icmp, daemon=True))
        for t in self._threads:
            t.start()

    # ── Public API ──

    def probe(self, ip: str, port: int) -> RawReply:
        """Send a probe (with retries) and wait for its reply."""
        src = self._source_ip(ip)
        for _ in range(self.retries + 1):
            pending = _Pending()
            with self._lock:
                sport = self.sport_base + self._sport_next
                self._sport_next = (self._sport_next + 1) % _SPORT_SPAN
                key = (ip, port, sport)
                self._pending[key] = pending
            pkt = build_tcp_packet(src, ip, sport, port, self.flags, random.randint(0, 0xFFFFFFFF))
            pending.sent_at = time.perf_counter()
            try:
                self._tcp_sock.sendto(pkt, (ip, 0))
            except OSError as e:
                logger.debug(f"Raw send to {ip}:{port} failed: {e}")
            got = pending.event.wait(self.timeout)
            with self._lock:
                self._pending.pop(key, None)
            if got and pending.reply:
                return pending.reply
        return RawReply()

    def close(self):
        self._closed.set()
        for t in self._threads:
            t.join(timeout=1)
        for s in (self._tcp_sock, self._icmp_sock):
            if s:
                try:
                    s.close()
                except OSError:
                    pass

    # ── Internals ──

    def _source_ip(self, dst: str) -> str:
        src = self._src_cache.get(dst)
        if src:
            return src
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            try:
                s.connect((dst, 9))
                src = s.getsockname()[0]
            except OSError:
                src = "0.0.0.0"
        self._src_cache[dst] = src
        return src

    def _owns(self, port: int) -> bool:
        return self.sport_base <= port < self.sport_base + _SPORT_SPAN

    def _deliver(self, key: tuple[str, int, int], reply: RawReply):
        with self._lock:
            pending = self._pending.get(key)
        if pending and not pending.event.is_set():
            reply.rtt = time.perf_counter() - pending.sent_at
            pending.reply = reply
            pending.event.set()

    def _recv_tcp(self):
        while not self._closed.is_set():
            try:
                data, _ = self._tcp_sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(data) < 40:
                continue
            ihl = (data[0] & 0x0F) * 4
            tcp = data[ihl : ihl + 20]
            if len(tcp) < 20:
                continue
            sport, dport, _seq, _ack, _off, flags, window = struct.unpack("!HHIIBBH", tcp[:16])
            if not self._owns(dport):
                continue
            src_ip = socket.inet_ntoa(data[12:16])
            self._deliver(
                (src_ip, sport, dport),
                RawReply(kind="tcp", flags=flags, window=window, ttl=data[8]),
            )

    def _recv_icmp(self):
        assert self._icmp_sock is not None
        while not self._closed.is_set():
            try:
                data, _ = self._icmp_sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            ihl = (data[0] & 0x0F) * 4
            icmp = data[ihl:]
            # type 3 = destination unreachable; payload = original IP hdr + 8 bytes
            if len(icmp) < 8 + 20 + 8 or icmp[0] != 3 or icmp[1] not in _ICMP_FILTER_CODES:
                continue
            inner = icmp[8:]
            inner_ihl = (inner[0] & 0x0F) * 4
            if inner[9] != socket.IPPROTO_TCP or len(inner) < inner_ihl + 4:
                continue
            dst_ip = socket.inet_ntoa(inner[16:20])
            isport, idport = struct.unpack("!HH", inner[inner_ihl : inner_ihl + 4])
            if not self._owns(isport):
                continue
            self._deliver((dst_ip, idport, isport), RawReply(kind="icmp", ttl=data[8]))


def interpret(scan_type: str, reply: RawReply) -> str:
    """Map a reply to a PortState value string for the given scan type."""
    if reply.kind == "icmp":
        return "filtered"
    if reply.kind == "none":
        return "open|filtered" if scan_type in ("fin", "xmas", "null") else "filtered"

    flags = reply.flags
    if scan_type == "syn_stealth":
        if flags & SYN and flags & ACK:
            return "open"
        if flags & RST:
            return "closed"
        return "filtered"
    if scan_type in ("fin", "xmas", "null"):
        return "closed" if flags & RST else "open|filtered"
    if scan_type == "ack":
        return "unfiltered" if flags & RST else "filtered"
    if scan_type == "window":
        if flags & RST:
            return "open" if reply.window > 0 else "closed"
        return "filtered"
    return "filtered"
