"""High-level engine helpers and async wrappers for NexScan."""

import asyncio
import os
from typing import Callable, Optional

from core.exceptions import InvalidPortSpec, InvalidTargetSpec, PrivilegeError
from core.scanner import PortScanner, ScanConfig, ScanType, parse_ports, parse_targets
from utils.logger import get_logger

logger = get_logger(__name__)


def validate_ports(port_str: str) -> list[int]:
    ports = parse_ports(port_str)
    if not ports:
        raise InvalidPortSpec(f"Invalid port specification: {port_str!r}")
    return ports


def validate_targets(target_str: str) -> list[str]:
    targets = parse_targets(target_str)
    if not targets:
        raise InvalidTargetSpec(f"Invalid target specification: {target_str!r}")
    return targets


def _check_privileges_for_scan(scan_type: ScanType):
    if scan_type == ScanType.SYN_STEALTH:
        # SYN (raw sockets) typically require elevated privileges
        try:
            if os.name == "nt":
                # Windows: best-effort admin check
                import ctypes

                if not ctypes.windll.shell32.IsUserAnAdmin():
                    raise PrivilegeError("SYN scan requires administrator privileges on Windows")
            else:
                if os.geteuid() != 0:
                    raise PrivilegeError("SYN scan requires root privileges on Unix-like systems")
        except AttributeError:
            # If check can't be performed, warn but allow
            logger.warning("Unable to fully verify privileges for SYN scan on this platform")


def run_scan(
    config: ScanConfig,
    callback: Optional[Callable] = None,
    host_callback: Optional[Callable] = None,
):
    _check_privileges_for_scan(config.scan_type)
    scanner = PortScanner(config, callback=callback, host_callback=host_callback)
    return scanner.run()


async def run_scan_async(
    config: ScanConfig,
    callback: Optional[Callable] = None,
    host_callback: Optional[Callable] = None,
):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, run_scan, config, callback, host_callback)
