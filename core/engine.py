"""High-level engine helpers and async wrappers for NexScan."""

import asyncio
from typing import Callable, Optional

from core.exceptions import InvalidPortSpec, InvalidTargetSpec, PrivilegeError
from core.scanner import (
    RAW_SCAN_TYPES,
    PortScanner,
    ScanConfig,
    ScanType,
    parse_ports,
    parse_targets,
)
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
    """Raise PrivilegeError early when a raw-socket scan cannot run here."""
    if scan_type not in RAW_SCAN_TYPES:
        return
    from core.raw_scan import raw_scans_available

    ok, reason = raw_scans_available()
    if not ok:
        raise PrivilegeError(reason)


def run_scan(
    config: ScanConfig,
    callback: Optional[Callable] = None,
    host_callback: Optional[Callable] = None,
    progress_callback: Optional[Callable] = None,
):
    _check_privileges_for_scan(config.scan_type)
    scanner = PortScanner(
        config,
        callback=callback,
        host_callback=host_callback,
        progress_callback=progress_callback,
    )
    return scanner.run()


async def run_scan_async(
    config: ScanConfig,
    callback: Optional[Callable] = None,
    host_callback: Optional[Callable] = None,
):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, run_scan, config, callback, host_callback)
