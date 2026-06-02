"""Scan comparison and diff utility."""

from dataclasses import dataclass
from typing import List, Tuple
from core.scanner import ScanResult, PortState


@dataclass
class PortDiff:
    port: int
    protocol: str
    change_type: str  # "new", "closed", "state_changed", "service_changed"
    old_state: str = ""
    new_state: str = ""
    old_service: str = ""
    new_service: str = ""
    old_version: str = ""
    new_version: str = ""


@dataclass
class HostDiff:
    target: str
    ip_address: str
    status_change: str = ""  # "up_to_down", "down_to_up", "unchanged"
    port_diffs: List[PortDiff] = None

    def __post_init__(self):
        if self.port_diffs is None:
            self.port_diffs = []


def compare_scans(scan_before: List[ScanResult], scan_after: List[ScanResult]) -> List[HostDiff]:
    """
    Compare two scan runs and return list of changes.
    Returns HostDiff objects with detailed port-level changes.
    """
    diffs = []

    # Build lookup maps
    before_map = {r.target: r for r in scan_before}
    after_map = {r.target: r for r in scan_after}

    # Get union of all hosts
    all_hosts = set(before_map.keys()) | set(after_map.keys())

    for host in sorted(all_hosts):
        before = before_map.get(host)
        after = after_map.get(host)

        # Host status change
        status_change = ""
        if before and after:
            if before.host_up and not after.host_up:
                status_change = "down"
            elif not before.host_up and after.host_up:
                status_change = "up"
            else:
                status_change = "unchanged"
        elif after and not before:
            status_change = "newly_scanned"
        elif before and not after:
            status_change = "not_in_recent"

        ip_address = (after or before).ip_address

        # Port-level diffs
        port_diffs = []
        if before and after:
            port_diffs = _diff_ports(before, after)

        if status_change != "unchanged" or port_diffs:
            diffs.append(
                HostDiff(
                    target=host,
                    ip_address=ip_address,
                    status_change=status_change,
                    port_diffs=port_diffs,
                )
            )

    return diffs


def _diff_ports(before: ScanResult, after: ScanResult) -> List[PortDiff]:
    """Compare ports between two scans."""
    diffs = []

    before_map = {(p.port, p.protocol): p for p in before.ports}
    after_map = {(p.port, p.protocol): p for p in after.ports}

    all_keys = set(before_map.keys()) | set(after_map.keys())

    for port, protocol in sorted(all_keys):
        before_p = before_map.get((port, protocol))
        after_p = after_map.get((port, protocol))

        if before_p and after_p:
            # Port existed in both
            if before_p.state != after_p.state:
                diffs.append(
                    PortDiff(
                        port=port,
                        protocol=protocol,
                        change_type="state_changed",
                        old_state=before_p.state.value,
                        new_state=after_p.state.value,
                    )
                )
            elif before_p.service != after_p.service or before_p.version != after_p.version:
                diffs.append(
                    PortDiff(
                        port=port,
                        protocol=protocol,
                        change_type="service_changed",
                        old_service=before_p.service,
                        new_service=after_p.service,
                        old_version=before_p.version,
                        new_version=after_p.version,
                    )
                )
        elif after_p and not before_p:
            # New port (if open/filtered)
            if after_p.state in (PortState.OPEN, PortState.OPEN_FILTERED):
                diffs.append(
                    PortDiff(
                        port=port,
                        protocol=protocol,
                        change_type="new",
                        new_state=after_p.state.value,
                        new_service=after_p.service,
                        new_version=after_p.version,
                    )
                )
        elif before_p and not after_p:
            # Port closed/disappeared
            if before_p.state in (PortState.OPEN, PortState.OPEN_FILTERED):
                diffs.append(
                    PortDiff(
                        port=port,
                        protocol=protocol,
                        change_type="closed",
                        old_state=before_p.state.value,
                        old_service=before_p.service,
                        old_version=before_p.version,
                    )
                )

    return diffs


def generate_diff_report(diffs: List[HostDiff]) -> str:
    """Generate human-readable diff report."""
    lines = []
    lines.append("=" * 70)
    lines.append("  SCAN COMPARISON REPORT")
    lines.append("=" * 70)
    lines.append("")

    if not diffs:
        lines.append("  ✓ No changes detected between scans")
        lines.append("")
        return "\n".join(lines)

    # Summary
    host_changes = sum(1 for d in diffs if d.status_change in ("up", "down"))
    port_changes = sum(len(d.port_diffs) for d in diffs)
    lines.append(f"  Changes: {host_changes} hosts | {port_changes} ports")
    lines.append("")

    for diff in diffs:
        lines.append(f"  Host: {diff.target} ({diff.ip_address})")

        if diff.status_change:
            icon = (
                "▲" if diff.status_change == "up" else "▼" if diff.status_change == "down" else "→"
            )
            lines.append(f"    {icon} Status: {diff.status_change.upper()}")

        for pd in diff.port_diffs:
            if pd.change_type == "new":
                lines.append(
                    f"    ✚ NEW: {pd.port}/{pd.protocol} → {pd.new_state}  "
                    f"({pd.new_service} {pd.new_version})".rstrip()
                )
            elif pd.change_type == "closed":
                lines.append(
                    f"    ✗ CLOSED: {pd.port}/{pd.protocol}  "
                    f"was {pd.old_service} {pd.old_version}".rstrip()
                )
            elif pd.change_type == "state_changed":
                lines.append(
                    f"    ⟳ STATE: {pd.port}/{pd.protocol}  {pd.old_state} → {pd.new_state}"
                )
            elif pd.change_type == "service_changed":
                lines.append(
                    f"    ⓘ SERVICE: {pd.port}/{pd.protocol}  "
                    f"{pd.old_service} {pd.old_version} → {pd.new_service} {pd.new_version}".rstrip()
                )

        lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)
