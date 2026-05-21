"""
NexScan - Report Exporter
Exports scan results in multiple formats: JSON, CSV, HTML, XML, TXT.
Credits to Florian van den Bersselaar and Anna Zieleman
"""

import json
import csv
import io
import datetime
from typing import List
from core.scanner import ScanResult, PortState

VERSION = "2.0"
APP_NAME = "NexScan"


def export_json(results: List[ScanResult], pretty: bool = True) -> str:
    data = {
        "scanner": APP_NAME,
        "version": VERSION,
        "generated": datetime.datetime.now().isoformat(),
        "hosts": [r.to_dict() for r in results],
        "summary": {
            "total_hosts": len(results),
            "hosts_up": sum(1 for r in results if r.host_up),
            "total_open_ports": sum(r.open_count for r in results),
        }
    }
    return json.dumps(data, indent=2 if pretty else None)


def export_csv(results: List[ScanResult]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Target", "IP Address", "Hostname", "Port", "Protocol", "State",
        "Service", "Version", "Banner", "Response Time (ms)", "SSL Version",
        "OS Guess", "Scan Duration (s)", "Timestamp"
    ])
    for r in results:
        for p in r.ports:
            if p.state == PortState.OPEN:
                ssl_ver = ""
                if p.ssl_info:
                    ssl_ver = p.ssl_info.get("version", "")
                writer.writerow([
                    r.target, r.ip_address, r.hostname,
                    p.port, p.protocol, p.state.value,
                    p.service, p.version,
                    p.banner.replace("\n", " ").replace("\r", "")[:100],
                    round(p.response_time * 1000, 2),
                    ssl_ver,
                    r.os_guess,
                    round(r.scan_duration, 3),
                    r.timestamp
                ])
    return output.getvalue()


def export_xml(results: List[ScanResult]) -> str:
    lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    lines.append(f'<nexscan version="{VERSION}" generated="{datetime.datetime.now().isoformat()}">')
    for r in results:
        lines.append(f'  <host target="{r.target}" ip="{r.ip_address}" hostname="{r.hostname}" up="{r.host_up}">')
        if r.os_guess:
            lines.append(f'    <os guess="{_esc(r.os_guess)}" confidence="{r.os_confidence}"/>')
        lines.append(f'    <scan_info type="{r.scan_type}" duration="{r.scan_duration:.3f}" '
                     f'open="{r.open_count}" filtered="{r.filtered_count}" closed="{r.closed_count}"/>')
        lines.append("    <ports>")
        for p in r.ports:
            if p.state == PortState.OPEN:
                ssl_attr = ""
                if p.ssl_info:
                    ssl_attr = f' ssl_version="{p.ssl_info.get("version", "")}"'
                lines.append(f'      <port number="{p.port}" protocol="{p.protocol}" state="{p.state.value}" '
                             f'service="{_esc(p.service)}" version="{_esc(p.version)}" '
                             f'response_ms="{round(p.response_time*1000,2)}"{ssl_attr}>')
                if p.banner:
                    lines.append(f'        <banner><![CDATA[{p.banner[:200]}]]></banner>')
                lines.append("      </port>")
        lines.append("    </ports>")
        lines.append("  </host>")
    lines.append("</nexscan>")
    return "\n".join(lines)


def export_txt(results: List[ScanResult]) -> str:
    lines = []
    sep = "=" * 72
    thin = "-" * 72
    lines.append(sep)
    lines.append(f"  {APP_NAME} v{VERSION} — Scan Report")
    lines.append(f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(sep)
    lines.append("")

    total_open = sum(r.open_count for r in results)
    hosts_up = sum(1 for r in results if r.host_up)
    lines.append(f"  Hosts scanned : {len(results)}")
    lines.append(f"  Hosts up      : {hosts_up}")
    lines.append(f"  Open ports    : {total_open}")
    lines.append("")

    for r in results:
        lines.append(sep)
        lines.append(f"  Host   : {r.target}")
        if r.ip_address and r.ip_address != r.target:
            lines.append(f"  IP     : {r.ip_address}")
        if r.hostname and r.hostname != r.target:
            lines.append(f"  rDNS   : {r.hostname}")
        lines.append(f"  Status : {'UP' if r.host_up else 'DOWN'}")
        if r.os_guess:
            lines.append(f"  OS     : {r.os_guess} ({r.os_confidence}% confidence)")
        lines.append(f"  Scan   : {r.scan_type}  |  Duration: {r.scan_duration:.2f}s")
        lines.append(f"  Open: {r.open_count}  Filtered: {r.filtered_count}  Closed: {r.closed_count}")
        lines.append(thin)

        open_ports = [p for p in r.ports if p.state == PortState.OPEN]
        if open_ports:
            lines.append(f"  {'PORT':<10} {'PROTO':<6} {'STATE':<12} {'SERVICE':<18} {'VERSION'}")
            lines.append(f"  {'-'*8:<10} {'-'*5:<6} {'-'*10:<12} {'-'*16:<18} {'-'*20}")
            for p in open_ports:
                lines.append(
                    f"  {p.port:<10} {p.protocol:<6} {p.state.value:<12} {p.service:<18} {p.version[:30]}"
                )
                if p.banner:
                    short_banner = p.banner.splitlines()[0][:60]
                    lines.append(f"  {'':10} {'':6} Banner: {short_banner}")
                if p.ssl_info:
                    lines.append(f"  {'':10} {'':6} SSL: {p.ssl_info.get('version','')}  CN={p.ssl_info.get('common_name','')}")
        else:
            lines.append("  No open ports found.")
        lines.append("")

    lines.append(sep)
    lines.append(f"  End of Report — {APP_NAME} v{VERSION}")
    lines.append(sep)
    return "\n".join(lines)


def export_html(results: List[ScanResult]) -> str:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_open = sum(r.open_count for r in results)
    hosts_up = sum(1 for r in results if r.host_up)

    rows = []
    for r in results:
        open_ports = [p for p in r.ports if p.state == PortState.OPEN]
        port_rows = ""
        for p in open_ports:
            ssl_badge = ""
            if p.ssl_info:
                ssl_badge = f'<span class="badge ssl">{p.ssl_info.get("version","SSL")}</span>'
            port_rows += f"""
            <tr>
              <td><strong>{p.port}</strong></td>
              <td>{p.protocol.upper()}</td>
              <td><span class="badge open">OPEN</span></td>
              <td>{_esc(p.service)} {ssl_badge}</td>
              <td>{_esc(p.version)}</td>
              <td class="banner">{_esc(p.banner.splitlines()[0][:80]) if p.banner else ''}</td>
              <td>{round(p.response_time*1000,1)}ms</td>
            </tr>"""
        if not port_rows:
            port_rows = '<tr><td colspan="7" style="text-align:center;color:#666">No open ports</td></tr>'

        os_info = f'<div class="os-badge">{_esc(r.os_guess)} ({r.os_confidence}%)</div>' if r.os_guess else ""
        status_cls = "up" if r.host_up else "down"
        rows.append(f"""
    <div class="host-card">
      <div class="host-header">
        <div>
          <span class="host-status {status_cls}">{'● UP' if r.host_up else '○ DOWN'}</span>
          <span class="host-target">{_esc(r.target)}</span>
          {f'<span class="host-ip">{_esc(r.ip_address)}</span>' if r.ip_address != r.target else ''}
          {f'<span class="host-rdns">{_esc(r.hostname)}</span>' if r.hostname and r.hostname != r.target else ''}
        </div>
        <div class="host-meta">
          {os_info}
          <span class="scan-type">{r.scan_type}</span>
          <span class="duration">{r.scan_duration:.2f}s</span>
          <span class="port-counts">
            <span class="cnt open">{r.open_count} open</span>
            <span class="cnt filtered">{r.filtered_count} filtered</span>
            <span class="cnt closed">{r.closed_count} closed</span>
          </span>
        </div>
      </div>
      <table>
        <thead><tr>
          <th>Port</th><th>Protocol</th><th>State</th>
          <th>Service</th><th>Version</th><th>Banner</th><th>RTT</th>
        </tr></thead>
        <tbody>{port_rows}</tbody>
      </table>
    </div>""")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NexScan Report — {now}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --muted: #8b949e; --accent: #58a6ff;
    --open: #3fb950; --filtered: #d29922; --closed: #6e7681;
    --danger: #f85149;
  }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ background:var(--bg); color:var(--text); font-family:'Consolas','Courier New',monospace; padding:24px; }}
  h1 {{ color:var(--accent); font-size:1.8rem; margin-bottom:4px; }}
  .subtitle {{ color:var(--muted); font-size:.9rem; margin-bottom:24px; }}
  .summary {{ display:flex; gap:16px; margin-bottom:32px; flex-wrap:wrap; }}
  .stat {{ background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:16px 24px; text-align:center; }}
  .stat .val {{ font-size:2rem; font-weight:bold; color:var(--accent); }}
  .stat .lbl {{ font-size:.8rem; color:var(--muted); text-transform:uppercase; letter-spacing:.05em; }}
  .host-card {{ background:var(--surface); border:1px solid var(--border); border-radius:8px; margin-bottom:20px; overflow:hidden; }}
  .host-header {{ padding:14px 18px; background:#1c2128; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; }}
  .host-status {{ font-weight:bold; margin-right:10px; }}
  .host-status.up {{ color:var(--open); }}
  .host-status.down {{ color:var(--danger); }}
  .host-target {{ font-size:1.1rem; font-weight:bold; margin-right:8px; }}
  .host-ip {{ color:var(--muted); font-size:.9rem; margin-right:8px; }}
  .host-rdns {{ color:var(--muted); font-size:.85rem; font-style:italic; }}
  .host-meta {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
  .scan-type {{ background:#21262d; border:1px solid var(--border); border-radius:4px; padding:2px 8px; font-size:.8rem; color:var(--muted); }}
  .duration {{ color:var(--muted); font-size:.85rem; }}
  .os-badge {{ background:#1f3a5f; color:#79c0ff; border-radius:4px; padding:2px 8px; font-size:.8rem; }}
  .cnt {{ font-size:.8rem; padding:2px 6px; border-radius:3px; }}
  .cnt.open {{ background:#1a3a1a; color:var(--open); }}
  .cnt.filtered {{ background:#3a2a00; color:var(--filtered); }}
  .cnt.closed {{ background:#1c1c1c; color:var(--closed); }}
  table {{ width:100%; border-collapse:collapse; font-size:.88rem; }}
  th {{ background:#1c2128; padding:8px 12px; text-align:left; color:var(--muted); font-weight:normal; text-transform:uppercase; font-size:.75rem; letter-spacing:.05em; border-bottom:1px solid var(--border); }}
  td {{ padding:7px 12px; border-bottom:1px solid #1c2128; }}
  tr:last-child td {{ border-bottom:none; }}
  tr:hover td {{ background:rgba(88,166,255,.04); }}
  .badge {{ border-radius:3px; padding:1px 6px; font-size:.78rem; font-weight:bold; }}
  .badge.open {{ background:#1a3a1a; color:var(--open); }}
  .badge.ssl {{ background:#1f3a5f; color:#79c0ff; }}
  .banner {{ color:var(--muted); font-size:.82rem; max-width:300px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
  footer {{ margin-top:40px; color:var(--muted); font-size:.8rem; text-align:center; }}
</style>
</head>
<body>
<h1>◈ NexScan Report</h1>
<div class="subtitle">Generated: {now}</div>
<div class="summary">
  <div class="stat"><div class="val">{len(results)}</div><div class="lbl">Hosts Scanned</div></div>
  <div class="stat"><div class="val">{hosts_up}</div><div class="lbl">Hosts Up</div></div>
  <div class="stat"><div class="val">{total_open}</div><div class="lbl">Open Ports</div></div>
</div>
{"".join(rows)}
<footer>NexScan v{VERSION} — For authorized use only</footer>
</body>
</html>"""


def _esc(s: str) -> str:
    """HTML escape."""
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")