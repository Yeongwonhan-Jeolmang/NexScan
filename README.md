# ◈ NexScan v3.0

**Advanced multi-threaded port scanner with a dark terminal-inspired GUI.**

![CI](https://github.com/Yeongwonhan-Jeolmang/NexScan/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-GPLv3-blue)

---

## Features

- Multi-threaded TCP Connect scanning (up to 1 000 concurrent threads) on a single
  worker pool shared across all hosts, with parallel host discovery
- UDP scanning with service-specific payload probes (ICMP port-unreachable ⇒ closed)
- Raw SYN / ACK / FIN / XMAS / NULL / Window scans *(requires root, IPv4, Linux/macOS)*
- Banner grabbing & protocol-aware product/version fingerprinting
  (OpenSSH, Apache, nginx, IIS, vsFTPd, Postfix, Exim, Dovecot, MySQL/MariaDB, Redis, VNC, …)
- SSL/TLS certificate inspection (CN, SANs, issuer, expiry, self-signed) + HTTP banner over TLS
- Heuristic OS detection (TTL + port fingerprint)
- CIDR range, IP range, and multi-host scanning
- Real-time live results stream with pause / resume, rate limiting and jitter
- Export to JSON, CSV, HTML, XML, Markdown, and plain text
- Port presets (Top 100, Top 1000, Web, Database, …) and custom ranges
- Host discovery & reverse DNS lookup
- Result filtering, sorting, and context menus
- Scan comparison — Detect port changes between scan runs
- CVE vulnerability lookup — Check discovered services against NVD database
- Geolocation & WHOIS — Map IP addresses to geographical locations
- Scan timeline — Query scan history by date, target, or service
- Batch processing — Scan multiple targets from file (one per line)
- ETA tracking — Real-time scan progress with estimated completion time
- Profile management — Save/load scan configurations (last session is remembered)
- Scan history in the GUI — save, reload and diff runs side by side

---

## Project Layout

```
nexscan/
├── nexscan.py          # Entry point (GUI + CLI)
├── gui/
│   └── app.py          # Tkinter main window
├── core/
│   ├── scanner.py      # Scanning engine, data classes
│   ├── raw_scan.py     # Raw-packet SYN/ACK/FIN/XMAS/NULL/Window engine
│   ├── fingerprint.py  # Banner → product/version, TLS certificate decoding
│   ├── service_db.py   # Port → service mapping & presets
│   ├── engine.py       # High-level scanning API with validation
│   ├── db.py           # SQLite persistence & timeline queries
│   ├── compare.py      # Scan differential analysis
│   ├── cve_lookup.py   # Vulnerability lookup (NVD API)
│   ├── geoloc.py       # Geolocation & WHOIS lookup
│   └── exceptions.py   # Custom exception hierarchy
├── reports/
│   └── exporter.py     # JSON / CSV / HTML / XML / TXT exporters
├── utils/
│   └── logger.py       # Logging helper
├── tests/              # pytest test suite
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
└── .github/
    └── workflows/
        └── ci.yml
```

---

## Requirements

- Python **3.10+**
- **tkinter** (bundled with most CPython distributions)
  - Debian/Ubuntu: `sudo apt-get install python3-tk`
  - Fedora: `sudo dnf install python3-tkinter`
  - macOS (Homebrew): `brew install python-tk`
- Raw socket scans (SYN, ACK, …) require **root / Administrator** privileges.

NexScan has **no required third-party runtime dependencies** — see [`requirements.txt`](requirements.txt) for details.
Installing the optional [`cryptography`](https://pypi.org/project/cryptography/) package (`pip install -e ".[tls]"`)
gives the most robust certificate parsing; without it NexScan falls back to the standard library.
Development tooling (pytest, ruff, black, mypy) is listed in [`requirements-dev.txt`](requirements-dev.txt).

---

## Installation

```bash
# Clone
git clone https://github.com/Yeongwonhan-Jeolmang/NexScan.git
cd nexscan

# (Optional) create a virtual environment
python -m venv .venv && source .venv/bin/activate

# Install in editable mode (adds the `nexscan` CLI entry point)
pip install -e .

# Or install dev dependencies directly from requirements-dev.txt
pip install -r requirements-dev.txt
```

---

## Usage

### GUI mode

```bash
python nexscan.py
# or, after pip install -e .
nexscan
```

| Shortcut | Action |
|----------|--------|
| `F5` | Start scan |
| `F6` | Pause / resume |
| `Escape` | Stop scan |
| `Ctrl+E` | Export menu |
| `Ctrl+L` | Clear results |
| `Ctrl+F` | Focus filter |
| `Ctrl+C` | Copy selected rows |
| `Ctrl+S` / `Ctrl+O` | Save / load profile |
| `Ctrl+H` | Scan history |

### CLI mode

```bash
python nexscan.py --cli -t 192.168.1.0/24 -p 22,80,443,1-1024

# Scanning options
  -t, --targets         IP, hostname, CIDR, or range (10.0.0.1-50)  (required in CLI mode)
  -f, --target-file     Read targets from file (one per line, # comments allowed)
  -p, --ports           Port spec or preset, e.g. 1-1024, 22,80,443, top100, web, database
  -s, --scan-type       tcp | udp | syn | ack | fin | xmas | null | window  (default: tcp)
      --threads         Concurrent threads  (default: 300)
      --timeout         Socket timeout in seconds  (default: 1.5)
      --rate-limit MS   Minimum delay between probes
      --jitter MS       Random extra delay per probe
      --retries N       Probe attempts for UDP / raw scans  (default: 1)
      --no-banner       Disable banner grabbing
      --no-rdns         Skip reverse DNS lookups
      --os-detect       Enable heuristic OS detection
      --skip-discovery  Skip host-up check
  -q, --quiet           Hide the progress bar and down hosts
  -o, --output          Output file (.json / .csv / .html / .txt / .xml / .md)
      --save-db         Persist scan to SQLite history database

# Advanced analysis options
      --cve-lookup      Lookup CVEs for fingerprinted services (NVD API)
      --geoloc          Geolocation + RDAP/WHOIS lookup on public IPs
      --compare ID      After scanning, show changes versus stored run ID
      --diff OLD NEW    Compare two stored runs (no scan)
      --timeline [MODE] list | target:<host> | since:<date> | range:<start>..<end>
      --limit N         Rows shown by --timeline (default: 20)
      --db-path PATH    Path to scan history database (default: nexscan_history.db)

Press Ctrl+C during a CLI scan to stop early — partial results are still printed/exported.
```

#### Examples

```bash
# Scan a single host, common ports
python nexscan.py --cli -t 10.0.0.1 -p 1-1024

# Scan a /24 subnet, save HTML report
python nexscan.py --cli -t 192.168.1.0/24 -p 80,443,8080 -o report.html

# UDP scan with OS detection
python nexscan.py --cli -t 10.0.0.1 -p 53,161,123 -s udp --os-detect

# Scan with vulnerability & geolocation analysis
python nexscan.py --cli -t 192.168.1.1 -p 22,80,443 --cve-lookup --geoloc --save-db

# Batch scan from file with history persistence
python nexscan.py --cli -f targets.txt -p 1-1000 --save-db

# Compare current scan against previous run
python nexscan.py --cli -t 192.168.1.1 -p 22,80,443 --compare 5 --db-path nexscan_history.db

# View scan history timeline
python nexscan.py --cli --timeline list --db-path nexscan_history.db

# Half-open SYN scan of the top-100 preset (root)
sudo python nexscan.py --cli -t 10.0.0.0/24 -p top100 -s syn

# Diff two stored runs
python nexscan.py --cli --diff 3 7
```

---

## Advanced Features

### Scan Comparison
Compare results between two scan runs to detect changes:
```bash
# First scan
python nexscan.py --cli -t 192.168.1.1 -p 22,80,443 --save-db

# ... time passes ...

# Second scan with comparison
python nexscan.py --cli -t 192.168.1.1 -p 22,80,443 --compare 1 --save-db
```
Output shows: new ports (✚), closed ports (✗), state changes (⟳), service updates (ⓘ)

### CVE Vulnerability Lookup
Automatically check discovered services against the NVD database:
```bash
python nexscan.py --cli -t 192.168.1.1 -p 22,80,443 --cve-lookup
```
- Severity indicators: 🔴 CRITICAL, 🟠 HIGH, 🟡 MEDIUM, 🟢 LOW
- Queries the official NVD API using the fingerprinted product/version (services without a
  version string are skipped instead of producing unrelated hits)
- Results are cached per (product, version) and requests respect NVD's rate limit;
  set `NVD_API_KEY` to raise it from 5 to 50 requests per 30 s
- Falls back to a small offline list when NVD is unreachable (marked "verify version")

### Geolocation & WHOIS
Map discovered IP addresses to their geographical location and ISP:
```bash
python nexscan.py --cli -t 192.168.1.0/24 --geoloc
```
- Displays: Country, city, coordinates, ISP, AS number, plus RDAP network/owner/abuse contact
- Uses free ipapi.co API (30K requests/month limit) and rdap.org
- Private/reserved addresses are skipped locally (no wasted lookups)

### Scan Timeline & History
Query scan history by date, target, or browse all scans:
```bash
# View recent scans
python nexscan.py --cli --timeline list

# Filter by host, start date, or a date range (ISO format)
python nexscan.py --cli --timeline target:192.168.1.1
python nexscan.py --cli --timeline since:2026-01-01
python nexscan.py --cli --timeline range:2026-01-01..2026-01-31
```
All scans are persisted to SQLite with `--save-db` flag.

### Batch Target Processing
Read targets from a file for large-scale scans:
```bash
# targets.txt (one target per line)
# 192.168.1.1
# 10.0.0.0/24
# example.com

python nexscan.py --cli -f targets.txt -p 22,80,443 --save-db
```

### GUI Enhancements
- **Live results**: rows, host list and statistics update while the scan runs; filter
  (plain or regex), sort by any column heading, and toggle filtered/closed ports at any time
- **History Tab**: save runs (or auto-save every scan), reload them, and diff a run against the
  current scan or two runs against each other
- **Vulnerabilities Tab**: background CVE and geolocation/WHOIS lookups with clickable NVD links
- **Profile Save/Load**: `Ctrl+S` / `Ctrl+O`; the last session's settings are restored on start
- **ETA Tracking**: estimated completion time and throughput (paused time excluded)
- **Port detail**: TLS certificate summary with expiry / self-signed / deprecated-protocol
  warnings, copy banner / JSON, open web ports in the browser

---

## Development

```bash
pip install -r requirements-dev.txt
# or via pyproject extras
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check .

# Format
black .

# Type-check
mypy core/ reports/ utils/
```

---

## Legal Notice

> **Only scan systems you own or have explicit written permission to scan.**
> Unauthorized port scanning may violate local laws and service agreements.
> NexScan is provided for authorized security testing and network administration only.

---

## Credits

| Name | Role |
|------|------|
| Florian van den Bersselaar | UI design & frontend |
| Anna Zieleman | Core development & exporter |
| Hana Eun-Seo | Core development |
| Simon Roberge | Core development |

---

## License

GPL-3.0-or-later © Florian van den Bersselaar, Hana Eun-Seo, Simon Roberge, Anna Zieleman