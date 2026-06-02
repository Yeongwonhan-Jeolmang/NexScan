# ◈ NexScan v2.0

**Advanced multi-threaded port scanner with a dark terminal-inspired GUI.**

![CI](https://github.com/Yeongwonhan-Jeolmang/NexScan/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-GPLv3-blue)

---

## Features

- Multi-threaded TCP Connect scanning (up to 1 000 concurrent threads)
- UDP scanning with service-specific payload probes
- Raw SYN / ACK / FIN / XMAS / NULL / Window scans *(requires root)*
- Banner grabbing & service fingerprinting
- SSL/TLS certificate inspection
- Heuristic OS detection (TTL + port fingerprint)
- CIDR range, IP range, and multi-host scanning
- Real-time live results stream with pause / resume
- Export to JSON, CSV, HTML, XML, and plain text
- Port presets (Top 100, Top 1000, Web, Database, …) and custom ranges
- Host discovery & reverse DNS lookup
- Result filtering, sorting, and context menus
- Scan comparison — Detect port changes between scan runs
- CVE vulnerability lookup — Check discovered services against NVD database
- Geolocation & WHOIS — Map IP addresses to geographical locations
- Scan timeline — Query scan history by date, target, or service
- Batch processing — Scan multiple targets from file (one per line)
- ETA tracking — Real-time scan progress with estimated completion time
- Profile management — Save/load scan configurations

---

## Project Layout

```
nexscan/
├── nexscan.py          # Entry point (GUI + CLI)
├── gui/
│   └── app.py          # Tkinter main window
├── core/
│   ├── scanner.py      # Scanning engine, data classes
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

NexScan has **no third-party runtime dependencies** — see [`requirements.txt`](requirements.txt) for details.
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
| `Escape` | Stop scan |
| `Ctrl+E` | Export menu |
| `Ctrl+L` | Clear results |
| `Ctrl+F` | Focus filter |

### CLI mode

```bash
python nexscan.py --cli -t 192.168.1.0/24 -p 22,80,443,1-1024

# Scanning options
  -t, --targets         IP, hostname, CIDR, or range  (required in CLI mode)
  -f, --target-file     Read targets from file (one per line)
  -p, --ports           Port spec, e.g. 1-1024 or 22,80,443  (default: 1-1024)
  -s, --scan-type       tcp | udp | syn  (default: tcp)
      --threads         Concurrent threads  (default: 300)
      --timeout         Socket timeout in seconds  (default: 1.5)
      --no-banner       Disable banner grabbing
      --os-detect       Enable heuristic OS detection
      --skip-discovery  Skip host-up check
  -o, --output          Output file (.json / .csv / .html / .txt / .xml)
      --save-db         Persist scan to SQLite history database

# Advanced analysis options
      --cve-lookup      Lookup CVEs for detected services (NVD API)
      --geoloc          Perform geolocation/WHOIS lookup on discovered IPs
      --compare ID      Compare against previous scan run by ID
      --timeline        Display scan history timeline (list/search/date-range)
      --db-path PATH    Path to scan history database (default: nexscan_history.db)
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
- Queries official NVD API with offline fallback cache

### Geolocation & WHOIS
Map discovered IP addresses to their geographical location and ISP:
```bash
python nexscan.py --cli -t 192.168.1.0/24 --geoloc
```
- Displays: Country, city, coordinates, ISP, AS number
- Uses free ipapi.co API (30K requests/month limit)

### Scan Timeline & History
Query scan history by date, target, or browse all scans:
```bash
# View recent scans
python nexscan.py --cli --timeline list

# Query by date range (ISO format)
python nexscan.py --cli --timeline --db-path nexscan_history.db
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
- **Vulnerabilities Tab**: Browse CVE findings and geolocation data with one click
- **Profile Save/Load**: Use `Ctrl+S` to save scan configurations, `Ctrl+O` to load
- **ETA Tracking**: Real-time estimated completion time (F5 to scan)
- **Regex Filtering**: Advanced filtering with regex pattern support

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