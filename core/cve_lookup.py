"""CVE vulnerability lookup integration."""

import collections
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Dict, List, Tuple

from utils.logger import get_logger

logger = get_logger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Optional NVD API key (raises the rate limit from 5 to 50 requests / 30 s)
NVD_API_KEY_ENV = "NVD_API_KEY"

# Product names in banners → better NVD keyword phrases
_PRODUCT_ALIASES = {
    "apache": "Apache HTTP Server",
    "microsoft-iis": "Microsoft IIS",
    "mysql": "MySQL",
    "mariadb": "MariaDB",
}

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


@dataclass
class CVEInfo:
    cve_id: str
    description: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    score: float
    url: str


class _RateLimiter:
    """Sliding-window limiter matching NVD's public quotas."""

    def __init__(self):
        self._lock = threading.Lock()
        self._calls: collections.deque = collections.deque()

    def wait(self):
        has_key = bool(os.environ.get(NVD_API_KEY_ENV))
        limit, window = (50, 30.0) if has_key else (5, 30.0)
        with self._lock:
            now = time.monotonic()
            while self._calls and now - self._calls[0] > window:
                self._calls.popleft()
            if len(self._calls) >= limit:
                time.sleep(window - (now - self._calls[0]) + 0.1)
            self._calls.append(time.monotonic())


_limiter = _RateLimiter()
_cache: Dict[Tuple[str, int], List[CVEInfo]] = {}
_cache_lock = threading.Lock()


def build_query(service_name: str, version: str = "") -> str:
    """
    Build an NVD keyword query, or return "" when there is nothing specific
    enough to look up (a bare protocol name like "ssh" only yields noise).
    """
    version = (version or "").strip()
    if not version or version == "Unknown":
        return ""

    if re.match(r"[A-Za-z]", version):
        # Fingerprinted "Product 1.2.3" — the product name is the best keyword
        product, _, ver = version.partition(" ")
        product = _PRODUCT_ALIASES.get(product.lower(), product)
        return f"{product} {ver}".strip()

    return f"{service_name} {version}".strip()


def lookup_service_cves(service_name: str, version: str = "", limit: int = 5) -> List[CVEInfo]:
    """
    Lookup CVEs for a given service and optional version.
    Uses NVD (National Vulnerability Database) API, with an in-memory cache
    and the bundled offline list as a fallback when NVD is unreachable.
    Returns list of matching CVEs with severity info, worst first.
    """
    query = build_query(service_name, version)
    if not query:
        return []

    key = (query.lower(), limit)
    with _cache_lock:
        if key in _cache:
            return list(_cache[key])

    try:
        cves = _query_nvd(query, limit)
    except Exception as e:
        logger.warning(f"Failed to lookup CVEs for {query}: {e} — using offline cache")
        return _offline_lookup(query)[:limit]

    with _cache_lock:
        _cache[key] = cves
    return list(cves)


def _query_nvd(query: str, limit: int) -> List[CVEInfo]:
    params = urllib.parse.urlencode({"keywordSearch": query, "resultsPerPage": limit})
    headers = {"User-Agent": "NexScan/2.0"}
    api_key = os.environ.get(NVD_API_KEY_ENV)
    if api_key:
        headers["apiKey"] = api_key

    req = urllib.request.Request(f"{NVD_URL}?{params}", headers=headers)
    for attempt in range(3):
        _limiter.wait()
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
            break
        except urllib.error.HTTPError as e:
            # 403 / 429 / 503 = throttled; back off and retry
            if e.code in (403, 429, 503) and attempt < 2:
                time.sleep(6 * (attempt + 1))
                continue
            raise

    cves = []
    for vuln in data.get("vulnerabilities", [])[:limit]:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        descriptions = cve.get("descriptions", [])
        description = next(
            (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
            descriptions[0].get("value", "") if descriptions else "",
        )
        severity, score = _extract_cvss(cve.get("metrics", {}))
        cves.append(
            CVEInfo(
                cve_id=cve_id,
                description=description[:160],
                severity=severity,
                score=score,
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            )
        )

    cves.sort(key=lambda c: (c.score, _SEVERITY_ORDER.get(c.severity, 0)), reverse=True)
    return cves


def _extract_cvss(metrics: dict) -> Tuple[str, float]:
    """Pick the newest CVSS metric available (v4.0 → v3.1 → v3.0 → v2)."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        cvss = entry.get("cvssData", {})
        score = float(cvss.get("baseScore", 0.0) or 0.0)
        # v2 keeps the severity on the metric, v3+/v4 inside cvssData
        severity = cvss.get("baseSeverity") or entry.get("baseSeverity") or "UNKNOWN"
        return str(severity).upper(), score
    return "UNKNOWN", 0.0


def _offline_lookup(query: str) -> List[CVEInfo]:
    q = query.lower()
    hits: List[CVEInfo] = []
    for product, cves in COMMON_CVES.items():
        if product.lower() in q:
            # The offline list is not version-aware — say so instead of implying a match
            hits.extend(
                CVEInfo(
                    c.cve_id,
                    f"[offline, verify version] {c.description}",
                    c.severity,
                    c.score,
                    c.url,
                )
                for c in cves
            )
    return hits


def severity_rank(severity: str) -> int:
    """Numeric rank for sorting / colouring (CRITICAL=4 … LOW=1, unknown=0)."""
    return _SEVERITY_ORDER.get((severity or "").upper(), 0)


def format_cve_report(service_name: str, version: str, cves: List[CVEInfo]) -> str:
    """Format CVE findings as a readable report."""
    if not cves:
        return f"  ✓ No known CVEs for {service_name} {version}"

    lines = [f"  ⚠ CVEs for {service_name} {version}:"]
    for cve in cves:
        severity_icon = (
            "🔴"
            if cve.severity == "CRITICAL"
            else "🟠"
            if cve.severity == "HIGH"
            else "🟡"
            if cve.severity == "MEDIUM"
            else "🟢"
        )
        desc = cve.description if len(cve.description) < 160 else cve.description[:157] + "..."
        lines.append(f"    {severity_icon} {cve.cve_id}  [{cve.severity} / {cve.score}]  {desc}")
        lines.append(f"       {cve.url}")

    return "\n".join(lines)


# For offline mode: pre-cached common service CVEs (optional fallback)
COMMON_CVES = {
    "Apache": [
        CVEInfo(
            "CVE-2021-41773",
            "Path traversal in Apache HTTP Server",
            "CRITICAL",
            9.8,
            "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
        ),
        CVEInfo(
            "CVE-2021-42013",
            "Path traversal in Apache HTTP Server",
            "CRITICAL",
            9.8,
            "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
        ),
    ],
    "nginx": [
        CVEInfo(
            "CVE-2021-3618",
            "Memory disclosure in nginx resolver",
            "MEDIUM",
            5.3,
            "https://nvd.nist.gov/vuln/detail/CVE-2021-3618",
        ),
    ],
    "OpenSSH": [
        CVEInfo(
            "CVE-2018-15473",
            "User enumeration in OpenSSH",
            "MEDIUM",
            5.3,
            "https://nvd.nist.gov/vuln/detail/CVE-2018-15473",
        ),
        CVEInfo(
            "CVE-2024-6387",
            "regreSSHion: unauthenticated RCE race condition in OpenSSH sshd",
            "HIGH",
            8.1,
            "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
        ),
    ],
    "MySQL": [
        CVEInfo(
            "CVE-2021-2109",
            "Oracle MySQL vulnerability",
            "HIGH",
            8.8,
            "https://nvd.nist.gov/vuln/detail/CVE-2021-2109",
        ),
    ],
    "PostgreSQL": [
        CVEInfo(
            "CVE-2021-3393",
            "PostgreSQL memory leak",
            "MEDIUM",
            6.5,
            "https://nvd.nist.gov/vuln/detail/CVE-2021-3393",
        ),
    ],
    "vsFTPd": [
        CVEInfo(
            "CVE-2011-2523",
            "vsftpd 2.3.4 backdoor (smiley-face command execution)",
            "CRITICAL",
            9.8,
            "https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
        ),
    ],
}
