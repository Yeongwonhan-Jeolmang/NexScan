"""CVE vulnerability lookup integration."""

import json
import urllib.request
from typing import List, Optional
from dataclasses import dataclass
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class CVEInfo:
    cve_id: str
    description: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    score: float
    url: str


def lookup_service_cves(service_name: str, version: str = "", limit: int = 5) -> List[CVEInfo]:
    """
    Lookup CVEs for a given service and optional version.
    Uses NVD (National Vulnerability Database) API.
    Returns list of matching CVEs with severity info.
    """
    cves = []
    try:
        # Format query
        query = f"{service_name}"
        if version and version != "Unknown":
            query += f" {version}"

        # Use NVD API (free, no key required)
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = f"?keywordSearch={urllib.parse.quote(query)}&resultsPerPage={limit}"
        full_url = url + params

        req = urllib.request.Request(full_url, headers={"User-Agent": "NexScan/2.0"})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())

            for vuln in data.get("vulnerabilities", [])[:limit]:
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                description = cve.get("descriptions", [{}])[0].get("value", "")
                metrics = cve.get("metrics", {})

                # Extract severity and score
                severity = "UNKNOWN"
                score = 0.0
                cvss = (
                    metrics.get("cvssMetricV31")
                    or metrics.get("cvssMetricV3")
                    or metrics.get("cvssMetricV2")
                )
                if cvss:
                    cvss_data = cvss[0].get("cvssData", {})
                    score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")

                url_str = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

                if cve_id:
                    cves.append(
                        CVEInfo(
                            cve_id=cve_id,
                            description=description[:100],
                            severity=severity,
                            score=score,
                            url=url_str,
                        )
                    )

    except Exception as e:
        logger.warning(f"Failed to lookup CVEs for {service_name}: {e}")

    return cves


def format_cve_report(service_name: str, version: str, cves: List[CVEInfo]) -> str:
    """Format CVE findings as a readable report."""
    if not cves:
        return f"  ✓ No known CVEs for {service_name} {version}"

    lines = [f"  ⚠ CVEs for {service_name} {version}:"]
    for cve in cves:
        severity_icon = (
            "🔴"
            if cve.severity == "CRITICAL"
            else "🟠" if cve.severity == "HIGH" else "🟡" if cve.severity == "MEDIUM" else "🟢"
        )
        lines.append(
            f"    {severity_icon} {cve.cve_id}  [{cve.severity} / {cve.score}]  {cve.description}..."
        )
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
}
