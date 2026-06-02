"""WHOIS and geolocation lookup utility."""

import urllib.request
import json
from dataclasses import dataclass
from typing import Optional
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class GeoLocation:
    ip_address: str
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    isp: str = ""
    organization: str = ""
    as_number: str = ""


def lookup_geolocation(ip_address: str) -> Optional[GeoLocation]:
    """
    Lookup geolocation info for an IP using free IP.json API.
    No authentication required.
    """
    try:
        url = f"https://ipapi.co/{ip_address}/json/"
        req = urllib.request.Request(url, headers={"User-Agent": "NexScan/2.0"})

        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())

            if data.get("error"):
                logger.debug(f"Geolocation lookup failed for {ip_address}: {data.get('error')}")
                return None

            return GeoLocation(
                ip_address=ip_address,
                country=data.get("country_name", ""),
                country_code=data.get("country_code", ""),
                region=data.get("region", ""),
                city=data.get("city", ""),
                latitude=float(data.get("latitude", 0.0)),
                longitude=float(data.get("longitude", 0.0)),
                isp=data.get("org", ""),
                as_number=data.get("asn", ""),
            )
    except Exception as e:
        logger.debug(f"Geolocation lookup error for {ip_address}: {e}")
        return None


def lookup_whois_simple(ip_address: str) -> dict:
    """
    Lightweight WHOIS lookup using WHOIS.com API.
    Returns basic ownership/registration info.
    """
    try:
        # Using public WHOIS server (no API key needed)
        url = f"https://www.whois.com/whois/{ip_address}"
        req = urllib.request.Request(url, headers={"User-Agent": "NexScan/2.0"})

        with urllib.request.urlopen(req, timeout=5) as response:
            html = response.read().decode()
            # Parse basic info from response
            info = {}
            if "registrar" in html.lower():
                info["type"] = "registered"
            if "isp" in html.lower() or "hosting" in html.lower():
                info["category"] = "hosting"
            return info if info else {"status": "registered"}
    except Exception as e:
        logger.debug(f"WHOIS lookup error for {ip_address}: {e}")
        return {}


def format_geolocation_report(geo: GeoLocation) -> str:
    """Format geolocation data as readable report."""
    if not geo:
        return "  ✗ Geolocation info unavailable"

    lines = [f"  📍 Geolocation for {geo.ip_address}:"]
    lines.append(f"    Location  : {geo.city}, {geo.region}, {geo.country} ({geo.country_code})")
    if geo.latitude and geo.longitude:
        lines.append(f"    Coords    : {geo.latitude:.4f}, {geo.longitude:.4f}")
    if geo.isp:
        lines.append(f"    ISP       : {geo.isp}")
    if geo.as_number:
        lines.append(f"    ASN       : {geo.as_number}")

    return "\n".join(lines)
