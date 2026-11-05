"""WHOIS and geolocation lookup utility."""

import ipaddress
import json
import threading
import urllib.request
from dataclasses import dataclass
from typing import Dict, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

_HEADERS = {"User-Agent": "NexScan/2.0", "Accept": "application/json"}

_geo_cache: Dict[str, Optional["GeoLocation"]] = {}
_whois_cache: Dict[str, dict] = {}
_cache_lock = threading.Lock()


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


def is_public_ip(ip_address: str) -> bool:
    """True for globally routable addresses (geolocation is meaningless otherwise)."""
    try:
        return ipaddress.ip_address(ip_address).is_global
    except ValueError:
        return False


def lookup_geolocation(ip_address: str) -> Optional[GeoLocation]:
    """
    Lookup geolocation info for an IP using free IP.json API.
    No authentication required. Private / reserved addresses are skipped
    locally and results are cached per process.
    """
    if not is_public_ip(ip_address):
        logger.debug(f"Skipping geolocation for non-public address {ip_address}")
        return None

    with _cache_lock:
        if ip_address in _geo_cache:
            return _geo_cache[ip_address]

    geo = None
    try:
        url = f"https://ipapi.co/{ip_address}/json/"
        req = urllib.request.Request(url, headers=_HEADERS)

        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())

        if data.get("error"):
            logger.debug(f"Geolocation lookup failed for {ip_address}: {data.get('reason')}")
        else:
            geo = GeoLocation(
                ip_address=ip_address,
                country=data.get("country_name", "") or "",
                country_code=data.get("country_code", "") or "",
                region=data.get("region", "") or "",
                city=data.get("city", "") or "",
                latitude=float(data.get("latitude") or 0.0),
                longitude=float(data.get("longitude") or 0.0),
                isp=data.get("org", "") or "",
                organization=data.get("org", "") or "",
                as_number=data.get("asn", "") or "",
            )
    except Exception as e:
        logger.debug(f"Geolocation lookup error for {ip_address}: {e}")
        return None  # don't cache transient failures

    with _cache_lock:
        _geo_cache[ip_address] = geo
    return geo


def lookup_whois_simple(ip_address: str) -> dict:
    """
    Lightweight WHOIS lookup using RDAP (the structured successor to WHOIS).
    Returns basic ownership/registration info: network name, handle, CIDR,
    country, owning organisation and abuse contact when available.
    """
    if not is_public_ip(ip_address):
        return {}

    with _cache_lock:
        if ip_address in _whois_cache:
            return dict(_whois_cache[ip_address])

    try:
        # rdap.org redirects to the authoritative regional registry
        req = urllib.request.Request(f"https://rdap.org/ip/{ip_address}", headers=_HEADERS)
        with urllib.request.urlopen(req, timeout=8) as response:
            data = json.loads(response.read().decode())
    except Exception as e:
        logger.debug(f"WHOIS lookup error for {ip_address}: {e}")
        return {}

    info = {
        "name": data.get("name", ""),
        "handle": data.get("handle", ""),
        "country": data.get("country", ""),
        "range": f"{data.get('startAddress', '')} - {data.get('endAddress', '')}".strip(" -"),
    }
    cidrs = data.get("cidr0_cidrs") or []
    if cidrs:
        c = cidrs[0]
        prefix = c.get("v4prefix") or c.get("v6prefix")
        if prefix:
            info["cidr"] = f"{prefix}/{c.get('length')}"

    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        name = _vcard_name(entity)
        if "registrant" in roles and name and "organization" not in info:
            info["organization"] = name
        if "abuse" in roles:
            email = _vcard_field(entity, "email")
            if email:
                info["abuse_email"] = email
        for sub in entity.get("entities", []):
            if "abuse" in sub.get("roles", []) and "abuse_email" not in info:
                email = _vcard_field(sub, "email")
                if email:
                    info["abuse_email"] = email

    info = {k: v for k, v in info.items() if v}
    with _cache_lock:
        _whois_cache[ip_address] = info
    return dict(info)


def _vcard_field(entity: dict, field_name: str) -> str:
    vcard = entity.get("vcardArray") or []
    if len(vcard) < 2:
        return ""
    for item in vcard[1]:
        if item and item[0] == field_name and len(item) >= 4:
            return str(item[3])
    return ""


def _vcard_name(entity: dict) -> str:
    return _vcard_field(entity, "fn")


def format_geolocation_report(geo: Optional[GeoLocation], whois: Optional[dict] = None) -> str:
    """Format geolocation data (and optional RDAP/WHOIS info) as readable report."""
    if not geo:
        return "  ✗ Geolocation info unavailable"

    lines = [f"  📍 Geolocation for {geo.ip_address}:"]
    place = ", ".join(p for p in (geo.city, geo.region, geo.country) if p)
    lines.append(f"    Location  : {place} ({geo.country_code})")
    if geo.latitude and geo.longitude:
        lines.append(f"    Coords    : {geo.latitude:.4f}, {geo.longitude:.4f}")
    if geo.isp:
        lines.append(f"    ISP       : {geo.isp}")
    if geo.as_number:
        lines.append(f"    ASN       : {geo.as_number}")
    if whois:
        if whois.get("name") or whois.get("handle"):
            lines.append(
                f"    Network   : {whois.get('name', '')} {whois.get('handle', '')}".rstrip()
            )
        if whois.get("cidr") or whois.get("range"):
            lines.append(f"    Range     : {whois.get('cidr') or whois.get('range')}")
        if whois.get("organization"):
            lines.append(f"    Owner     : {whois['organization']}")
        if whois.get("abuse_email"):
            lines.append(f"    Abuse     : {whois['abuse_email']}")

    return "\n".join(lines)
