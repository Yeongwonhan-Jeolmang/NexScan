"""
NexScan - Service Fingerprinting
Protocol-aware banner parsing (product / version extraction) and
TLS certificate decoding.
"""

import datetime
import os
import re
import ssl
import tempfile
from typing import Optional

from utils.logger import get_logger

logger = get_logger(__name__)


# ─────────────────────────── BANNER SIGNATURES ───────────────────────────
# Each signature: (service_hint, compiled regex, product override or None).
# The regex must expose a "product" group and may expose a "version" group.

_SIGNATURES = [
    (
        "ssh",
        re.compile(r"^SSH-[\d.]+-(?P<product>[A-Za-z][A-Za-z-]*)[_-](?P<version>[\w.]+)", re.M),
        None,
    ),
    (
        "http",
        re.compile(
            r"^Server:\s*(?P<product>[A-Za-z][\w .-]*?)(?:/(?P<version>\d[\w.-]*))?\s*(?:\(|$)",
            re.M | re.I,
        ),
        None,
    ),
    (
        "ftp",
        re.compile(
            r"^220[ -].*?(?P<product>vsFTPd|ProFTPD|Pure-FTPd|FileZilla Server|"
            r"Microsoft FTP Service|Serv-U)[ /]*(?P<version>\d[\w.]*)?",
            re.M | re.I,
        ),
        None,
    ),
    (
        "smtp",
        re.compile(
            r"^220[ -].*?(?P<product>Postfix|Exim|Sendmail|Microsoft ESMTP MAIL Service|"
            r"OpenSMTPD|qmail)[ /]*(?P<version>\d[\w.]*)?",
            re.M | re.I,
        ),
        None,
    ),
    (
        "imap",
        re.compile(r"^\* OK.*?(?P<product>Dovecot|Cyrus|Courier)", re.M | re.I),
        None,
    ),
    (
        "pop3",
        re.compile(r"^\+OK.*?(?P<product>Dovecot|Cyrus|Courier|Qpopper)", re.M | re.I),
        None,
    ),
    ("redis", re.compile(r"^(?P<product>\+PONG|-NOAUTH|-DENIED)", re.M), "Redis"),
    ("mysql", re.compile(r"(?P<version>\d+\.\d+\.\d+)-(?P<product>MariaDB)", re.I), None),
    ("mysql", re.compile(r"(?P<product>mysql_native_password|caching_sha2_password)"), "MySQL"),
    (
        "vnc",
        re.compile(r"^(?P<product>RFB) (?P<version>\d{3}\.\d{3})", re.M),
        "VNC (RFB)",
    ),
]

_PROTOCOL_HINTS = [
    ("ssh", re.compile(r"^SSH-\d")),
    ("http", re.compile(r"^HTTP/\d")),
    ("ftp", re.compile(r"^220[ -].*FTP", re.I)),
    ("smtp", re.compile(r"^220[ -].*(SMTP|mail)", re.I)),
    ("pop3", re.compile(r"^\+OK")),
    ("imap", re.compile(r"^\* OK")),
    ("redis", re.compile(r"^(\+PONG|-NOAUTH|-ERR)")),
    ("vnc", re.compile(r"^RFB \d")),
]

_GENERIC_VERSION = [
    re.compile(r"(\d+\.\d+\.\d+[-.\w]*)"),
    re.compile(r"v(\d+\.\d+[-.\w]*)", re.I),
    re.compile(r"version (\d+\.\d+[-.\w]*)", re.I),
]

# Sanity guard: generic matches longer than this are almost always noise.
_MAX_VERSION_LEN = 40


def identify(banner: str, port: int = 0) -> tuple[str, str]:
    """
    Identify a service from its banner.

    Returns ``(service_hint, version)`` where *service_hint* is a protocol name
    (``"ssh"``, ``"http"``, …) or ``""`` when the banner gives no clue, and
    *version* is a human-readable ``"Product 1.2.3"`` string or ``""``.
    """
    if not banner:
        return "", ""

    for service, rx, override in _SIGNATURES:
        m = rx.search(banner)
        if not m:
            continue
        product = override or m.group("product").strip()
        version = (m.groupdict().get("version") or "").strip()
        if service == "mysql" and not version:
            gm = _GENERIC_VERSION[0].search(banner)
            version = gm.group(1) if gm else ""
        text = f"{product} {version}".strip()
        return service, text[:_MAX_VERSION_LEN]

    hint = ""
    for service, rx in _PROTOCOL_HINTS:
        if rx.search(banner):
            hint = service
            break

    return hint, generic_version(banner)


def generic_version(banner: str) -> str:
    """Fallback version extraction used when no signature matches."""
    if not banner:
        return ""
    for rx in _GENERIC_VERSION:
        m = rx.search(banner)
        if m and len(m.group(0)) <= _MAX_VERSION_LEN:
            return m.group(0)
    return ""


# ─────────────────────────── TLS CERTIFICATES ───────────────────────────

_CERT_TIME_FMT = "%b %d %H:%M:%S %Y GMT"


def decode_der_cert(der: Optional[bytes]) -> dict:
    """
    Decode a DER-encoded X.509 certificate into a flat dict.

    Uses the optional ``cryptography`` package when available, otherwise falls
    back to CPython's internal certificate decoder. Returns ``{}`` on failure.
    """
    if not der:
        return {}

    info = _decode_with_cryptography(der)
    if info is None:
        info = _decode_with_stdlib(der)
    if not info:
        return {}

    _annotate_validity(info)
    return info


_crypto_modules: Optional[tuple] = None
_crypto_checked = False


def _load_cryptography() -> Optional[tuple]:
    """Import the optional ``cryptography`` package once; None if unavailable/broken."""
    global _crypto_modules, _crypto_checked
    if _crypto_checked:
        return _crypto_modules
    _crypto_checked = True
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID, NameOID

        _crypto_modules = (x509, ExtensionOID, NameOID)
    except ImportError:
        pass
    except BaseException as e:  # broken native builds raise e.g. pyo3 PanicException
        if isinstance(e, (KeyboardInterrupt, SystemExit)):
            raise
        logger.debug(f"cryptography unusable, using stdlib decoder: {e!r}")
    return _crypto_modules


def _decode_with_cryptography(der: bytes) -> Optional[dict]:
    mods = _load_cryptography()
    if mods is None:
        return None
    x509, ExtensionOID, NameOID = mods

    try:
        cert = x509.load_der_x509_certificate(der)

        def _attr(name, oid):
            vals = name.get_attributes_for_oid(oid)
            return str(vals[0].value) if vals else ""

        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san = [str(v) for v in san_ext.value.get_values_for_type(x509.DNSName)]
        except x509.ExtensionNotFound:
            san = []

        not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
        not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        return {
            "common_name": _attr(cert.subject, NameOID.COMMON_NAME),
            "issuer": _attr(cert.issuer, NameOID.ORGANIZATION_NAME)
            or _attr(cert.issuer, NameOID.COMMON_NAME),
            "not_before": not_before.strftime(_CERT_TIME_FMT),
            "not_after": not_after.strftime(_CERT_TIME_FMT),
            "san": san,
            "self_signed": cert.issuer == cert.subject,
        }
    except Exception as e:
        logger.debug(f"cryptography failed to decode certificate: {e}")
        return {}


def _decode_with_stdlib(der: bytes) -> dict:
    decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if decoder is None:
        return {}

    path = ""
    try:
        fd, path = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w") as f:
            f.write(ssl.DER_cert_to_PEM_cert(der))
        cert = decoder(path)
    except Exception as e:
        logger.debug(f"stdlib failed to decode certificate: {e}")
        return {}
    finally:
        if path:
            try:
                os.remove(path)
            except OSError:
                pass

    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    return {
        "common_name": subject.get("commonName", ""),
        "issuer": issuer.get("organizationName", "") or issuer.get("commonName", ""),
        "not_before": cert.get("notBefore", ""),
        "not_after": cert.get("notAfter", ""),
        "san": [v for k, v in cert.get("subjectAltName", []) if k == "DNS"],
        "self_signed": cert.get("subject") == cert.get("issuer"),
    }


def _annotate_validity(info: dict):
    """Add ``days_left`` / ``expired`` keys based on ``not_after``."""
    not_after = info.get("not_after")
    if not not_after:
        return
    try:
        expires = ssl.cert_time_to_seconds(not_after)
    except ValueError:
        return
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    days_left = int((expires - now) // 86400)
    info["days_left"] = days_left
    info["expired"] = days_left < 0
