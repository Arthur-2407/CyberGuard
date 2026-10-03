"""
ioc_classifier.py — Indicator of Compromise (IOC) Classifier for CyberGuard.

Accurately classifies indicators into:
- Hashes: MD5 (32 hex), SHA-1 (40 hex), SHA-256 (64 hex)
- URLs: Public URLs vs Localhost / Private network URLs
- IP Addresses: Public IPv4/IPv6 vs Localhost / RFC 1918 Private IPv4 / IPv6
- Domains: Public domains vs Local / Internal hostnames
- Unknown
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse
from typing import Dict, Any, Optional
from enum import Enum


class IOCType(str, Enum):
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    PUBLIC_URL = "public_url"
    LOCAL_URL = "local_url"
    PUBLIC_IP = "public_ip"
    LOCAL_IP = "local_ip"
    PUBLIC_DOMAIN = "public_domain"
    LOCAL_DOMAIN = "local_domain"
    UNKNOWN = "unknown"


class IOCScope(str, Enum):
    PUBLIC = "PUBLIC"
    LOCAL_OR_PRIVATE = "LOCAL_OR_PRIVATE"
    UNKNOWN = "UNKNOWN"


_LOCAL_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
}

_LOCAL_DOMAIN_SUFFIXES = (
    ".local",
    ".internal",
    ".lan",
    ".home",
    ".corp",
    ".test",
    ".example",
    ".invalid",
    ".localhost",
)


def is_private_or_loopback_ip(ip_str: str) -> bool:
    """Check if an IP string is loopback, private, link-local, or reserved."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return bool(
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return False


class IOCClassifier:
    """Classifies indicator strings into typed, scoped threat intelligence targets."""

    @staticmethod
    def classify(indicator: str) -> Dict[str, Any]:
        cleaned = (indicator or "").strip()
        if not cleaned:
            return {
                "indicator": "",
                "ioc_type": IOCType.UNKNOWN.value,
                "category": "unknown",
                "scope": IOCScope.UNKNOWN.value,
                "is_local": False,
                "is_supported": False,
                "message": "Empty indicator provided.",
            }

        # 1. Hashes (MD5, SHA-1, SHA-256)
        if re.match(r"^[a-fA-F0-9]{64}$", cleaned):
            return {
                "indicator": cleaned.lower(),
                "ioc_type": IOCType.HASH_SHA256.value,
                "category": "hash",
                "hash_type": "SHA-256",
                "scope": IOCScope.PUBLIC.value,
                "is_local": False,
                "is_supported": True,
                "message": "Valid SHA-256 hash.",
            }
        if re.match(r"^[a-fA-F0-9]{40}$", cleaned):
            return {
                "indicator": cleaned.lower(),
                "ioc_type": IOCType.HASH_SHA1.value,
                "category": "hash",
                "hash_type": "SHA-1",
                "scope": IOCScope.PUBLIC.value,
                "is_local": False,
                "is_supported": True,
                "message": "Valid SHA-1 hash.",
            }
        if re.match(r"^[a-fA-F0-9]{32}$", cleaned):
            return {
                "indicator": cleaned.lower(),
                "ioc_type": IOCType.HASH_MD5.value,
                "category": "hash",
                "hash_type": "MD5",
                "scope": IOCScope.PUBLIC.value,
                "is_local": False,
                "is_supported": True,
                "message": "Valid MD5 hash.",
            }

        # 2. Pure IP addresses (IPv4 / IPv6)
        try:
            ip_obj = ipaddress.ip_address(cleaned)
            is_local = (
                ip_obj.is_loopback
                or ip_obj.is_private
                or ip_obj.is_link_local
                or ip_obj.is_reserved
                or ip_obj.is_unspecified
            )
            ioc_type = IOCType.LOCAL_IP if is_local else IOCType.PUBLIC_IP
            scope = IOCScope.LOCAL_OR_PRIVATE if is_local else IOCScope.PUBLIC
            return {
                "indicator": str(ip_obj),
                "ioc_type": ioc_type.value,
                "category": "ip",
                "ip_version": ip_obj.version,
                "scope": scope.value,
                "is_local": is_local,
                "is_supported": True,
                "message": "Local or private IP address." if is_local else f"Valid public IPv{ip_obj.version} address.",
            }
        except ValueError:
            pass

        # 3. URLs (explicit scheme http:// or https://)
        if cleaned.lower().startswith(("http://", "https://")):
            parsed = urlparse(cleaned)
            hostname = (parsed.hostname or "").lower()
            port = parsed.port

            is_local = (
                hostname in _LOCAL_HOSTNAMES
                or hostname.endswith(_LOCAL_DOMAIN_SUFFIXES)
                or is_private_or_loopback_ip(hostname)
            )

            ioc_type = IOCType.LOCAL_URL if is_local else IOCType.PUBLIC_URL
            scope = IOCScope.LOCAL_OR_PRIVATE if is_local else IOCScope.PUBLIC

            return {
                "indicator": cleaned,
                "ioc_type": ioc_type.value,
                "category": "url",
                "hostname": hostname,
                "port": port,
                "scheme": parsed.scheme.lower(),
                "scope": scope.value,
                "is_local": is_local,
                "is_supported": True,
                "message": (
                    "LOCAL / PRIVATE URL: This address refers to a local development environment or private network. "
                    "Public threat intelligence does not apply."
                ) if is_local else "Valid public URL.",
            }

        # 4. Hostname / Domain (e.g. google.com, localhost, test.internal)
        # Check if contains slashes or path characters
        if "/" in cleaned or " " in cleaned:
            return {
                "indicator": cleaned,
                "ioc_type": IOCType.UNKNOWN.value,
                "category": "unknown",
                "scope": IOCScope.UNKNOWN.value,
                "is_local": False,
                "is_supported": False,
                "message": "Malformed indicator. URLs must include http:// or https://.",
            }

        cleaned_host = cleaned.lower()
        # Strip trailing dot if present
        if cleaned_host.endswith("."):
            cleaned_host = cleaned_host[:-1]

        # Check local hostnames
        if cleaned_host in _LOCAL_HOSTNAMES or cleaned_host.endswith(_LOCAL_DOMAIN_SUFFIXES):
            return {
                "indicator": cleaned_host,
                "ioc_type": IOCType.LOCAL_DOMAIN.value,
                "category": "domain",
                "domain": cleaned_host,
                "scope": IOCScope.LOCAL_OR_PRIVATE.value,
                "is_local": True,
                "is_supported": True,
                "message": "LOCAL / PRIVATE DOMAIN: Internal development hostname.",
            }

        # Check domain pattern (at least one dot, valid domain characters)
        if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$", cleaned_host):
            return {
                "indicator": cleaned_host,
                "ioc_type": IOCType.PUBLIC_DOMAIN.value,
                "category": "domain",
                "domain": cleaned_host,
                "scope": IOCScope.PUBLIC.value,
                "is_local": False,
                "is_supported": True,
                "message": "Valid public domain name.",
            }

        # Fallback unknown
        return {
            "indicator": cleaned,
            "ioc_type": IOCType.UNKNOWN.value,
            "category": "unknown",
            "scope": IOCScope.UNKNOWN.value,
            "is_local": False,
            "is_supported": False,
            "message": "Unrecognized indicator format. Enter a valid hash, public URL, domain, or IP address.",
        }
