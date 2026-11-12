"""
hosting_intelligence.py — Ephemeral Tunnel, Temporary Hosting, and Dynamic Infrastructure Intelligence.

Detects:
  - Cloudflare Quick Tunnels (*.trycloudflare.com)
  - Ngrok endpoints (*.ngrok.io, *.ngrok-free.app, etc.)
  - Localtunnel, Pinggy, Serveo, Pagekite, Bore, Telebit, Localxpose, and other reverse tunnels
  - Dynamic DNS providers (DuckDNS, No-IP, DDNS)
  - Subdomain entropy and multi-word random slug indicators (e.g. colin-representations-murray-reveals)
  - Webhook and out-of-band exfiltration targets

Security & Architecture Principles:
  - Ephemeral hosting alone is NOT classified as malicious (standalone_maliciousness = NOT_ESTABLISHED).
  - Provides rich hosting context: hosting_type, hosting_provider, infrastructure_status.
  - Combines with independent behavioral evidence (permissions, credential forms, lures) to calibrate overall risk.
"""

from __future__ import annotations

import math
import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class HostingType(str, Enum):
    EPHEMERAL_TUNNEL = "EPHEMERAL_TUNNEL"
    DYNAMIC_DNS = "DYNAMIC_DNS"
    FREE_APP_HOSTING = "FREE_APP_HOSTING"
    EXFILTRATION_SINK = "EXFILTRATION_SINK"
    PUBLIC_CLOUD = "PUBLIC_CLOUD"
    STANDARD = "STANDARD"
    LOCAL_PRIVATE = "LOCAL_PRIVATE"


class InfrastructureStatus(str, Enum):
    TEMPORARY_PUBLIC_ENDPOINT = "TEMPORARY_PUBLIC_ENDPOINT"
    DYNAMIC_PUBLIC_ENDPOINT = "DYNAMIC_PUBLIC_ENDPOINT"
    PERSISTENT_INFRASTRUCTURE = "PERSISTENT_INFRASTRUCTURE"
    LOCAL_ENVIRONMENT = "LOCAL_ENVIRONMENT"
    UNKNOWN = "UNKNOWN"


EPHEMERAL_TUNNEL_DOMAINS: Dict[str, Tuple[str, str]] = {
    "trycloudflare.com": ("CLOUDFLARE", "Cloudflare Quick Tunnel (cloudflared)"),
    "ngrok.io": ("NGROK", "Ngrok Tunnel"),
    "ngrok-free.app": ("NGROK", "Ngrok Free Tunnel"),
    "ngrok.app": ("NGROK", "Ngrok Tunnel"),
    "ngrok-free.dev": ("NGROK", "Ngrok Dev Tunnel"),
    "localtunnel.me": ("LOCALTUNNEL", "Localtunnel Public Gateway"),
    "loca.lt": ("LOCALTUNNEL", "Localtunnel Gateway"),
    "pinggy.link": ("PINGGY", "Pinggy Public Tunnel"),
    "pinggy.io": ("PINGGY", "Pinggy Tunnel"),
    "pinggy.online": ("PINGGY", "Pinggy Online Tunnel"),
    "pinggy.app": ("PINGGY", "Pinggy App Gateway"),
    "serveo.net": ("SERVEO", "Serveo SSH Tunnel"),
    "pagekite.me": ("PAGEKITE", "PageKite Dynamic Gateway"),
    "portmap.io": ("PORTMAP", "Portmap.io OpenVPN/SSH Gateway"),
    "portmap.host": ("PORTMAP", "Portmap Host Gateway"),
    "bore.pub": ("BORE", "Bore Lightweight Tunnel"),
    "telebit.io": ("TELEBIT", "Telebit Cloud Relay"),
    "loclx.io": ("LOCALXPOSE", "LocalXpose Reverse Proxy"),
    "pktriot.net": ("PACKETRIOT", "Packetriot Reverse Tunnel"),
    "jprq.live": ("JPRQ", "JPRQ Tunnel Gateway"),
    "jprq.site": ("JPRQ", "JPRQ Site Gateway"),
    "playit.gg": ("PLAYIT", "Playit.gg Tunnel"),
}

DYNAMIC_DNS_DOMAINS: Dict[str, str] = {
    "duckdns.org": "DuckDNS Free Dynamic DNS",
    "no-ip.com": "No-IP Dynamic DNS",
    "no-ip.org": "No-IP Dynamic DNS",
    "ddns.net": "No-IP DDNS",
    "zapto.org": "No-IP Zapto",
    "sytes.net": "No-IP Sytes",
    "freeddns.org": "FreeDDNS Service",
    "dynu.net": "Dynu Dynamic DNS",
    "hopto.org": "Hopto Dynamic DNS",
}

EXFILTRATION_SINK_DOMAINS: Dict[str, str] = {
    "webhook.site": "Webhook.site Data Receiver",
    "pipedream.net": "Pipedream Request Collector",
    "burpcollaborator.net": "Burp Collaborator OAST Server",
    "oastify.com": "ProjectDiscovery OAST Server",
    "interact.sh": "Interactsh OAST Server",
    "canarytokens.org": "CanaryTokens Detection Sink",
}


@dataclass
class HostingIntelligenceResult:
    hosting_type: HostingType = HostingType.STANDARD
    hosting_provider: Optional[str] = None
    provider_label: Optional[str] = None
    infrastructure_status: InfrastructureStatus = InfrastructureStatus.PERSISTENT_INFRASTRUCTURE
    is_ephemeral_tunnel: bool = False
    is_dynamic_dns: bool = False
    is_exfiltration_sink: bool = False
    subdomain: str = ""
    subdomain_entropy: float = 0.0
    has_random_slug: bool = False
    slug_word_count: int = 0
    standalone_maliciousness: str = "NOT_ESTABLISHED"
    risk_contribution: float = 0.0
    confidence: float = 0.85
    evidence_description: str = ""
    indicators: List[str] = field(default_factory=list)

    @property
    def evidence(self) -> List[str]:
        return self.indicators

    @property
    def provider_name(self) -> Optional[str]:
        return self.hosting_provider

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hosting_type": self.hosting_type.value,
            "hosting_provider": self.hosting_provider,
            "provider_label": self.provider_label,
            "infrastructure_status": self.infrastructure_status.value,
            "is_ephemeral_tunnel": self.is_ephemeral_tunnel,
            "is_dynamic_dns": self.is_dynamic_dns,
            "is_exfiltration_sink": self.is_exfiltration_sink,
            "subdomain": self.subdomain,
            "subdomain_entropy": round(self.subdomain_entropy, 2),
            "has_random_slug": self.has_random_slug,
            "slug_word_count": self.slug_word_count,
            "standalone_maliciousness": self.standalone_maliciousness,
            "risk_contribution": round(self.risk_contribution, 2),
            "confidence": round(self.confidence, 2),
            "evidence_description": self.evidence_description,
            "indicators": self.indicators,
        }


class HostingIntelligenceEngine:
    """
    Evaluates hosting provider, tunnel status, and hostname entropy without blanket-blocking legitimate infrastructure.
    """

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy in bits for string characters."""
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        counts: Dict[str, int] = {}
        for char in text:
            counts[char] = counts.get(char, 0) + 1
        for count in counts.values():
            p_x = count / length
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        return entropy

    @classmethod
    def evaluate(cls, url_or_hostname: str) -> HostingIntelligenceResult:
        res = HostingIntelligenceResult()
        raw = url_or_hostname.strip()
        if not raw:
            return res

        if "://" in raw:
            try:
                parsed = urllib.parse.urlparse(raw)
                hostname = (parsed.hostname or "").lower()
            except Exception:
                hostname = raw.lower().split("/")[0].split(":")[0]
        else:
            hostname = raw.lower().split("/")[0].split(":")[0]

        if not hostname:
            return res

        if hostname in ("localhost", "127.0.0.1", "::1") or hostname.endswith((".local", ".internal", ".test")):
            res.hosting_type = HostingType.LOCAL_PRIVATE
            res.infrastructure_status = InfrastructureStatus.LOCAL_ENVIRONMENT
            res.evidence_description = f"Local development or private network target: {hostname}."
            return res

        for suffix, (provider, label) in EPHEMERAL_TUNNEL_DOMAINS.items():
            if hostname == suffix or hostname.endswith("." + suffix):
                res.is_ephemeral_tunnel = True
                res.hosting_type = HostingType.EPHEMERAL_TUNNEL
                res.hosting_provider = provider
                res.provider_label = label
                res.infrastructure_status = InfrastructureStatus.TEMPORARY_PUBLIC_ENDPOINT

                if hostname.endswith("." + suffix):
                    sub = hostname[:-len("." + suffix)]
                else:
                    sub = ""
                res.subdomain = sub
                break

        if not res.is_ephemeral_tunnel:
            for suffix, label in DYNAMIC_DNS_DOMAINS.items():
                if hostname == suffix or hostname.endswith("." + suffix):
                    res.is_dynamic_dns = True
                    res.hosting_type = HostingType.DYNAMIC_DNS
                    res.hosting_provider = "DYNAMIC_DNS"
                    res.provider_label = label
                    res.infrastructure_status = InfrastructureStatus.DYNAMIC_PUBLIC_ENDPOINT
                    if hostname.endswith("." + suffix):
                        sub = hostname[:-len("." + suffix)]
                    else:
                        sub = ""
                    res.subdomain = sub
                    break

        if not res.is_ephemeral_tunnel and not res.is_dynamic_dns:
            for suffix, label in EXFILTRATION_SINK_DOMAINS.items():
                if hostname == suffix or hostname.endswith("." + suffix):
                    res.is_exfiltration_sink = True
                    res.hosting_type = HostingType.EXFILTRATION_SINK
                    res.hosting_provider = "EXFILTRATION_SINK"
                    res.provider_label = label
                    res.infrastructure_status = InfrastructureStatus.DYNAMIC_PUBLIC_ENDPOINT
                    if hostname.endswith("." + suffix):
                        sub = hostname[:-len("." + suffix)]
                    else:
                        sub = ""
                    res.subdomain = sub
                    break

        if res.subdomain:
            res.subdomain_entropy = cls.calculate_shannon_entropy(res.subdomain)
            hyphen_parts = res.subdomain.split("-")
            res.slug_word_count = len(hyphen_parts)
            if len(hyphen_parts) >= 3 and all(len(p) >= 2 for p in hyphen_parts):
                res.has_random_slug = True

            if bool(re.match(r"^[a-f0-9]{8,}$", res.subdomain)) or (len(res.subdomain) >= 12 and res.subdomain_entropy >= 3.4):
                res.has_random_slug = True

        if res.is_ephemeral_tunnel:
            res.indicators.append(f"Ephemeral public tunnel endpoint identified ({res.provider_label})")
            if res.has_random_slug:
                res.indicators.append(f"Random multi-segment generated subdomain detected ('{res.subdomain}', entropy: {res.subdomain_entropy:.2f})")
            res.evidence_description = (
                f"Target is hosted on a temporary public tunnel ({res.provider_label}). "
                "Ephemeral tunnels expose local test environments to the public internet and are frequently leveraged "
                "in unindexed phishing, credential harvesting, or social engineering lures. Tunnel hosting alone does not "
                "establish maliciousness, but necessitates comprehensive behavioral verification."
            )
            res.risk_contribution = 0.25 if res.has_random_slug else 0.20
            return res

        if res.is_dynamic_dns:
            res.indicators.append(f"Dynamic DNS hostname identified ({res.provider_label})")
            res.evidence_description = (
                f"Target utilizes a dynamic DNS service ({res.provider_label}). "
                "Dynamic DNS domains can change IP destination rapidly and require careful reputation tracking."
            )
            res.risk_contribution = 0.15
            return res

        if res.is_exfiltration_sink:
            res.indicators.append(f"Known HTTP/OAST data receiver endpoint ({res.provider_label})")
            res.evidence_description = (
                f"Target matches known data collection/testing sink ({res.provider_label}). "
                "Often used by phishing or security test kits to receive exfiltrated credentials or victim telemetry."
            )
            res.risk_contribution = 0.35
            return res

        return res


_global_hosting_engine: Optional[HostingIntelligenceEngine] = None


def get_hosting_intelligence_engine() -> HostingIntelligenceEngine:
    global _global_hosting_engine
    if _global_hosting_engine is None:
        _global_hosting_engine = HostingIntelligenceEngine()
    return _global_hosting_engine
