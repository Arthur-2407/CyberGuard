"""
hosting_intelligence.py — Ephemeral Tunnel, Temporary Public Endpoints & Hosting Context Intelligence.

Analyzes hosting infrastructure characteristics for submitted URLs:
  - Detects ephemeral public tunnels (Cloudflare Quick Tunnels, ngrok, localtunnel, serveo, etc.)
  - Analyzes subdomain entropy and random word patterns
  - Evaluates hosting context without blanket-blocking legitimate infrastructure
  - Standalone policy: ephemeral hosting alone is NOT established as malicious, but provides
    critical context when correlated with credential harvesting, sensor probes, or unreachable states.
"""

from __future__ import annotations

import math
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


# Known ephemeral tunnel / temporary public gateway root domains
EPHEMERAL_TUNNEL_DOMAINS: Dict[str, Dict[str, str]] = {
    "trycloudflare.com": {
        "provider": "Cloudflare Quick Tunnel",
        "description": "Cloudflare ephemeral quick tunnel (cloudflared). Generates temporary random subdomains.",
        "category": "EPHEMERAL_TUNNEL",
    },
    "ngrok-free.app": {
        "provider": "ngrok",
        "description": "ngrok free-tier public tunnel endpoint.",
        "category": "EPHEMERAL_TUNNEL",
    },
    "ngrok.io": {
        "provider": "ngrok",
        "description": "ngrok public tunnel endpoint.",
        "category": "EPHEMERAL_TUNNEL",
    },
    "ngrok.app": {
        "provider": "ngrok",
        "description": "ngrok public tunnel endpoint.",
        "category": "EPHEMERAL_TUNNEL",
    },
    "loca.lt": {
        "provider": "Localtunnel",
        "description": "Localtunnel open-source reverse proxy tunnel.",
        "category": "EPHEMERAL_TUNNEL",
    },
    "serveo.net": {
        "provider": "Serveo",
        "description": "Serveo SSH port forwarding public tunnel.",
        "category": "EPHEMERAL_TUNNEL",
    },
    "pagekite.me": {
        "provider": "PageKite",
        "description": "PageKite public reverse-proxy tunnel.",
        "category": "EPHEMERAL_TUNNEL",
    },
    "telebit.io": {
        "provider": "Telebit",
        "description": "Telebit secure relay public tunnel.",
        "category": "EPHEMERAL_TUNNEL",
    },
    "pinggy.link": {
        "provider": "Pinggy",
        "description": "Pinggy HTTP/TCP tunnel endpoint.",
        "category": "EPHEMERAL_TUNNEL",
    },
    "portmap.io": {
        "provider": "Portmap",
        "description": "Portmap.io free port forwarding tunnel.",
        "category": "EPHEMERAL_TUNNEL",
    },
    "portmap.host": {
        "provider": "Portmap",
        "description": "Portmap.io public proxy host.",
        "category": "EPHEMERAL_TUNNEL",
    },
    "tunnelmole.net": {
        "provider": "Tunnelmole",
        "description": "Tunnelmole open-source deep tunneling service.",
        "category": "EPHEMERAL_TUNNEL",
    },
}

# Known free Dynamic DNS providers often observed in temporary/disposable deployments
DYNAMIC_DNS_DOMAINS: Dict[str, str] = {
    "duckdns.org": "DuckDNS Free Dynamic DNS",
    "no-ip.com": "No-IP Dynamic DNS",
    "no-ip.org": "No-IP Dynamic DNS",
    "ddns.net": "No-IP Free DDNS",
    "zapto.org": "No-IP Dynamic DNS",
    "hopto.org": "No-IP Dynamic DNS",
    "freeddns.org": "Free DDNS",
    "dynu.net": "Dynu Dynamic DNS",
}


def compute_shannon_entropy(data: str) -> float:
    """Computes Shannon entropy of a string (bits per symbol)."""
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = float(len(data))
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


@dataclass
class HostingContext:
    is_ephemeral_tunnel: bool = False
    hosting_type: str = "STANDARD_HOSTING"  # "EPHEMERAL_TUNNEL" | "DYNAMIC_DNS" | "STANDARD_HOSTING"
    provider_name: Optional[str] = None
    infrastructure_status: str = "PERSISTENT_INFRASTRUCTURE"  # "TEMPORARY_PUBLIC_ENDPOINT" | "PERSISTENT_INFRASTRUCTURE"
    standalone_maliciousness: str = "NOT_ESTABLISHED"  # Ephemeral alone != malicious
    base_domain: str = ""
    subdomain: str = ""
    subdomain_entropy: float = 0.0
    is_multi_word_slug: bool = False
    risk_contribution: float = 0.0
    details: str = ""
    indicators: List[str] = field(default_factory=list)
    resolved_ips: List[str] = field(default_factory=list)
    dns_records: Dict[str, Any] = field(default_factory=dict)
    tls_certificate: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_ephemeral_tunnel": self.is_ephemeral_tunnel,
            "hosting_type": self.hosting_type,
            "provider_name": self.provider_name,
            "infrastructure_status": self.infrastructure_status,
            "standalone_maliciousness": self.standalone_maliciousness,
            "base_domain": self.base_domain,
            "subdomain": self.subdomain,
            "subdomain_entropy": self.subdomain_entropy,
            "is_multi_word_slug": self.is_multi_word_slug,
            "risk_contribution": self.risk_contribution,
            "details": self.details,
            "indicators": self.indicators,
            "resolved_ips": self.resolved_ips,
            "dns_records": self.dns_records,
            "tls_certificate": self.tls_certificate,
        }


class HostingIntelligenceAnalyzer:
    """
    Evaluates hosting context, ephemeral tunnels, and temporary public endpoints.
    Adheres strictly to the architectural rule:
      - Ephemeral hosting provides supporting context, NOT standalone proof of maliciousness.
      - A temporary endpoint combined with deceptive actions, credential forms, or permission
        probes escalates overall risk appropriately.
    """

    @classmethod
    def analyze(cls, url: str, resolution_hops: Optional[List[str]] = None) -> HostingContext:
        ctx = cls.analyze_url(url)
        if resolution_hops:
            for hop_url in resolution_hops:
                hop_ctx = cls.analyze_url(hop_url)
                if hop_ctx.is_ephemeral_tunnel:
                    ctx.indicators.append(
                        f"Redirect chain traversed ephemeral tunnel: {hop_ctx.base_domain} ({hop_ctx.provider_name})"
                    )
                    if not ctx.is_ephemeral_tunnel:
                        ctx.is_ephemeral_tunnel = True
                        ctx.hosting_type = "EPHEMERAL_TUNNEL"
                        ctx.provider_name = hop_ctx.provider_name
                        ctx.infrastructure_status = "TEMPORARY_PUBLIC_ENDPOINT"
                        ctx.base_domain = hop_ctx.base_domain
                        ctx.risk_contribution = max(ctx.risk_contribution, hop_ctx.risk_contribution)
        return ctx

    @classmethod
    def analyze_url(cls, url: str) -> HostingContext:
        try:
            parsed = urllib.parse.urlparse(url)
            hostname = (parsed.hostname or "").lower().strip()
        except Exception:
            hostname = ""

        return cls.analyze_hostname(hostname)

    @classmethod
    def analyze_hostname(cls, hostname: str) -> HostingContext:
        ctx = HostingContext()
        clean_host = hostname.lower().strip()
        if not clean_host:
            return ctx

        # Check against ephemeral tunnel domains
        matched_tunnel = None
        matched_tunnel_domain = ""
        for domain, meta in EPHEMERAL_TUNNEL_DOMAINS.items():
            if clean_host == domain or clean_host.endswith("." + domain):
                matched_tunnel = meta
                matched_tunnel_domain = domain
                break

        if matched_tunnel:
            ctx.is_ephemeral_tunnel = True
            ctx.hosting_type = "EPHEMERAL_TUNNEL"
            ctx.provider_name = matched_tunnel["provider"]
            ctx.infrastructure_status = "TEMPORARY_PUBLIC_ENDPOINT"
            ctx.standalone_maliciousness = "NOT_ESTABLISHED"
            ctx.base_domain = matched_tunnel_domain
            ctx.risk_contribution = 0.20

            # Extract subdomain prefix
            sub = clean_host[:-len(matched_tunnel_domain)].rstrip(".")
            ctx.subdomain = sub
            ctx.subdomain_entropy = compute_shannon_entropy(sub)

            # Check for multi-word hyphenated generated slugs (e.g. colin-representations-murray-reveals)
            parts = sub.split("-")
            if len(parts) >= 3:
                ctx.is_multi_word_slug = True
                ctx.indicators.append(
                    f"Generated multi-token tunnel subdomain slug ({len(parts)} parts): '{sub}'"
                )

            ctx.indicators.append(
                f"Target hosted on {matched_tunnel['provider']} temporary public gateway ({matched_tunnel_domain})"
            )
            ctx.details = (
                f"Target uses an ephemeral public tunnel endpoint ({matched_tunnel_domain}). "
                f"Temporary tunnels provide dynamic, short-lived public URLs that bypass NAT/firewalls. "
                "While legitimate for local developer testing, ephemeral tunnels are frequently used in "
                "social engineering and phishing kits to host transient collection servers without registering domains. "
                "Contextual evaluation: standalone status is NOT_ESTABLISHED; risk is escalated when paired with "
                "credential harvesting, sensor permission probing, or unverified crawler states."
            )
            return ctx

        # Check against dynamic DNS domains
        for ddns_domain, provider_label in DYNAMIC_DNS_DOMAINS.items():
            if clean_host == ddns_domain or clean_host.endswith("." + ddns_domain):
                ctx.hosting_type = "DYNAMIC_DNS"
                ctx.provider_name = provider_label
                ctx.infrastructure_status = "PERSISTENT_INFRASTRUCTURE"
                ctx.standalone_maliciousness = "NOT_ESTABLISHED"
                ctx.base_domain = ddns_domain
                ctx.risk_contribution = 0.10
                sub = clean_host[:-len(ddns_domain)].rstrip(".")
                ctx.subdomain = sub
                ctx.subdomain_entropy = compute_shannon_entropy(sub)
                ctx.indicators.append(f"Target uses dynamic DNS provider ({provider_label})")
                ctx.details = f"Target domain is registered under a free dynamic DNS provider ({provider_label})."
                return ctx

        ctx.base_domain = clean_host
        ctx.hosting_type = "STANDARD_HOSTING"
        ctx.infrastructure_status = "PERSISTENT_INFRASTRUCTURE"
        ctx.standalone_maliciousness = "NOT_ESTABLISHED"
        ctx.details = "Target resides on standard Internet hosting infrastructure."
        return ctx
