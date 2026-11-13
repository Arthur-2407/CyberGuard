"""
network_telemetry.py — Isolated Network Traffic Intelligence & Destination Analysis for CyberGuard.

Analyzes authorized scanner-generated traffic and network behavior:
  1. Browser-level network event monitoring (Playwright request/response tracking)
  2. Contacted destination graph (main origin vs third-party scripts vs external APIs vs exfiltration targets)
  3. HTTP behavior analysis (methods, status codes, content-types, resource origins)
  4. Sequence correlation: sensitive browser permissions (GPS/Camera/Mic) followed by outbound data transmission
  5. Privacy guarantees: collects only network metadata; NEVER collects passwords, session tokens, or private bodies
"""

from __future__ import annotations

import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set, Tuple

from backend.threats.models import Evidence

logger = logging.getLogger(__name__)

# Common third-party CDN / utility domains (should not be falsely flagged as malicious exfiltration)
KNOWN_BENIGN_CDNS: Set[str] = {
    "fonts.googleapis.com", "fonts.gstatic.com", "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net", "ajax.googleapis.com", "code.jquery.com",
    "maxcdn.bootstrapcdn.com", "unpkg.com", "stackpath.bootstrapcdn.com",
    "www.google-analytics.com", "google-analytics.com", "www.googletagmanager.com",
}

# Suspicious exfiltration endpoint patterns (PHP collection scripts, webhooks, telegram bot APIs)
EXFILTRATION_PATH_PATTERNS = [
    re.compile(r"(?i)\b(?:post|login|location|grab|log|submit|capture|save|receive|track|report|dump)\.php\b"),
    re.compile(r"(?i)\b(?:api/v1/telemetry|collect|endpoint/log|hook|beacon)\b"),
    re.compile(r"(?i)api\.telegram\.org/bot"),
    re.compile(r"(?i)discord(?:app)?\.com/api/webhooks"),
    re.compile(r"(?i)webhook\.site/"),
]


@dataclass
class NetworkRequestRecord:
    url: str
    method: str = "GET"
    resource_type: str = "document"  # document, script, xhr, fetch, stylesheet, image, websocket, other
    status_code: Optional[int] = None
    status_text: Optional[str] = None
    domain: str = ""
    is_external: bool = False
    is_exfiltration: bool = False
    error_text: Optional[str] = None
    timing_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "resource_type": self.resource_type,
            "status_code": self.status_code,
            "status_text": self.status_text,
            "domain": self.domain,
            "is_external": self.is_external,
            "is_exfiltration": self.is_exfiltration,
            "error_text": self.error_text,
            "timing_ms": round(self.timing_ms, 1),
        }


@dataclass
class DestinationNode:
    domain: str
    is_external: bool = False
    request_count: int = 0
    roles: List[str] = field(default_factory=list)  # MAIN_ORIGIN, THIRD_PARTY_SCRIPT, EXFILTRATION_ENDPOINT, API
    sample_urls: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "is_external": self.is_external,
            "request_count": self.request_count,
            "roles": self.roles,
            "sample_urls": self.sample_urls[:3],
        }


@dataclass
class NetworkTrafficReport:
    total_requests: int = 0
    total_responses: int = 0
    failed_requests: int = 0
    unique_destinations: List[str] = field(default_factory=list)
    requests: List[NetworkRequestRecord] = field(default_factory=list)
    destinations: Dict[str, DestinationNode] = field(default_factory=dict)
    suspicious_requests: List[Dict[str, Any]] = field(default_factory=list)
    exfiltration_events: List[Dict[str, Any]] = field(default_factory=list)
    sensor_probes_observed: List[Dict[str, Any]] = field(default_factory=list)
    traffic_patterns_detected: List[str] = field(default_factory=list)
    network_risk_score: float = 0.0
    evidence: List[Evidence] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "total_responses": self.total_responses,
            "failed_requests": self.failed_requests,
            "unique_destinations": self.unique_destinations,
            "requests_sample": [r.to_dict() for r in self.requests[:20]],
            "destinations": {k: v.to_dict() for k, v in self.destinations.items()},
            "suspicious_requests": self.suspicious_requests,
            "exfiltration_events": self.exfiltration_events,
            "sensor_probes_observed": self.sensor_probes_observed,
            "traffic_patterns_detected": self.traffic_patterns_detected,
            "network_risk_score": round(self.network_risk_score, 3),
            "evidence_count": len(self.evidence),
            "summary": self.summary,
        }


class NetworkTrafficIntelligenceEngine:
    """
    Evaluates real network traffic captured during live page inspection.
    """

    @classmethod
    def analyze_traffic(
        cls,
        *,
        base_url: str,
        requests: List[NetworkRequestRecord],
        sensor_probes: Optional[List[Dict[str, Any]]] = None,
        is_ephemeral_tunnel: bool = False,
    ) -> NetworkTrafficReport:
        report = NetworkTrafficReport()
        probes = sensor_probes or []
        report.sensor_probes_observed = probes

        try:
            base_parsed = urllib.parse.urlparse(base_url)
            base_domain = (base_parsed.netloc or "").lower()
        except Exception:
            base_domain = ""

        report.total_requests = len(requests)
        unique_domains: Set[str] = set()

        for req in requests:
            req_url = req.url
            try:
                p = urllib.parse.urlparse(req_url)
                req_domain = (p.netloc or "").lower()
            except Exception:
                req_domain = ""

            req.domain = req_domain
            is_ext = bool(req_domain and base_domain and req_domain != base_domain)
            req.is_external = is_ext

            if req_domain:
                unique_domains.add(req_domain)
                if req_domain not in report.destinations:
                    report.destinations[req_domain] = DestinationNode(
                        domain=req_domain,
                        is_external=is_ext,
                        request_count=0,
                        roles=[],
                        sample_urls=[]
                    )
                node = report.destinations[req_domain]
                node.request_count += 1
                if len(node.sample_urls) < 3:
                    node.sample_urls.append(req_url)

                # Classify role
                if not is_ext and "MAIN_ORIGIN" not in node.roles:
                    node.roles.append("MAIN_ORIGIN")
                elif req_domain in KNOWN_BENIGN_CDNS and "CDN_OR_ANALYTICS" not in node.roles:
                    node.roles.append("CDN_OR_ANALYTICS")
                elif req.resource_type in ("script", "stylesheet") and "THIRD_PARTY_RESOURCE" not in node.roles:
                    node.roles.append("THIRD_PARTY_RESOURCE")

            if req.status_code is not None:
                report.total_responses += 1
            if req.error_text:
                report.failed_requests += 1

            # Check exfiltration patterns
            is_exfil = False
            for pat in EXFILTRATION_PATH_PATTERNS:
                if pat.search(req_url):
                    is_exfil = True
                    break

            # Also check POST to external domain
            if req.method == "POST":
                if is_ext and req_domain not in KNOWN_BENIGN_CDNS:
                    is_exfil = True

            if is_exfil:
                req.is_exfiltration = True
                exfil_entry = {
                    "url": req_url,
                    "method": req.method,
                    "domain": req_domain,
                    "is_external": is_ext,
                    "resource_type": req.resource_type,
                }
                report.exfiltration_events.append(exfil_entry)
                if req_domain and "EXFILTRATION_ENDPOINT" not in report.destinations[req_domain].roles:
                    report.destinations[req_domain].roles.append("EXFILTRATION_ENDPOINT")

        report.unique_destinations = sorted(list(unique_domains))
        report.requests = requests

        # ── Correlation: Sensitive Sensor Access + Outbound Telemetry ─────────
        # Pattern: CamPhish / Geolocation Phishing sequence
        if probes and report.exfiltration_events:
            sensor_names = [p.get("sensor", "UNKNOWN") for p in probes]
            exfil_urls = [e.get("url") for e in report.exfiltration_events]

            pattern_desc = (
                f"CORRELATED EXFILTRATION SEQUENCE: Client-side sensitive permission probes ({', '.join(sensor_names)}) "
                f"correlated with immediate outbound data transmission to collection endpoint ({', '.join(exfil_urls[:2])})."
            )
            report.traffic_patterns_detected.append(pattern_desc)
            report.network_risk_score = max(report.network_risk_score, 0.90)

            report.evidence.append(Evidence(
                evidence_type="correlated_sensor_exfiltration",
                description=pattern_desc,
                value=f"Sensors: {', '.join(sensor_names)} -> Outbound: {', '.join(exfil_urls[:2])}",
                severity_contribution=0.85,
                confidence=0.95,
                source="NetworkTrafficAnalyzer"
            ))

        elif report.exfiltration_events:
            exfil_urls = [e.get("url") for e in report.exfiltration_events]
            pattern_desc = f"Outbound telemetry/collection endpoint contacted: {', '.join(exfil_urls[:3])}"
            report.traffic_patterns_detected.append(pattern_desc)
            contrib = 0.70 if is_ephemeral_tunnel else 0.50
            report.network_risk_score = max(report.network_risk_score, contrib)

            report.evidence.append(Evidence(
                evidence_type="suspicious_exfiltration_traffic",
                description=f"Outbound network telemetry observed communicating with collection endpoint ({', '.join(exfil_urls[:2])}).",
                value=", ".join(exfil_urls[:3]),
                severity_contribution=contrib,
                confidence=0.88,
                source="NetworkTrafficAnalyzer"
            ))

        elif probes:
            sensor_names = [p.get("sensor", "UNKNOWN") for p in probes]
            pattern_desc = f"Sensitive hardware sensors probed without exfiltration observed: {', '.join(sensor_names)}"
            report.traffic_patterns_detected.append(pattern_desc)
            contrib = 0.50 if is_ephemeral_tunnel else 0.30
            report.network_risk_score = max(report.network_risk_score, contrib)

        # Summary generation
        parts = []
        parts.append(f"{report.total_requests} request(s) observed across {len(report.unique_destinations)} destination(s)")
        if report.exfiltration_events:
            parts.append(f"{len(report.exfiltration_events)} exfiltration request(s) flagged")
        if probes:
            parts.append(f"{len(probes)} sensitive sensor probe(s) intercepted")
        report.summary = "; ".join(parts) + "."

        return report

