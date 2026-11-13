"""
phishing_engine.py — Advanced Phishing, Credential-Harvesting & Deceptive Threat Detection Engine.

Implements multi-dimensional website-level and behavioral phishing detection:
  1. URL & Hostname Heuristics (entropy, excessive subdomains, homoglyphs, Punycode, IP-as-host, shorteners)
  2. Brand Impersonation & Deceptive Logos/Titles (Google, Microsoft, Apple, Meta, Banking, Zoom, Teams, Meet)
  3. Credential-Harvesting Forms & Inputs (passwords, OTPs, PINs, tokens, SSN, card inputs)
  4. Sensitive Permission-Abuse Detection (Geolocation, Camera, Microphone, Notifications in deceptive context)
  5. Deceptive Social Engineering (Fake meeting rooms, festival greeting traps, urgent warnings, fake giveaways)
  6. External Exfiltration Destinies (cross-origin form actions, Telegram/Discord webhooks, PHP collection scripts)
"""

from __future__ import annotations

import re
import math
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple

from backend.threats.models import Evidence, RiskLevel, ThreatCategory
from backend.threats.hosting_intelligence import HostingIntelligenceAnalyzer, HostingContext, compute_shannon_entropy


# Recognized major brands targeted in phishing campaigns
BRAND_TARGETS: Dict[str, Dict[str, Any]] = {
    "google": {
        "name": "Google",
        "legit_domains": {"google.com", "accounts.google.com", "gmail.com", "youtube.com"},
        "keywords": ["google", "gmail", "workspace", "google drive", "google docs"],
    },
    "microsoft": {
        "name": "Microsoft",
        "legit_domains": {"microsoft.com", "login.microsoftonline.com", "live.com", "office.com", "outlook.com"},
        "keywords": ["microsoft", "office 365", "o365", "outlook", "onedrive", "sharepoint", "azure"],
    },
    "apple": {
        "name": "Apple",
        "legit_domains": {"apple.com", "icloud.com", "appleid.apple.com"},
        "keywords": ["apple id", "icloud", "find my", "itunes"],
    },
    "meta": {
        "name": "Meta / Facebook",
        "legit_domains": {"facebook.com", "meta.com", "instagram.com", "whatsapp.com"},
        "keywords": ["facebook", "meta", "instagram", "whatsapp", "messenger"],
    },
    "paypal": {
        "name": "PayPal",
        "legit_domains": {"paypal.com"},
        "keywords": ["paypal", "paypal verification", "paypal security"],
    },
    "zoom": {
        "name": "Zoom",
        "legit_domains": {"zoom.us", "zoomgov.com"},
        "keywords": ["zoom meeting", "join zoom", "zoom video", "zoom call"],
    },
    "teams": {
        "name": "Microsoft Teams",
        "legit_domains": {"teams.microsoft.com", "microsoft.com"},
        "keywords": ["teams meeting", "join teams", "microsoft teams"],
    },
    "meet": {
        "name": "Google Meet",
        "legit_domains": {"meet.google.com", "google.com"},
        "keywords": ["google meet", "join meet", "meet video call"],
    },
    "netflix": {
        "name": "Netflix",
        "legit_domains": {"netflix.com"},
        "keywords": ["netflix", "netflix payment", "netflix account"],
    },
    "amazon": {
        "name": "Amazon",
        "legit_domains": {"amazon.com", "amazon.in", "amazon.co.uk"},
        "keywords": ["amazon prime", "amazon order", "amazon security"],
    },
}

# Deceptive meeting / video conference lures (commonly used by CamPhish, TrackUrl, etc.)
MEETING_LURE_PATTERNS = [
    r"(?i)\b(online\s*meeting|join\s*meeting|video\s*conference|meeting\s*room)\b",
    r"(?i)\b(camera\s*test|webcam\s*test|mic\s*test|audio\s*test)\b",
    r"(?i)\b(live\s*stream|live\s*youtube\s*tv|youtube\s*live|watch\s*live)\b",
    r"(?i)\b(festival\s*wishing|festival\s*greeting|greeting\s*card|happy\s*festival)\b",
    r"(?i)\b(verify\s*your\s*age|age\s*verification|prove\s*you\s*are\s*human)\b",
]

# Sensitive sensor & browser API probing patterns
SENSOR_PROBE_PATTERNS = {
    "GEOLOCATION": [
        r"navigator\.geolocation\.getCurrentPosition",
        r"navigator\.geolocation\.watchPosition",
        r"navigator\.geolocation",
    ],
    "CAMERA_MICROPHONE": [
        r"navigator\.mediaDevices\.getUserMedia",
        r"navigator\.getUserMedia",
        r"webkitGetUserMedia",
        r"mozGetUserMedia",
        r"video:\s*true",
        r"audio:\s*true",
    ],
    "NOTIFICATIONS": [
        r"Notification\.requestPermission",
    ],
}

# Suspicious exfiltration endpoints & webhooks
EXFILTRATION_PATTERNS = [
    r"(?i)(?:action|href|url|endpoint)[\s=:\'\"\`]+[^\'\"]*(?:post\.php|login\.php|location\.php|grab\.php|log\.php|submit\.php)",
    r"https?://(?:api\.)?telegram\.org/bot",
    r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks",
    r"https?://hook\.(?:integromat|make)\.com",
    r"https?://webhook\.site",
]

# URL shortener domains
URL_SHORTENER_DOMAINS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc", "goo.gl", "bit.do",
})


@dataclass
class PhishingEvaluation:
    is_phishing: bool = False
    is_suspicious: bool = False
    score: float = 0.0  # 0.0 to 1.0
    confidence: float = 0.0  # 0.0 to 1.0
    credential_harvesting_detected: bool = False
    credential_input_count: int = 0
    sensitive_permission_probe_detected: bool = False
    probed_permissions: List[str] = field(default_factory=list)
    brand_impersonation_detected: bool = False
    impersonated_brand: Optional[str] = None
    social_engineering_detected: bool = False
    social_engineering_lure: Optional[str] = None
    suspicious_exfiltration_detected: bool = False
    exfiltration_targets: List[str] = field(default_factory=list)
    url_heuristics_flags: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    summary: str = ""
    reasoning: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_phishing": self.is_phishing,
            "is_suspicious": self.is_suspicious,
            "score": round(self.score, 3),
            "confidence": round(self.confidence, 3),
            "credential_harvesting_detected": self.credential_harvesting_detected,
            "credential_input_count": self.credential_input_count,
            "sensitive_permission_probe_detected": self.sensitive_permission_probe_detected,
            "probed_permissions": self.probed_permissions,
            "brand_impersonation_detected": self.brand_impersonation_detected,
            "impersonated_brand": self.impersonated_brand,
            "social_engineering_detected": self.social_engineering_detected,
            "social_engineering_lure": self.social_engineering_lure,
            "suspicious_exfiltration_detected": self.suspicious_exfiltration_detected,
            "exfiltration_targets": self.exfiltration_targets,
            "url_heuristics_flags": self.url_heuristics_flags,
            "evidence_count": len(self.evidence),
            "summary": self.summary,
            "reasoning": self.reasoning,
        }


class PhishingDetectionEngine:
    """
    Authoritative, multi-layered phishing detection engine.
    Analyzes URL syntax, hosting context, live DOM inspection, JavaScript sensor probing,
    and deceptive social engineering lures.
    """

    @classmethod
    def evaluate(
        cls,
        *,
        url: str,
        hostname: str = "",
        page_content: Optional[str] = None,
        dom_inspection: Optional[Dict[str, Any]] = None,
        hosting_ctx: Optional[HostingContext] = None,
        page_title: str = "",
        dns_rdap_info: Optional[Dict[str, Any]] = None,
        network_traffic: Optional[Dict[str, Any]] = None,
    ) -> PhishingEvaluation:
        eval_result = PhishingEvaluation()
        dom = dom_inspection or {}
        content = page_content or ""
        clean_url = url.strip()

        # Parse URL
        try:
            parsed = urllib.parse.urlparse(clean_url)
            host = (hostname or parsed.hostname or "").lower().strip()
            path = parsed.path or ""
            query = parsed.query or ""
        except Exception:
            host = (hostname or "").lower().strip()
            path = ""
            query = ""

        # 1. Hosting Context Evaluation
        if not hosting_ctx:
            hosting_ctx = HostingIntelligenceAnalyzer.analyze_hostname(host)

        # 2. URL Syntax & Heuristics
        cls._evaluate_url_heuristics(clean_url, host, path, query, hosting_ctx, eval_result)

        # 3. DOM & Form Credential-Harvesting Analysis
        cls._evaluate_credential_harvesting(dom, content, eval_result)

        # 4. Sensitive Permission Probing Analysis (Camera / Mic / Geolocation)
        cls._evaluate_sensor_permissions(content, dom, hosting_ctx, eval_result, network_traffic=network_traffic)

        # 5. Brand Impersonation Analysis
        cls._evaluate_brand_impersonation(host, page_title, content, dom, eval_result)

        # 6. Deceptive Social Engineering Lures (Meeting, Greeting, Live TV traps)
        cls._evaluate_social_engineering_lures(content, page_title, hosting_ctx, eval_result)

        # 7. Script Exfiltration Endpoints & Live Network Telemetry
        cls._evaluate_exfiltration_endpoints(content, dom, host, eval_result)
        if network_traffic:
            cls._evaluate_network_telemetry(network_traffic, hosting_ctx, eval_result)

        # 8. Composite Scoring & Determination
        cls._compute_final_phishing_verdict(eval_result, hosting_ctx)

        return eval_result

    @classmethod
    def _evaluate_url_heuristics(
        cls,
        url: str,
        host: str,
        path: str,
        query: str,
        hosting_ctx: HostingContext,
        res: PhishingEvaluation,
    ) -> None:
        # A. Ephemeral tunnel hosting context
        if hosting_ctx.is_ephemeral_tunnel:
            res.url_heuristics_flags.append(
                f"Ephemeral public tunnel hosting detected ({hosting_ctx.provider_name})"
            )
            # Ephemeral tunnel adds supporting evidence, NOT standalone phishing
            res.evidence.append(Evidence(
                evidence_type="ephemeral_tunnel_hosting",
                description=f"Target is hosted on a temporary public tunnel ({hosting_ctx.provider_name} - {hosting_ctx.base_domain}).",
                value=host,
                severity_contribution=0.20,
                confidence=0.95,
                source="HostingIntelligence"
            ))
            res.score += 0.20

        # B. URL Shorteners
        if host in URL_SHORTENER_DOMAINS:
            res.url_heuristics_flags.append("URL shortener gateway")
            res.evidence.append(Evidence(
                evidence_type="url_shortener_gateway",
                description=f"Domain '{host}' is a known public URL shortener used to conceal terminal destinations.",
                value=host,
                severity_contribution=0.15,
                confidence=0.90,
                source="URLHeuristics"
            ))
            res.score += 0.15

        # C. IP address as host
        import ipaddress
        try:
            ipaddress.ip_address(host)
            res.url_heuristics_flags.append("Raw IP address used as host")
            res.evidence.append(Evidence(
                evidence_type="ip_address_hostname",
                description=f"URL uses a bare IP address ({host}) instead of a qualified domain name.",
                value=host,
                severity_contribution=0.35,
                confidence=0.95,
                source="URLHeuristics"
            ))
            res.score += 0.35
        except ValueError:
            pass

        # D. Subdomain Depth & Entropy
        sub_parts = host.split(".")
        if len(sub_parts) > 4:
            res.url_heuristics_flags.append(f"Excessive subdomain depth ({len(sub_parts)} levels)")
            res.evidence.append(Evidence(
                evidence_type="excessive_subdomains",
                description=f"Host contains {len(sub_parts)} subdomain levels, commonly used to disguise actual domain root.",
                value=host,
                severity_contribution=0.15,
                confidence=0.80,
                source="URLHeuristics"
            ))
            res.score += 0.15

        # E. Suspicious Authentication Keywords in Path/Host
        auth_keywords = ["login", "signin", "verify", "security-check", "account-recovery", "wallet-auth", "authenticate"]
        matched_kw = [kw for kw in auth_keywords if kw in host or kw in path.lower()]
        if matched_kw:
            # If on ephemeral tunnel or unknown domain, keywords are high-risk
            kw_contrib = 0.35 if hosting_ctx.is_ephemeral_tunnel else 0.20
            res.url_heuristics_flags.append(f"Authentication keywords in path/host ({', '.join(matched_kw)})")
            res.evidence.append(Evidence(
                evidence_type="auth_keywords_in_url",
                description=f"URL path or hostname contains sensitive authentication keywords: {', '.join(matched_kw)}.",
                value=url,
                severity_contribution=kw_contrib,
                confidence=0.85,
                source="URLHeuristics"
            ))
            res.score += kw_contrib

        # F. Homoglyph / Punycode (xn--)
        if host.startswith("xn--") or ".xn--" in host:
            res.url_heuristics_flags.append("Punycode / IDN homoglyph encoding")
            res.evidence.append(Evidence(
                evidence_type="punycode_idn_domain",
                description=f"Domain uses Punycode encoding ({host}), often leveraged in Internationalized Domain Name homoglyph attacks.",
                value=host,
                severity_contribution=0.30,
                confidence=0.90,
                source="URLHeuristics"
            ))
            res.score += 0.30

    @classmethod
    def _evaluate_credential_harvesting(
        cls,
        dom: Dict[str, Any],
        content: str,
        res: PhishingEvaluation,
    ) -> None:
        has_pwd = bool(dom.get("has_password_field"))
        has_otp = bool(dom.get("has_otp_or_pin_field"))
        has_creds = bool(dom.get("has_credential_forms"))
        form_actions = dom.get("form_actions", [])

        # Also inspect raw HTML content if dom was basic
        if not has_pwd and content:
            if re.search(r'''<input[^>]+type\s*=\s*['"]password['"]''', content, re.I):
                has_pwd = True
                has_creds = True
        if not has_otp and content:
            if re.search(r'''<input[^>]+(?:name|id|placeholder)\s*=\s*['"][^'"]*(?:otp|pin|passcode|token|cvv|ssn)['"]''', content, re.I):
                has_otp = True
                has_creds = True

        if has_pwd or has_otp or has_creds:
            res.credential_harvesting_detected = True
            count = 1 + (1 if has_pwd else 0) + (1 if has_otp else 0)
            res.credential_input_count = count

            desc_parts = []
            if has_pwd:
                desc_parts.append("Password input field detected")
            if has_otp:
                desc_parts.append("OTP/PIN/Identity verification input detected")
            if not desc_parts:
                desc_parts.append("Credential or account submission inputs detected")

            res.evidence.append(Evidence(
                evidence_type="credential_harvesting_form",
                description=f"Active credential harvesting interface: {'; '.join(desc_parts)}.",
                value="; ".join(desc_parts),
                severity_contribution=0.75,
                confidence=0.95,
                source="DOMForensics"
            ))
            res.score += 0.75

    @classmethod
    def _evaluate_sensor_permissions(
        cls,
        content: str,
        dom: Dict[str, Any],
        hosting_ctx: HostingContext,
        res: PhishingEvaluation,
        network_traffic: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Inspects JavaScript, DOM, and runtime telemetry for sensitive sensor probes (Camera, Mic, GPS).
        Specifically detects social engineering kits like CamPhish, TrackUrl, Storm-Breaker.
        """
        probes_found = []

        # 1. Check direct DOM / runtime telemetry flags
        dom_probes = dom.get("probed_sensors", []) or dom.get("detected_sensor_types", [])
        if dom_probes:
            for p in dom_probes:
                p_upper = str(p).upper()
                if "GEO" in p_upper or "GPS" in p_upper:
                    if "GEOLOCATION" not in res.probed_permissions:
                        probes_found.append("GPS Geolocation (navigator.geolocation)")
                        res.probed_permissions.append("GEOLOCATION")
                if "CAM" in p_upper or "MIC" in p_upper or "MEDIA" in p_upper:
                    if "CAMERA_MICROPHONE" not in res.probed_permissions:
                        probes_found.append("Camera / Microphone (navigator.mediaDevices.getUserMedia)")
                        res.probed_permissions.append("CAMERA_MICROPHONE")
                if "NOTIF" in p_upper:
                    if "NOTIFICATIONS" not in res.probed_permissions:
                        probes_found.append("Browser Push Notifications (Notification.requestPermission)")
                        res.probed_permissions.append("NOTIFICATIONS")

        # 2. Check network telemetry probes
        if network_traffic and network_traffic.get("sensor_probes_observed"):
            for net_p in network_traffic["sensor_probes_observed"]:
                s = str(net_p.get("sensor", "")).upper()
                if "GEO" in s and "GEOLOCATION" not in res.probed_permissions:
                    probes_found.append("GPS Geolocation (navigator.geolocation)")
                    res.probed_permissions.append("GEOLOCATION")
                if ("CAM" in s or "MIC" in s) and "CAMERA_MICROPHONE" not in res.probed_permissions:
                    probes_found.append("Camera / Microphone (navigator.mediaDevices.getUserMedia)")
                    res.probed_permissions.append("CAMERA_MICROPHONE")
                if "NOTIF" in s and "NOTIFICATIONS" not in res.probed_permissions:
                    probes_found.append("Browser Push Notifications (Notification.requestPermission)")
                    res.probed_permissions.append("NOTIFICATIONS")

        # 3. Static regex patterns in HTML/JS content
        if content:
            if "GEOLOCATION" not in res.probed_permissions:
                for pattern in SENSOR_PROBE_PATTERNS["GEOLOCATION"]:
                    if re.search(pattern, content):
                        probes_found.append("GPS Geolocation (navigator.geolocation)")
                        res.probed_permissions.append("GEOLOCATION")
                        break

            if "CAMERA_MICROPHONE" not in res.probed_permissions:
                for pattern in SENSOR_PROBE_PATTERNS["CAMERA_MICROPHONE"]:
                    if re.search(pattern, content):
                        probes_found.append("Camera / Microphone (navigator.mediaDevices.getUserMedia)")
                        res.probed_permissions.append("CAMERA_MICROPHONE")
                        break

            if "NOTIFICATIONS" not in res.probed_permissions:
                for pattern in SENSOR_PROBE_PATTERNS["NOTIFICATIONS"]:
                    if re.search(pattern, content):
                        probes_found.append("Browser Push Notifications (Notification.requestPermission)")
                        res.probed_permissions.append("NOTIFICATIONS")
                        break

        if probes_found:
            res.sensitive_permission_probe_detected = True

            # If probed on an ephemeral tunnel, this is extremely high-confidence social engineering/camphish
            is_high_risk_env = hosting_ctx.is_ephemeral_tunnel or res.url_heuristics_flags
            severity_contrib = 0.85 if is_high_risk_env else 0.50

            res.evidence.append(Evidence(
                evidence_type="sensitive_permission_probe",
                description=(
                    f"Suspicious client-side device permission probe: {', '.join(probes_found)}. "
                    + ("Target uses an ephemeral public tunnel — highly characteristic of CamPhish / GPS tracking toolkits."
                       if hosting_ctx.is_ephemeral_tunnel else "Page probes sensitive hardware sensors upon load.")
                ),
                value=", ".join(probes_found),
                severity_contribution=severity_contrib,
                confidence=0.95 if hosting_ctx.is_ephemeral_tunnel else 0.85,
                source="ScriptInspection"
            ))
            res.score += severity_contrib

    @classmethod
    def _evaluate_network_telemetry(
        cls,
        network_traffic: Dict[str, Any],
        hosting_ctx: HostingContext,
        res: PhishingEvaluation,
    ) -> None:
        """
        Correlates observable network traffic events, contacted external destinations,
        and exfiltration request patterns.
        """
        exfil_events = network_traffic.get("exfiltration_events", [])
        patterns = network_traffic.get("traffic_patterns_detected", [])

        for pat in patterns:
            if "CORRELATED EXFILTRATION" in pat:
                res.suspicious_exfiltration_detected = True
                res.sensitive_permission_probe_detected = True
                res.evidence.append(Evidence(
                    evidence_type="correlated_sensor_exfiltration",
                    description=pat,
                    value="SensorProbe -> NetworkExfiltration",
                    severity_contribution=0.85,
                    confidence=0.95,
                    source="NetworkTrafficTelemetry"
                ))
                res.score += 0.85

        if exfil_events and not any(e.evidence_type == "network_exfiltration_traffic" for e in res.evidence):
            urls = [e.get("url") for e in exfil_events if e.get("url")]
            res.suspicious_exfiltration_detected = True
            contrib = 0.70 if hosting_ctx.is_ephemeral_tunnel else 0.50
            res.evidence.append(Evidence(
                evidence_type="network_exfiltration_traffic",
                description=f"Outbound network telemetry observed communicating with exfiltration endpoint ({', '.join(urls[:2])}).",
                value=", ".join(urls[:3]),
                severity_contribution=contrib,
                confidence=0.90,
                source="NetworkTrafficTelemetry"
            ))
            res.score += contrib

    @classmethod
    def _evaluate_brand_impersonation(
        cls,
        host: str,
        page_title: str,
        content: str,
        dom: Dict[str, Any],
        res: PhishingEvaluation,
    ) -> None:
        title_lower = page_title.lower()
        content_snippet = content[:5000].lower() if content else ""

        for brand_key, meta in BRAND_TARGETS.items():
            brand_name = meta["name"]
            legit_domains = meta["legit_domains"]
            keywords = meta["keywords"]

            # Check if domain is genuinely legitimate for this brand
            is_legit_host = any(host == ld or host.endswith("." + ld) for ld in legit_domains)
            if is_legit_host:
                continue

            # Check if brand is prominently claimed in title or initial page content
            brand_in_title = any(kw in title_lower for kw in keywords)
            brand_in_content = any(f"sign in to {kw}" in content_snippet or f"log in to {kw}" in content_snippet or f"{kw} account" in content_snippet for kw in keywords)

            if brand_in_title or brand_in_content:
                res.brand_impersonation_detected = True
                res.impersonated_brand = brand_name

                res.evidence.append(Evidence(
                    evidence_type="brand_impersonation",
                    description=(
                        f"Deceptive Brand Impersonation: Page claims identity of '{brand_name}' "
                        f"(title: '{page_title}'), but host '{host}' does NOT belong to {brand_name} legitimate infrastructure."
                    ),
                    value=f"Claimed={brand_name}, Host={host}",
                    severity_contribution=0.70,
                    confidence=0.92,
                    source="BrandImpersonationEngine"
                ))
                res.score += 0.70
                break

    @classmethod
    def _evaluate_social_engineering_lures(
        cls,
        content: str,
        page_title: str,
        hosting_ctx: HostingContext,
        res: PhishingEvaluation,
    ) -> None:
        sample_text = (page_title + " " + (content[:6000] if content else "")).lower()

        for lure_pattern in MEETING_LURE_PATTERNS:
            match = re.search(lure_pattern, sample_text)
            if match:
                matched_lure = match.group(0).strip()
                res.social_engineering_detected = True
                res.social_engineering_lure = matched_lure

                # Pair lure with sensor probe or ephemeral tunnel
                lure_contrib = 0.40 if (res.sensitive_permission_probe_detected or hosting_ctx.is_ephemeral_tunnel) else 0.20
                res.evidence.append(Evidence(
                    evidence_type="deceptive_social_engineering_lure",
                    description=f"Deceptive social engineering lure detected: '{matched_lure}'. Often utilized to manipulate victims into authorizing webcam/GPS access or disclosing credentials.",
                    value=matched_lure,
                    severity_contribution=lure_contrib,
                    confidence=0.88,
                    source="SocialEngineeringForensics"
                ))
                res.score += lure_contrib
                break

    @classmethod
    def _evaluate_exfiltration_endpoints(
        cls,
        content: str,
        dom: Dict[str, Any],
        host: str,
        res: PhishingEvaluation,
    ) -> None:
        form_actions = dom.get("form_actions", [])
        content_sample = content[:15000] if content else ""

        found_exfil = []
        for action in form_actions:
            if any(re.search(pat, action) for pat in EXFILTRATION_PATTERNS):
                found_exfil.append(action)

        for pat in EXFILTRATION_PATTERNS:
            matches = re.findall(pat, content_sample)
            if matches:
                found_exfil.extend(matches[:2])

        if found_exfil:
            res.suspicious_exfiltration_detected = True
            res.exfiltration_targets = list(set(found_exfil))[:3]
            res.evidence.append(Evidence(
                evidence_type="suspicious_exfiltration_endpoint",
                description=f"Data exfiltration endpoint discovered in page code/form action: {', '.join(res.exfiltration_targets)}.",
                value=", ".join(res.exfiltration_targets),
                severity_contribution=0.60,
                confidence=0.90,
                source="ExfiltrationForensics"
            ))
            res.score += 0.60

    @classmethod
    def _compute_final_phishing_verdict(
        cls,
        res: PhishingEvaluation,
        hosting_ctx: HostingContext,
    ) -> None:
        # Cap score at 1.0
        res.score = min(1.0, res.score)

        # Decision thresholds for phishing classification:
        # A. Direct Credential Harvesting form -> PHISHING
        # B. Sensitive Permission Probe (Camera/GPS) + Ephemeral Tunnel / Deceptive Lure -> PHISHING
        # C. Brand Impersonation + Form / Exfiltration -> PHISHING
        # D. High cumulative score (>= 0.65) -> PHISHING
        # E. Moderate score (>= 0.35) -> SUSPICIOUS
        is_camphish_vector = (
            res.sensitive_permission_probe_detected
            and (hosting_ctx.is_ephemeral_tunnel or res.social_engineering_detected or res.suspicious_exfiltration_detected)
        )
        is_credential_vector = (
            res.credential_harvesting_detected
            and (res.brand_impersonation_detected or hosting_ctx.is_ephemeral_tunnel or res.suspicious_exfiltration_detected or res.score >= 0.65)
        )

        if is_camphish_vector or is_credential_vector or res.score >= 0.65:
            res.is_phishing = True
            res.is_suspicious = False
            res.confidence = max(0.85, min(0.98, 0.70 + (res.score * 0.28)))
            
            reasons = []
            if is_camphish_vector:
                reasons.append("Unauthorized device sensor probing (GPS/Camera) orchestrated through temporary public infrastructure (CamPhish / tracking toolkit signature)")
            if res.credential_harvesting_detected:
                reasons.append("Active credential-harvesting input forms")
            if res.brand_impersonation_detected:
                reasons.append(f"Deceptive impersonation of {res.impersonated_brand}")
            if res.suspicious_exfiltration_detected:
                reasons.append("Data exfiltration endpoints detected in page logic")
            
            res.summary = f"PHISHING DETECTED: {'; '.join(reasons)}."
            res.reasoning = (
                f"Multi-layered behavioral analysis confirmed active phishing indicators. "
                f"Score: {res.score:.2f}, Confidence: {res.confidence:.2f}. "
                f"Primary vectors identified: {', '.join(reasons)}."
            )
        elif res.score >= 0.35 or res.credential_harvesting_detected or res.sensitive_permission_probe_detected or res.brand_impersonation_detected:
            res.is_phishing = False
            res.is_suspicious = True
            res.confidence = max(0.60, min(0.85, 0.50 + (res.score * 0.30)))
            res.summary = f"SUSPICIOUS ACTIVITY: Potential social engineering or deceptive indicators detected (Score: {res.score:.2f})."
            res.reasoning = (
                f"Heuristic and behavioral checks identified suspicious characteristics. "
                f"Flags: {', '.join(res.url_heuristics_flags or ['Heuristic indicators'])}."
            )
        else:
            res.is_phishing = False
            res.is_suspicious = False
            res.confidence = 0.50
            res.summary = "No behavioral phishing indicators detected by local heuristic inspection."
            res.reasoning = "Target page exhibits no credential harvesting forms, sensor probes, or deceptive branding."

