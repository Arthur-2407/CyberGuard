"""
web_inspector.py — Comprehensive Web Page, DOM, Behavioral, and Forensic Inspector for CyberGuard.

Analyzes:
  1. Credential-Harvesting Mechanisms (inputs, forms, cross-domain targets, exfiltration scripts)
  2. Sensitive Permission-Abuse Probes (Geolocation/GPS, Camera, Microphone, Notifications)
  3. Deceptive Content, Brand Impersonation, and Social Engineering Lures (Fake Meetings, Login Portals)
  4. Malware Distribution, Dropper Links, and Payload Delivery Indicators

Isolation & Safety:
  - Untrusted HTML and script analysis is strictly non-executing and sandboxed.
  - Safe parsing via BeautifulSoup and regex inspection.
  - Never grants camera, mic, location, or sensitive permissions during automated analysis.
"""

from __future__ import annotations

import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class InspectionState(str, Enum):
    CLEAN = "CLEAN"
    HARVESTING_DETECTED = "HARVESTING_DETECTED"
    PERMISSION_ABUSE_DETECTED = "PERMISSION_ABUSE_DETECTED"
    BRAND_IMPERSONATION_DETECTED = "BRAND_IMPERSONATION_DETECTED"
    MALWARE_DELIVERY_DETECTED = "MALWARE_DELIVERY_DETECTED"
    SUSPICIOUS_CONTENT = "SUSPICIOUS_CONTENT"
    UNREACHABLE = "UNREACHABLE"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"
    NOT_INSPECTED = "NOT_INSPECTED"


MAJOR_BRAND_SIGNATURES: List[Tuple[str, str, List[str], List[str]]] = [
    (
        "MICROSOFT",
        "Microsoft / Office 365",
        [r"\bmicrosoft\b", r"\boffice\s*365\b", r"\boutlook\b", r"\bonedrive\b", r"\bsharepoint\b", r"\bmsft\b"],
        ["microsoft.com", "office.com", "live.com", "outlook.com", "microsoftonline.com", "sharepoint.com", "azure.com", "msn.com"]
    ),
    (
        "GOOGLE",
        "Google Workspace",
        [r"\bgoogle\b", r"\bgmail\b", r"\bgoogle\s*drive\b", r"\bgoogle\s*docs\b", r"\bgoogle\s*workspace\b"],
        ["google.com", "gmail.com", "google.co.in", "google.co.uk", "googleusercontent.com", "gstatic.com"]
    ),
    (
        "APPLE",
        "Apple / iCloud",
        [r"\bapple\s*id\b", r"\bicloud\b", r"\bapple\s*inc\b", r"\bfind\s*my\b"],
        ["apple.com", "icloud.com"]
    ),
    (
        "META",
        "Meta / Facebook / Instagram",
        [r"\bfacebook\b", r"\binstagram\b", r"\bmeta\s*platforms\b", r"\bwhatsapp\b"],
        ["facebook.com", "instagram.com", "meta.com", "whatsapp.com", "fb.com"]
    ),
    (
        "ZOOM",
        "Zoom Video Communications",
        [r"\bzoom\s*(meeting|video|webinar)?\b", r"\bjoin\s*zoom\s*meeting\b"],
        ["zoom.us", "zoom.com", "zoomgov.com"]
    ),
    (
        "TEAMS",
        "Microsoft Teams",
        [r"\bmicrosoft\s*teams\b", r"\bteams\s*meeting\b"],
        ["teams.microsoft.com", "microsoft.com", "office.com"]
    ),
    (
        "WEBEX",
        "Cisco Webex",
        [r"\bcisco\s*webex\b", r"\bwebex\s*meeting\b"],
        ["webex.com", "cisco.com"]
    ),
    (
        "PAYPAL",
        "PayPal",
        [r"\bpaypal\b", r"\bpay\s*with\s*paypal\b"],
        ["paypal.com", "paypal.me"]
    ),
    (
        "BANKING",
        "Banking & Financial Services",
        [
            r"\bstate\s*bank\s*of\s*india\b",
            r"\bsbi\s*(yono|online)?\b",
            r"\bhdfc\s*bank\b",
            r"\bicici\s*bank\b",
            r"\bchase\s*bank\b",
            r"\bwells\s*fargo\b",
            r"\bbank\s*of\s*america\b",
            r"\baxis\s*bank\b",
            r"\bkotak\s*bank\b"
        ],
        [
            "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com",
            "chase.com", "wellsfargo.com", "bankofamerica.com", "axisbank.com", "kotak.com"
        ]
    ),
    (
        "NETFLIX",
        "Netflix",
        [r"\bnetflix\b"],
        ["netflix.com"]
    ),
    (
        "AMAZON",
        "Amazon",
        [r"\bamazon\s*(prime|pay|account)?\b"],
        ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de"]
    )
]

MEETING_LURE_PATTERNS = [
    r"\bonline\s*meeting\b",
    r"\bjoin\s*(the)?\s*meeting\b",
    r"\bwaiting\s*for\s*(the)?\s*host\b",
    r"\bvideo\s*conference\b",
    r"\bmeeting\s*room\b",
    r"\bconnect\s*audio\s*and\s*video\b",
    r"\bstart\s*video\s*call\b",
    r"\bmeeting\s*id\b",
    r"\blive\s*youtube\s*tv\b",
    r"\bfestival\s*wishing\b",
    r"\bcamera\s*test\b"
]

URGENCY_PATTERNS = [
    r"\baccount\s*(has\s*been)?\s*suspended\b",
    r"\bimmediate\s*action\s*required\b",
    r"\bunauthorized\s*(sign-in|activity|access)\b",
    r"\bsecurity\s*alert\b",
    r"\bverify\s*your\s*identity\b",
    r"\bwithin\s*24\s*hours\b",
    r"\byour\s*password\s*has\s*expired\b",
    r"\bconfirm\s*your\s*credentials\b"
]

HIGH_RISK_PAYLOAD_EXTENSIONS = [
    ".exe", ".msi", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".hta", ".apk", ".jar", ".dmg", ".pkg",
    ".iso", ".img", ".vhd", ".vhdx", ".lnk", ".cpl", ".inf", ".reg"
]


@dataclass
class CredentialHarvestingReport:
    has_credential_forms: bool = False
    has_password_field: bool = False
    has_otp_field: bool = False
    has_username_field: bool = False
    input_fields: List[str] = field(default_factory=list)
    form_actions: List[str] = field(default_factory=list)
    cross_domain_targets: List[str] = field(default_factory=list)
    suspicious_endpoints: List[str] = field(default_factory=list)
    exfiltration_scripts: List[str] = field(default_factory=list)
    evidence_descriptions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "has_credential_forms": self.has_credential_forms,
            "has_password_field": self.has_password_field,
            "has_otp_field": self.has_otp_field,
            "has_username_field": self.has_username_field,
            "input_fields": self.input_fields,
            "form_actions": self.form_actions,
            "cross_domain_targets": self.cross_domain_targets,
            "suspicious_endpoints": self.suspicious_endpoints,
            "exfiltration_scripts": self.exfiltration_scripts,
            "evidence_descriptions": self.evidence_descriptions,
        }


@dataclass
class SensitivePermissionReport:
    probes_geolocation: bool = False
    probes_camera: bool = False
    probes_microphone: bool = False
    probes_notifications: bool = False
    probes_clipboard: bool = False
    deceptive_context_detected: bool = False
    lure_type: Optional[str] = None
    abuse_detected: bool = False
    evidence_descriptions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "probes_geolocation": self.probes_geolocation,
            "probes_camera": self.probes_camera,
            "probes_microphone": self.probes_microphone,
            "probes_notifications": self.probes_notifications,
            "probes_clipboard": self.probes_clipboard,
            "deceptive_context_detected": self.deceptive_context_detected,
            "lure_type": self.lure_type,
            "abuse_detected": self.abuse_detected,
            "evidence_descriptions": self.evidence_descriptions,
        }


@dataclass
class BrandImpersonationReport:
    impersonation_detected: bool = False
    brand_id: Optional[str] = None
    brand_name: Optional[str] = None
    declared_brand: Optional[str] = None
    legitimate_domain_matched: bool = False
    domain_mismatch: bool = False
    social_engineering_signals: List[str] = field(default_factory=list)
    evidence_descriptions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "impersonation_detected": self.impersonation_detected,
            "brand_id": self.brand_id,
            "brand_name": self.brand_name,
            "declared_brand": self.declared_brand,
            "legitimate_domain_matched": self.legitimate_domain_matched,
            "domain_mismatch": self.domain_mismatch,
            "social_engineering_signals": self.social_engineering_signals,
            "evidence_descriptions": self.evidence_descriptions,
        }


@dataclass
class PayloadDeliveryReport:
    malware_delivery_detected: bool = False
    download_links: List[str] = field(default_factory=list)
    high_risk_extensions: List[str] = field(default_factory=list)
    double_extension_files: List[str] = field(default_factory=list)
    auto_download_scripts: List[str] = field(default_factory=list)
    evidence_descriptions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "malware_delivery_detected": self.malware_delivery_detected,
            "download_links": self.download_links,
            "high_risk_extensions": self.high_risk_extensions,
            "double_extension_files": self.double_extension_files,
            "auto_download_scripts": self.auto_download_scripts,
            "evidence_descriptions": self.evidence_descriptions,
        }


@dataclass
class WebInspectionResult:
    is_live: bool = False
    status_code: int = 0
    inspection_state: InspectionState = InspectionState.NOT_INSPECTED
    title: str = ""
    meta_description: str = ""
    rendering_engine: str = "HTTP+BS4"
    clean_body_snippet: str = ""
    credential_harvesting: CredentialHarvestingReport = field(default_factory=CredentialHarvestingReport)
    sensitive_permissions: SensitivePermissionReport = field(default_factory=SensitivePermissionReport)
    brand_impersonation: BrandImpersonationReport = field(default_factory=BrandImpersonationReport)
    payload_delivery: PayloadDeliveryReport = field(default_factory=PayloadDeliveryReport)
    all_evidence_items: List[Dict[str, Any]] = field(default_factory=list)
    error_message: Optional[str] = None
    credential_status: str = "NOT_INSPECTED"
    permission_status: str = "NOT_INSPECTED"
    evidence_summary: str = ""
    content_type: str = "text/html"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_live": self.is_live,
            "status_code": self.status_code,
            "inspection_state": self.inspection_state.value,
            "title": self.title,
            "meta_description": self.meta_description,
            "rendering_engine": self.rendering_engine,
            "clean_body_snippet": self.clean_body_snippet[:300],
            "credential_harvesting": self.credential_harvesting.to_dict(),
            "sensitive_permissions": self.sensitive_permissions.to_dict(),
            "brand_impersonation": self.brand_impersonation.to_dict(),
            "payload_delivery": self.payload_delivery.to_dict(),
            "evidence_count": len(self.all_evidence_items),
            "evidence_items": self.all_evidence_items,
            "error_message": self.error_message,
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "WebInspectionResult":
        if not data or not isinstance(data, dict):
            return cls(is_live=False, status_code=0, inspection_state=InspectionState.NOT_INSPECTED)

        state_val = data.get("inspection_state", InspectionState.NOT_INSPECTED.value)
        try:
            state = InspectionState(state_val)
        except ValueError:
            state = InspectionState.NOT_INSPECTED

        cred_dict = data.get("credential_harvesting") or {}
        cred_report = CredentialHarvestingReport(
            has_credential_forms=cred_dict.get("has_credential_forms", False),
            has_password_field=cred_dict.get("has_password_field", False),
            has_otp_field=cred_dict.get("has_otp_field", False),
            has_username_field=cred_dict.get("has_username_field", False),
            input_fields=cred_dict.get("input_fields", []),
            form_actions=cred_dict.get("form_actions", []),
            cross_domain_targets=cred_dict.get("cross_domain_targets", []),
            suspicious_endpoints=cred_dict.get("suspicious_endpoints", []),
            exfiltration_scripts=cred_dict.get("exfiltration_scripts", []),
            evidence_descriptions=cred_dict.get("evidence_descriptions", []),
        )

        perm_dict = data.get("sensitive_permissions") or {}
        perm_report = SensitivePermissionReport(
            probes_camera=perm_dict.get("probes_camera", False),
            probes_microphone=perm_dict.get("probes_microphone", False),
            probes_geolocation=perm_dict.get("probes_geolocation", False),
            probes_notifications=perm_dict.get("probes_notifications", False),
            probes_clipboard=perm_dict.get("probes_clipboard", False),
            deceptive_context_detected=perm_dict.get("deceptive_context_detected", False),
            lure_type=perm_dict.get("lure_type"),
            abuse_detected=perm_dict.get("abuse_detected", False),
            evidence_descriptions=perm_dict.get("evidence_descriptions", []),
        )

        brand_dict = data.get("brand_impersonation") or {}
        brand_report = BrandImpersonationReport(
            impersonation_detected=brand_dict.get("impersonation_detected", False),
            brand_id=brand_dict.get("brand_id"),
            brand_name=brand_dict.get("brand_name"),
            declared_brand=brand_dict.get("declared_brand"),
            legitimate_domain_matched=brand_dict.get("legitimate_domain_matched", False),
            domain_mismatch=brand_dict.get("domain_mismatch", False),
            social_engineering_signals=brand_dict.get("social_engineering_signals", []),
            evidence_descriptions=brand_dict.get("evidence_descriptions", []),
        )

        payload_dict = data.get("payload_delivery") or {}
        payload_report = PayloadDeliveryReport(
            malware_delivery_detected=payload_dict.get("malware_delivery_detected", False),
            download_links=payload_dict.get("download_links", []),
            high_risk_extensions=payload_dict.get("high_risk_extensions", []),
            double_extension_files=payload_dict.get("double_extension_files", []),
            auto_download_scripts=payload_dict.get("auto_download_scripts", []),
            evidence_descriptions=payload_dict.get("evidence_descriptions", []),
        )

        return cls(
            is_live=data.get("is_live", False),
            status_code=data.get("status_code", 0),
            inspection_state=state,
            title=data.get("title", ""),
            meta_description=data.get("meta_description", ""),
            rendering_engine=data.get("rendering_engine", "HTTP+BS4"),
            clean_body_snippet=data.get("clean_body_snippet", ""),
            credential_harvesting=cred_report,
            sensitive_permissions=perm_report,
            brand_impersonation=brand_report,
            payload_delivery=payload_report,
            all_evidence_items=data.get("evidence_items", []),
            error_message=data.get("error_message"),
        )


class WebInspector:
    """
    Safe DOM & behavioral web analyzer executing credential, permission, impersonation, and payload audits.
    """

    @classmethod
    def inspect_offline(cls, url: str = "", error_message: str = "") -> WebInspectionResult:
        res = WebInspectionResult(
            is_live=False,
            status_code=0,
            inspection_state=InspectionState.UNREACHABLE,
            credential_status="UNVERIFIED_UNREACHABLE",
            permission_status="UNVERIFIED_UNREACHABLE",
            error_message=error_message or "Target is offline or unreachable",
            evidence_summary=f"Destination '{url}' is unreachable or offline: {error_message}",
        )
        return res

    @classmethod
    def inspect_html(
        cls,
        html_content: str = "",
        base_url: str = "",
        status_code: int = 200,
        is_live: bool = True,
        rendering_engine: str = "HTTP+BS4",
        url: str = "",
        html: str = "",
        content_type: str = "text/html",
        **kwargs: Any,
    ) -> WebInspectionResult:
        if html and not html_content:
            html_content = html
        if url and not base_url:
            base_url = url
        res = WebInspectionResult(is_live=is_live, status_code=status_code, rendering_engine=rendering_engine, content_type=content_type)

        if not is_live or not html_content or not html_content.strip():
            res.inspection_state = InspectionState.UNREACHABLE
            res.error_message = "Target webpage is offline, unreachable, or returned empty response."
            return res

        parsed_url = urllib.parse.urlparse(base_url) if base_url else None
        base_hostname = (parsed_url.hostname or "").lower() if parsed_url else ""

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, "html.parser")
        except Exception as e:
            res.inspection_state = InspectionState.ERROR
            res.error_message = f"HTML parsing error: {e}"
            return res

        if soup.title and soup.title.string:
            res.title = soup.title.string.strip()

        meta_desc = soup.find("meta", attrs={"name": "description"}) or soup.find("meta", attrs={"property": "og:description"})
        if meta_desc and meta_desc.get("content"):
            res.meta_description = str(meta_desc.get("content")).strip()

        text_elements = soup.find_all(["p", "div", "span", "h1", "h2", "h3", "li"])
        body_texts = [el.get_text(strip=True) for el in text_elements if el.get_text(strip=True)]
        combined_text = " ".join(body_texts[:40])
        res.clean_body_snippet = combined_text[:400]

        all_scripts_text = " ".join([s.get_text() for s in soup.find_all("script") if s.get_text()])

        # ── 1. Credential Harvesting Analysis ─────────────────────────────────
        cred = res.credential_harvesting
        inputs = soup.find_all(["input", "textarea", "select"])
        for inp in inputs:
            itype = (inp.get("type") or "text").lower()
            iname = (inp.get("name") or "").lower()
            iid = (inp.get("id") or "").lower()
            iplaceholder = (inp.get("placeholder") or "").lower()
            ihint = f"{iname} {iid} {iplaceholder}"

            if itype == "password" or any(k in ihint for k in ("pass", "pwd", "secret", "passwd")):
                cred.has_password_field = True
                cred.has_credential_forms = True
                cred.input_fields.append("password:" + (iname or iid))

            if any(k in ihint for k in ("otp", "token", "2fa", "mfa", "pin", "cvv", "cardnumber", "securitycode")):
                cred.has_otp_field = True
                cred.has_credential_forms = True
                cred.input_fields.append("otp_or_token:" + (iname or iid))

            if any(k in ihint for k in ("user", "login", "email", "account", "username", "phone")):
                cred.has_username_field = True
                cred.input_fields.append("identity:" + (iname or iid))

        forms = soup.find_all("form")
        for f in forms:
            action = (f.get("action") or "").strip()
            method = (f.get("method") or "get").lower()
            if not action:
                continue
            cred.form_actions.append(f"{method.upper()} {action}")
            act_parsed = urllib.parse.urlparse(action)
            act_host = (act_parsed.hostname or "").lower()

            if act_host and base_hostname and act_host != base_hostname:
                cred.cross_domain_targets.append(act_host)
                cred.evidence_descriptions.append(
                    f"Form action exfiltrates user input across domains to: {act_host}"
                )

            act_path = act_parsed.path.lower()
            if any(k in act_path for k in ("login.php", "post.php", "capture.php", "collect.php", "receive.php", "auth.php", "process.php")):
                cred.suspicious_endpoints.append(action)
                cred.evidence_descriptions.append(
                    f"Form targets known credential collection script endpoint: {action}"
                )

        script_lower = all_scripts_text.lower()
        if re.search(r'addEventListener\s*\(\s*[\'"]submit[\'"]', all_scripts_text) and cred.has_password_field:
            cred.exfiltration_scripts.append("DOM submit event listener captures form inputs programmatically")
        if re.search(r'navigator\.sendBeacon\s*\(', all_scripts_text):
            cred.exfiltration_scripts.append("navigator.sendBeacon asynchronous background telemetry dispatch")
        if re.search(r'\b(fetch|XMLHttpRequest)\b.*(location\.php|login\.php|cam\.php|post\.php)', script_lower):
            cred.exfiltration_scripts.append("AJAX/fetch background exfiltration request to collector endpoint")

        if cred.has_password_field:
            cred.evidence_descriptions.append("Target page renders password input field probing for user credentials.")
        if cred.has_otp_field:
            cred.evidence_descriptions.append("Target page renders OTP/PIN/Security token verification input.")

        # ── 2. Sensitive Permissions Probes ───────────────────────────────────
        perm = res.sensitive_permissions

        if re.search(r'navigator\.geolocation\.(getCurrentPosition|watchPosition)', all_scripts_text):
            perm.probes_geolocation = True
            perm.evidence_descriptions.append(
                "JavaScript API invocation: 'navigator.geolocation.getCurrentPosition/watchPosition' active GPS tracking probe detected."
            )

        if re.search(r'navigator\.(mediaDevices\.getUserMedia|getUserMedia|webkitGetUserMedia|mozGetUserMedia)', all_scripts_text):
            if re.search(r'video\s*:\s*(true|\{)', all_scripts_text):
                perm.probes_camera = True
                perm.evidence_descriptions.append(
                    "JavaScript API invocation: 'navigator.mediaDevices.getUserMedia({video: true})' active webcam/video capture probe detected."
                )
            if re.search(r'audio\s*:\s*(true|\{)', all_scripts_text):
                perm.probes_microphone = True
                perm.evidence_descriptions.append(
                    "JavaScript API invocation: 'navigator.mediaDevices.getUserMedia({audio: true})' active microphone audio probe detected."
                )

        if re.search(r'Notification\.requestPermission', all_scripts_text):
            perm.probes_notifications = True
            perm.evidence_descriptions.append("Browser Notification permission prompt probe detected.")
        if re.search(r'navigator\.clipboard\.readText', all_scripts_text):
            perm.probes_clipboard = True
            perm.evidence_descriptions.append("Clipboard access probe detected ('navigator.clipboard.readText').")

        eval_text = (f"{res.title} {res.meta_description} {combined_text}").lower()
        for meeting_pat in MEETING_LURE_PATTERNS:
            if re.search(meeting_pat, eval_text):
                perm.deceptive_context_detected = True
                perm.lure_type = "MEETING_OR_SOCIAL_ENGINEERING_LURE"
                break

        if (perm.probes_camera or perm.probes_geolocation or perm.probes_microphone):
            if perm.deceptive_context_detected:
                perm.abuse_detected = True
                cam_label = "Camera " if perm.probes_camera else ""
                gps_label = "GPS " if perm.probes_geolocation else ""
                perm.evidence_descriptions.append(
                    f"Sensitive hardware/location permission probe ({cam_label}{gps_label}) paired with "
                    f"deceptive social engineering lure ('{perm.lure_type}'). Characteristic of automated CamPhish / surveillance kits."
                )
            elif "trycloudflare.com" in base_url or "ngrok" in base_url or "localtunnel" in base_url:
                perm.abuse_detected = True
                perm.evidence_descriptions.append(
                    "Sensitive device permission probe (Camera/GPS) operating on temporary public tunnel endpoint without established identity."
                )

        # ── 3. Brand Impersonation & Social Engineering ───────────────────────
        brand = res.brand_impersonation
        for brand_id, display_name, patterns, official_domains in MAJOR_BRAND_SIGNATURES:
            matched_pattern = False
            for pat in patterns:
                if re.search(pat, eval_text):
                    matched_pattern = True
                    break
            if not matched_pattern:
                continue

            brand.declared_brand = display_name
            brand.brand_id = brand_id
            brand.brand_name = display_name

            is_official = False
            if base_hostname:
                for off in official_domains:
                    if base_hostname == off or base_hostname.endswith("." + off):
                        is_official = True
                        break

            brand.legitimate_domain_matched = is_official
            if not is_official and base_hostname:
                brand.domain_mismatch = True
                if cred.has_credential_forms or cred.has_password_field or perm.deceptive_context_detected:
                    brand.impersonation_detected = True
                    brand.evidence_descriptions.append(
                        f"Brand Impersonation Detected: Page visual or textual indicators claim to represent '{display_name}', "
                        f"but host '{base_hostname}' is NOT an authorized domain for this entity."
                    )
            break

        for urg in URGENCY_PATTERNS:
            if re.search(urg, eval_text):
                cleaned_urg = urg.replace(r"\b", "").replace(r"\s*", " ")
                brand.social_engineering_signals.append(cleaned_urg)
        if brand.social_engineering_signals:
            brand.evidence_descriptions.append(
                f"Urgency & psychological coercion language detected: {', '.join(brand.social_engineering_signals[:3])}"
            )

        # ── 4. Malware & Payload Delivery ─────────────────────────────────────
        mal = res.payload_delivery
        links = soup.find_all("a", href=True)
        for a in links:
            href = (a.get("href") or "").strip()
            href_clean = href.split("?")[0].lower()
            for ext in HIGH_RISK_PAYLOAD_EXTENSIONS:
                if href_clean.endswith(ext):
                    mal.download_links.append(href)
                    if ext not in mal.high_risk_extensions:
                        mal.high_risk_extensions.append(ext)
                    if re.search(r'\.(pdf|doc|docx|xls|xlsx|txt|jpg|png|zip)\.(exe|scr|bat|vbs|msi)$', href_clean):
                        mal.double_extension_files.append(href)

        if mal.double_extension_files:
            mal.malware_delivery_detected = True
            mal.evidence_descriptions.append(
                f"Deceptive double-extension executable file download link detected: {', '.join(mal.double_extension_files[:2])}"
            )
        elif mal.high_risk_extensions:
            mal.malware_delivery_detected = True
            mal.evidence_descriptions.append(
                f"High-risk executable or script payload download links detected: {', '.join(mal.high_risk_extensions[:4])}"
            )

        # ── 5. State Classification ───────────────────────────────────────────
        if cred.has_password_field and (brand.impersonation_detected or cred.cross_domain_targets or cred.suspicious_endpoints):
            res.inspection_state = InspectionState.HARVESTING_DETECTED
        elif perm.abuse_detected:
            res.inspection_state = InspectionState.PERMISSION_ABUSE_DETECTED
        elif brand.impersonation_detected:
            res.inspection_state = InspectionState.BRAND_IMPERSONATION_DETECTED
        elif mal.malware_delivery_detected:
            res.inspection_state = InspectionState.MALWARE_DELIVERY_DETECTED
        elif cred.has_password_field or perm.probes_camera or perm.probes_geolocation or brand.social_engineering_signals:
            res.inspection_state = InspectionState.SUSPICIOUS_CONTENT
        else:
            res.inspection_state = InspectionState.CLEAN

        # ── 6. Normalize Evidence Collection ──────────────────────────────────
        for desc in cred.evidence_descriptions:
            res.all_evidence_items.append({
                "evidence_type": "credential_harvesting_indicator",
                "description": desc,
                "severity_contribution": 0.85 if "password" in desc.lower() else 0.45,
                "confidence": 0.95,
                "source": "WebInspector"
            })
        for desc in perm.evidence_descriptions:
            res.all_evidence_items.append({
                "evidence_type": "sensitive_permission_probe",
                "description": desc,
                "severity_contribution": 0.80 if perm.abuse_detected else 0.40,
                "confidence": 0.92,
                "source": "WebInspector"
            })
        for desc in brand.evidence_descriptions:
            res.all_evidence_items.append({
                "evidence_type": "brand_impersonation_indicator",
                "description": desc,
                "severity_contribution": 0.75 if brand.impersonation_detected else 0.35,
                "confidence": 0.90,
                "source": "WebInspector"
            })
        for desc in mal.evidence_descriptions:
            res.all_evidence_items.append({
                "evidence_type": "malware_payload_delivery",
                "description": desc,
                "severity_contribution": 0.90,
                "confidence": 0.95,
                "source": "WebInspector"
            })

        return res


_global_web_inspector: Optional[WebInspector] = None


def get_web_inspector() -> WebInspector:
    global _global_web_inspector
    if _global_web_inspector is None:
        _global_web_inspector = WebInspector()
    return _global_web_inspector
