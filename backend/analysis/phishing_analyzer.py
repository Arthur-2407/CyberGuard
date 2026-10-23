import time
import re
from typing import List

from backend.threats.models import (
    ThreatEvent, Evidence, Explanation, ThreatCategory, RiskLevel
)

class PhishingAnalyzer:
    """Heuristics-based Phishing and Social Engineering analyzer for text."""
    
    def __init__(self, config=None):
        self.config = config
        
        self.urgency_keywords = [
            "urgent", "immediately", "action required", "account suspended",
            "last chance", "act now", "final notice", "within 24 hours",
            "expiring soon", "limited time", "immediate attention"
        ]
        
        self.credential_keywords = [
            "password", "login", "verify your account", "confirm identity",
            "ssn", "social security", "credit card", "bank details", "pin code",
            "passcode", "security question", "unlock account", "re-authenticate"
        ]
        
        self.financial_keywords = [
            "wire transfer", "gift card", "crypto", "bitcoin", "payment",
            "invoice attached", "unpaid", "overdue", "bank account", "remittance",
            "direct deposit", "payroll", "refund", "tax return"
        ]

        self.authority_impersonation_keywords = [
            "ceo", "chief executive", "managing director", "it support", "helpdesk",
            "system administrator", "hr department", "human resources", "legal counsel",
            "aicte", "cyber security cell", "income tax", "police department",
            "compliance officer", "audit committee"
        ]

        self.brand_impersonation_keywords = [
            "paypal", "microsoft 365", "office 365", "google workspace", "apple id",
            "netflix", "amazon prime", "state bank of india", "sbi", "hdfc bank",
            "icici bank", "chase bank", "wells fargo", "binance", "metamask"
        ]

        self.psychological_pressure_keywords = [
            "legal action", "arrest warrant", "account will be terminated",
            "strictly confidential", "keep this private", "do not discuss with anyone",
            "security breach detected", "unauthorized access reported"
        ]

    def analyze(self, text: str, source: str = "text_submission", correlation_id: str = None) -> ThreatEvent:
        start_time = time.time()
        evidences: List[Evidence] = []
        risk_score = 0.0
        
        text_lower = text.lower()
        
        # Rule 1: Urgency
        found_urgency = [kw for kw in self.urgency_keywords if kw in text_lower]
        if found_urgency:
            evidences.append(Evidence(
                evidence_type="urgency_language",
                description="Text contains language intended to create artificial urgency.",
                value=",".join(found_urgency),
                severity_contribution=0.3,
                source="phishing_analyzer"
            ))
            risk_score += 0.3
            
        # Rule 2: Credential harvesting
        found_credentials = [kw for kw in self.credential_keywords if kw in text_lower]
        if found_credentials:
            evidences.append(Evidence(
                evidence_type="credential_request",
                description="Text contains requests for credentials or sensitive information.",
                value=",".join(found_credentials),
                severity_contribution=0.4,
                source="phishing_analyzer"
            ))
            risk_score += 0.4
            
        # Rule 3: Financial requests
        found_financial = [kw for kw in self.financial_keywords if kw in text_lower]
        if found_financial:
            evidences.append(Evidence(
                evidence_type="financial_request",
                description="Text contains language related to urgent financial transactions.",
                value=",".join(found_financial),
                severity_contribution=0.3,
                source="phishing_analyzer"
            ))
            risk_score += 0.3
            
        # Rule 4: Suspicious Links
        # Just check for existence of http links in text, actual link analysis is done by url_analyzer
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text_lower)
        if urls:
            evidences.append(Evidence(
                evidence_type="embedded_links",
                description="Text contains embedded links. These should be analyzed separately.",
                value=f"Found {len(urls)} links",
                severity_contribution=0.1,
                source="phishing_analyzer"
            ))
            risk_score += 0.1

        # Rule 5: Authority & Executive Impersonation
        found_authority = [kw for kw in self.authority_impersonation_keywords if kw in text_lower]
        if found_authority:
            evidences.append(Evidence(
                evidence_type="executive_authority_impersonation",
                description="Text exhibits indicators of executive, managerial or institutional authority impersonation.",
                value=",".join(found_authority),
                severity_contribution=0.35,
                source="phishing_analyzer"
            ))
            risk_score += 0.35

        # Rule 6: Brand Impersonation & Spoofing
        found_brands = [kw for kw in self.brand_impersonation_keywords if kw in text_lower]
        if found_brands:
            evidences.append(Evidence(
                evidence_type="brand_impersonation",
                description="Text references trusted high-value corporate or financial brands often abused in phishing lures.",
                value=",".join(found_brands),
                severity_contribution=0.25,
                source="phishing_analyzer"
            ))
            risk_score += 0.25

        # Rule 7: Psychological Coercion & Pressure
        found_pressure = [kw for kw in self.psychological_pressure_keywords if kw in text_lower]
        if found_pressure:
            evidences.append(Evidence(
                evidence_type="psychological_coercion",
                description="Text employs psychological pressure, fear tactics, or artificial secrecy to inhibit verification.",
                value=",".join(found_pressure),
                severity_contribution=0.3,
                source="phishing_analyzer"
            ))
            risk_score += 0.3
            
        # Determine severity
        risk_score = min(risk_score, 1.0)
        if risk_score >= 0.8:
            severity = RiskLevel.CRITICAL
            classification = "SUSPICIOUS"
        elif risk_score >= 0.6:
            severity = RiskLevel.HIGH
            classification = "SUSPICIOUS"
        elif risk_score >= 0.35:
            severity = RiskLevel.MEDIUM
            classification = "SUSPICIOUS"
        elif risk_score > 0.0:
            severity = RiskLevel.LOW
            classification = "SAFE"
        else:
            severity = RiskLevel.SAFE
            classification = "SAFE"

        # Explanation
        if evidences:
            summary = "Phishing & social engineering indicators detected in message."
            reasoning = (
                f"Content exhibits {len(evidences)} corroborating social engineering vectors "
                f"(urgency, credential probing, or institutional impersonation)."
            )
        else:
            summary = "No phishing indicators detected."
            reasoning = "The text appears normal based on current heuristic rules."

        explanation = Explanation(
            summary=summary,
            reasoning=reasoning
        )

        actions = []
        if severity in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            actions = [
                "Do not click embedded links or download attachments",
                "Verify sender authenticity via known out-of-band contact channel",
                "Quarantine communication and notify SOC team",
                "Report impersonation attempt to security operations"
            ]

        event = ThreatEvent(
            source=source,
            source_type="text",
            modality="text",
            threat_category=ThreatCategory.PHISHING if risk_score >= 0.35 else ThreatCategory.SAFE,
            severity=severity,
            confidence=0.85 if evidences else 1.0,
            classification=classification,
            evidence=evidences,
            explanation=explanation,
            recommended_actions=actions,
            detector="PhishingHeuristicAnalyzer",
            processing_time_ms=(time.time() - start_time) * 1000.0,
            correlation_id=correlation_id,
            mitre_technique_id="T1566.002" if risk_score >= 0.35 else None,
            mitre_technique_name="Spearphishing Link" if risk_score >= 0.35 else None,
        )

        # Trigger automatic policy enforcement if critical
        try:
            from backend.security.enforcement import get_enforcement_engine
            get_enforcement_engine().evaluate_threat_for_auto_block(event)
        except Exception:
            pass

        # Trigger threshold email alert if critical
        try:
            from backend.alerts.email_notifier import get_email_notifier
            import asyncio
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(get_email_notifier().notify_threat_event(event))
            except RuntimeError:
                pass
        except Exception:
            pass

        return event
