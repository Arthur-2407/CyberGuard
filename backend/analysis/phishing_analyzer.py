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
            "last chance", "act now", "final notice", "within 24 hours"
        ]
        
        self.credential_keywords = [
            "password", "login", "verify your account", "confirm identity",
            "ssn", "social security", "credit card", "bank details", "pin code"
        ]
        
        self.financial_keywords = [
            "wire transfer", "gift card", "crypto", "bitcoin", "payment",
            "invoice attached", "unpaid", "overdue", "bank account"
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
            summary = "Phishing indicators detected in text."
            reasoning = "The text exhibits characteristics of social engineering, combining multiple suspicious factors."
        else:
            summary = "No phishing indicators detected."
            reasoning = "The text appears normal based on current heuristic rules."

        explanation = Explanation(
            summary=summary,
            reasoning=reasoning
        )

        return ThreatEvent(
            source=source,
            source_type="text",
            modality="text",
            threat_category=ThreatCategory.PHISHING if risk_score >= 0.35 else ThreatCategory.SAFE,
            severity=severity,
            confidence=0.7 if evidences else 1.0,
            classification=classification,
            evidence=evidences,
            explanation=explanation,
            recommended_actions=["Do not click links", "Verify sender identity out-of-band"] if severity in [RiskLevel.HIGH, RiskLevel.CRITICAL] else [],
            detector="PhishingHeuristicAnalyzer",
            processing_time_ms=(time.time() - start_time) * 1000.0,
            correlation_id=correlation_id
        )
