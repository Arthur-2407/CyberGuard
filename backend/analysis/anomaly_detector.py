import time
from typing import List, Dict, Any

from backend.threats.models import (
    ThreatEvent, Evidence, Explanation, ThreatCategory, RiskLevel
)

class AnomalyDetector:
    """Heuristics-based Anomaly detector for technical and authentication events."""
    
    def __init__(self, config=None):
        self.config = config

    def analyze(self, event_data: Dict[str, Any], source: str = "log_ingestion", correlation_id: str = None) -> ThreatEvent:
        start_time = time.time()
        evidences: List[Evidence] = []
        risk_score = 0.0
        
        event_type = event_data.get("event_type", "unknown").lower()
        user = event_data.get("user", "unknown")
        ip_address = event_data.get("ip_address", "unknown")
        
        threat_category = ThreatCategory.ANOMALOUS_BEHAVIOUR
        
        # Scenario 1: Authentication Logs (Credential Attack / ATO)
        if event_type in ["login", "authentication"]:
            threat_category = ThreatCategory.CREDENTIAL_ATTACK
            failed_attempts = event_data.get("failed_attempts", 0)
            
            if failed_attempts > 10:
                evidences.append(Evidence(
                    evidence_type="brute_force",
                    description=f"High number of failed login attempts ({failed_attempts}).",
                    value=str(failed_attempts),
                    severity_contribution=0.7,
                    source="anomaly_detector"
                ))
                risk_score += 0.7
                
            elif failed_attempts > 3:
                evidences.append(Evidence(
                    evidence_type="repeated_failures",
                    description="Multiple failed login attempts.",
                    value=str(failed_attempts),
                    severity_contribution=0.3,
                    source="anomaly_detector"
                ))
                risk_score += 0.3
                
            is_new_device = event_data.get("is_new_device", False)
            if is_new_device and event_data.get("status") == "success":
                evidences.append(Evidence(
                    evidence_type="new_device_login",
                    description="Successful login from a previously unseen device.",
                    severity_contribution=0.4,
                    source="anomaly_detector"
                ))
                risk_score += 0.4
                threat_category = ThreatCategory.ACCOUNT_TAKEOVER
                
        # Scenario 2: API Abuse / System Logs
        elif event_type in ["api_request", "system_event"]:
            request_rate = event_data.get("requests_per_minute", 0)
            
            if request_rate > 1000:
                evidences.append(Evidence(
                    evidence_type="api_abuse",
                    description="Abnormally high request rate detected.",
                    value=f"{request_rate} req/min",
                    severity_contribution=0.6,
                    source="anomaly_detector"
                ))
                risk_score += 0.6
                threat_category = ThreatCategory.API_ABUSE
                
            data_volume_mb = event_data.get("data_volume_mb", 0)
            if data_volume_mb > 500:
                evidences.append(Evidence(
                    evidence_type="large_data_transfer",
                    description="Unusually large data transfer, potential exfiltration.",
                    value=f"{data_volume_mb} MB",
                    severity_contribution=0.8,
                    source="anomaly_detector"
                ))
                risk_score += 0.8
                threat_category = ThreatCategory.DATA_EXFILTRATION

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
            threat_category = ThreatCategory.SAFE

        # Explanation
        if evidences:
            summary = f"Anomalous behavior detected in {event_type} event."
            reasoning = "Event characteristics deviated significantly from expected baselines."
        else:
            summary = "No anomalies detected."
            reasoning = "Event parameters are within normal ranges."

        explanation = Explanation(
            summary=summary,
            reasoning=reasoning
        )
        
        recommended_actions = []
        if severity in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            if threat_category == ThreatCategory.CREDENTIAL_ATTACK:
                recommended_actions = ["Block IP", "Require MFA"]
            elif threat_category == ThreatCategory.ACCOUNT_TAKEOVER:
                recommended_actions = ["Revoke Session", "Lock Account"]
            else:
                recommended_actions = ["Investigate User Activity", "Rate Limit"]

        return ThreatEvent(
            source=source,
            source_type="system_log",
            modality="structured_data",
            threat_category=threat_category,
            severity=severity,
            confidence=0.8 if evidences else 1.0,
            classification=classification,
            evidence=evidences,
            explanation=explanation,
            recommended_actions=recommended_actions,
            affected_user=user if user != "unknown" else None,
            detector="LogAnomalyDetector",
            processing_time_ms=(time.time() - start_time) * 1000.0,
            correlation_id=correlation_id
        )
