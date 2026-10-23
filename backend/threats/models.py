"""
models.py — Unified Threat Event Model for CyberGuard.

Defines the normalized schema for all analyzed threats, 
including enums for risk levels, threat categories, and incident statuses.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import time
import uuid

class ThreatCategory(str, Enum):
    SAFE = "SAFE"
    PHISHING = "PHISHING"
    SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING"
    DIGITAL_IMPERSONATION = "DIGITAL_IMPERSONATION"
    VOICE_CLONING = "VOICE_CLONING"
    DEEPFAKE = "DEEPFAKE"
    MALICIOUS_URL = "MALICIOUS_URL"
    CREDENTIAL_ATTACK = "CREDENTIAL_ATTACK"
    ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER"
    ANOMALOUS_BEHAVIOUR = "ANOMALOUS_BEHAVIOUR"
    MALWARE_INDICATOR = "MALWARE_INDICATOR"
    SUSPICIOUS_NETWORK_ACTIVITY = "SUSPICIOUS_NETWORK_ACTIVITY"
    API_ABUSE = "API_ABUSE"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    UNKNOWN = "UNKNOWN"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

class RiskLevel(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class IncidentStatus(str, Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    CLOSED = "CLOSED"

class Evidence(BaseModel):
    evidence_type: str
    description: str
    value: Optional[str] = None
    severity_contribution: float = 0.0
    confidence: float = 1.0
    source: str

class Explanation(BaseModel):
    summary: str
    reasoning: str
    limitations: Optional[str] = None

class ThreatEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = Field(default_factory=time.time)
    source: str
    source_type: str
    modality: str
    threat_category: ThreatCategory
    subcategory: Optional[str] = None
    severity: RiskLevel = RiskLevel.SAFE
    confidence: float = 0.0
    classification: str
    evidence: List[Evidence] = Field(default_factory=list)
    explanation: Optional[Explanation] = None
    recommended_actions: List[str] = Field(default_factory=list)
    incident_status: Optional[IncidentStatus] = None
    affected_user: Optional[str] = None
    affected_asset: Optional[str] = None
    detector: str
    detector_version: str = "1.0"
    processing_time_ms: float = 0.0
    capability_status: str = "READY"
    correlation_id: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    threat_intelligence: Optional[Dict[str, Any]] = None
    forensic_metrics: Optional[Dict[str, Any]] = None
    threat_score: Optional[float] = None
    media_info: Optional[Dict[str, Any]] = None
    metadata_details: Optional[Dict[str, Any]] = None
    frame_analysis: Optional[Dict[str, Any]] = None

class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    events: List[ThreatEvent] = Field(default_factory=list)
    event_count: int = 0
    first_seen: float = Field(default_factory=time.time)
    last_seen: float = Field(default_factory=time.time)
    category: ThreatCategory = ThreatCategory.UNKNOWN
    risk: RiskLevel = RiskLevel.LOW
    status: IncidentStatus = IncidentStatus.NEW
    affected_assets: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    analyst_notes: Optional[str] = None
    resolved_at: Optional[float] = None
