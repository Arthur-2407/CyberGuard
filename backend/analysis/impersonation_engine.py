import time
from typing import Optional, List

from backend.threats.models import (
    ThreatEvent, Evidence, Explanation, ThreatCategory, RiskLevel
)

class ImpersonationEngine:
    """Wraps speaker consistency to identify Digital Impersonation attacks."""
    
    def __init__(self, config=None, registry=None):
        self.config = config
        self.registry = registry

    def analyze(self, speaker_similarity: float, speaker_id: str, correlation_id: str = None) -> ThreatEvent:
        start_time = time.time()
        
        # If there's no similarity score (e.g. no speaker enrolled)
        if speaker_similarity is None:
            return self._build_safe_event("No enrolled speaker profile to compare against.", correlation_id, start_time)
            
        threshold = self.config.speaker.consistency_threshold if self.config else 0.75
        
        evidences = []
        is_impersonation = speaker_similarity < threshold
        
        if is_impersonation:
            evidences.append(Evidence(
                evidence_type="speaker_inconsistency",
                description=f"Voice embedding cosine similarity ({speaker_similarity:.2f}) is below the trusted threshold ({threshold:.2f}).",
                value=str(speaker_similarity),
                severity_contribution=0.8,
                source="SpeakerConsistency"
            ))
            
            severity = RiskLevel.HIGH
            classification = "SUSPICIOUS"
            summary = f"Digital Impersonation detected for {speaker_id}."
            reasoning = "The active speaker's voice does not match the enrolled biometric profile for this identity."
            threat_category = ThreatCategory.DIGITAL_IMPERSONATION
        else:
            evidences.append(Evidence(
                evidence_type="speaker_match",
                description=f"Voice embedding cosine similarity ({speaker_similarity:.2f}) meets the trusted threshold ({threshold:.2f}).",
                value=str(speaker_similarity),
                severity_contribution=0.0,
                source="SpeakerConsistency"
            ))
            
            severity = RiskLevel.SAFE
            classification = "SAFE"
            summary = f"Speaker identity verified as {speaker_id}."
            reasoning = "The active speaker's voice matches the enrolled biometric profile."
            threat_category = ThreatCategory.SAFE
            
        explanation = Explanation(summary=summary, reasoning=reasoning)
        
        return ThreatEvent(
            source="audio_stream",
            source_type="audio",
            modality="voice",
            threat_category=threat_category,
            severity=severity,
            confidence=0.9,
            classification=classification,
            evidence=evidences,
            explanation=explanation,
            recommended_actions=["Request video verification", "Halt sensitive transactions"] if is_impersonation else [],
            affected_user=speaker_id,
            detector="ImpersonationEngine",
            processing_time_ms=(time.time() - start_time) * 1000.0,
            correlation_id=correlation_id
        )
        
    def _build_safe_event(self, summary, correlation_id, start_time) -> ThreatEvent:
        return ThreatEvent(
            source="audio_stream",
            source_type="audio",
            modality="voice",
            threat_category=ThreatCategory.INSUFFICIENT_EVIDENCE,
            severity=RiskLevel.SAFE,
            classification="SAFE",
            explanation=Explanation(
                summary=summary,
                reasoning="Insufficient evidence to assess impersonation risk."
            ),
            detector="ImpersonationEngine",
            processing_time_ms=(time.time() - start_time) * 1000.0,
            correlation_id=correlation_id
        )
