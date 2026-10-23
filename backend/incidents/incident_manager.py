import logging
import time
from typing import List, Dict, Optional, Any, Union
import uuid
import json
import datetime

from backend.threats.models import (
    ThreatEvent, Evidence, Explanation, Incident, IncidentStatus, RiskLevel, ThreatCategory
)
from backend.storage.database import (
    get_session_factory, ThreatEventModel, ThreatEvidenceModel, IncidentModel
)

logger = logging.getLogger(__name__)


def _to_utc_timestamp(dt: Optional[datetime.datetime]) -> Optional[float]:
    """Converts a SQLite-stored naive UTC datetime to an accurate epoch timestamp."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.timestamp()


class IncidentManager:
    """Correlates ThreatEvents into Incidents and manages security response lifecycle."""
    
    def __init__(self, config=None, db_path="data/cyberguard.db"):
        self.config = config
        self.db_path = db_path
        self._active_incidents: Dict[str, Incident] = {}
        
    def process_event(self, event: ThreatEvent) -> Incident:
        """Processes a new ThreatEvent, correlating or creating an actionable incident."""
        
        # Only create/update incidents for events that are SUSPICIOUS / elevated (not SAFE)
        if event.threat_category == ThreatCategory.SAFE or event.severity == RiskLevel.SAFE:
            self._save_event_to_db(event)
            return None
            
        incident = None
        
        # Correlation by correlation_id or affected_user / affected_asset
        if event.correlation_id and event.correlation_id in self._active_incidents:
            incident = self._active_incidents[event.correlation_id]
        else:
            for inc in self._active_incidents.values():
                if event.affected_user and event.affected_user in inc.affected_assets:
                    incident = inc
                    break
                if event.affected_asset and event.affected_asset in inc.affected_assets:
                    incident = inc
                    break
                    
        if not incident:
            # Check DB for active (unresolved) incident with same correlation ID or asset
            session_factory = get_session_factory(self.db_path)
            with session_factory() as db:
                if event.correlation_id:
                    existing_db = db.query(IncidentModel).filter(
                        IncidentModel.incident_id == event.correlation_id,
                        IncidentModel.status.in_(["NEW", "INVESTIGATING", "CONTAINED"])
                    ).first()
                    if existing_db:
                        incident = self._model_to_incident(existing_db, db=db)

            if not incident:
                # Create brand new incident
                inc_id = event.correlation_id if (event.correlation_id and len(event.correlation_id) <= 16) else str(uuid.uuid4())[:8]
                incident = Incident(
                    incident_id=inc_id,
                    first_seen=event.timestamp,
                    last_seen=event.timestamp,
                    category=event.threat_category,
                    risk=event.severity,
                    status=IncidentStatus.NEW,
                )

        if incident.incident_id:
            self._active_incidents[incident.incident_id] = incident

        # Update incident attributes
        incident.events.append(event)
        incident.event_count = len(incident.events)
        incident.last_seen = event.timestamp
        
        # Elevate risk to highest observed
        if self._risk_level_to_int(event.severity) > self._risk_level_to_int(incident.risk):
            incident.risk = event.severity
            
        # Update category if the new event has a more specific category
        if incident.category in [ThreatCategory.UNKNOWN, ThreatCategory.INSUFFICIENT_EVIDENCE, ThreatCategory.SAFE]:
            incident.category = event.threat_category
            
        # Add affected entities
        if event.affected_user and event.affected_user not in incident.affected_assets:
            incident.affected_assets.append(event.affected_user)
        if event.affected_asset and event.affected_asset not in incident.affected_assets:
            incident.affected_assets.append(event.affected_asset)
        if event.threat_intelligence and isinstance(event.threat_intelligence, dict):
            rec_malware = event.threat_intelligence.get("recorded_malware_url")
            if rec_malware and rec_malware not in incident.affected_assets:
                incident.affected_assets.append(rec_malware)

            
        # Accumulate distinct recommendations
        for rec in event.recommended_actions:
            if rec not in incident.recommendations:
                incident.recommendations.append(rec)
                
        event.incident_status = incident.status
        event.correlation_id = incident.incident_id
        
        self._save_event_to_db(event)
        self._save_incident_to_db(incident)
        self._broadcast_incident_event(incident, action="created_or_updated")
        
        return incident

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Fetch incident from DB or active cache."""
        session_factory = get_session_factory(self.db_path)
        with session_factory() as db:
            inc_model = db.query(IncidentModel).filter(IncidentModel.incident_id == incident_id).first()
            if inc_model:
                return self._model_to_incident(inc_model, db=db)
        if incident_id in self._active_incidents:
            return self._active_incidents[incident_id]
        return None

    def get_all_incidents(self, limit: int = 50) -> List[Incident]:
        """Fetch all incidents from DB with populated event metadata."""
        incidents = []
        session_factory = get_session_factory(self.db_path)
        with session_factory() as db:
            models = db.query(IncidentModel).order_by(IncidentModel.first_seen.desc()).limit(limit).all()
            for m in models:
                incidents.append(self._model_to_incident(m, db=db))
        return incidents

    def get_recent_threat_events(self, limit: int = 50) -> List[ThreatEvent]:
        """Fetch recent ThreatEvents across all modalities."""
        events = []
        session_factory = get_session_factory(self.db_path)
        with session_factory() as db:
            models = db.query(ThreatEventModel).order_by(ThreatEventModel.timestamp.desc()).limit(limit).all()
            for m in models:
                events.append(self._model_to_threat_event(m, db=db))
        return events

    def update_incident_status(self, incident_id: str, new_status: IncidentStatus, notes: str = None) -> bool:
        """Updates the status and analyst notes of an incident."""
        session_factory = get_session_factory(self.db_path)
        with session_factory() as db:
            inc_model = db.query(IncidentModel).filter(IncidentModel.incident_id == incident_id).first()
            if inc_model:
                inc_model.status = new_status.value if hasattr(new_status, "value") else str(new_status)
                if notes:
                    inc_model.analyst_notes = notes
                if inc_model.status in [IncidentStatus.RESOLVED.value, IncidentStatus.FALSE_POSITIVE.value, IncidentStatus.CLOSED.value]:
                    inc_model.resolved_at = datetime.datetime.now(datetime.timezone.utc)
                db.commit()
                
                # Update memory if active
                if incident_id in self._active_incidents:
                    self._active_incidents[incident_id].status = new_status
                    if notes:
                        self._active_incidents[incident_id].analyst_notes = notes
                
                self._broadcast_status_change(incident_id, new_status, notes)
                return True
        return False

    def _broadcast_incident_event(self, incident: Incident, action: str = "updated"):
        try:
            from backend.main import get_app_ws_notifier
            ws_notifier = get_app_ws_notifier()
            if ws_notifier and hasattr(ws_notifier, "broadcast_raw"):
                import asyncio
                msg = {
                    "type": "incident_update",
                    "action": action,
                    "incident": self._incident_to_dict(incident)
                }
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(ws_notifier.broadcast_raw(msg))
                except RuntimeError:
                    pass
        except Exception as exc:
            logger.debug(f"Incident broadcast skipped: {exc}")

    def _broadcast_status_change(self, incident_id: str, new_status: IncidentStatus, notes: str = None):
        try:
            from backend.main import get_app_ws_notifier
            ws_notifier = get_app_ws_notifier()
            if ws_notifier and hasattr(ws_notifier, "broadcast_raw"):
                import asyncio
                status_str = new_status.value if hasattr(new_status, "value") else str(new_status)
                msg = {
                    "type": "incident_status_changed",
                    "incident_id": incident_id,
                    # Field is named "status" (not "new_status") so the frontend
                    # handleWsStatusChange can read it as data.status without a mismatch.
                    # The old field name "new_status" caused status changes to silently
                    # fail to update local item state in the Security Center.
                    "status": status_str,
                    "analyst_notes": notes
                }
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(ws_notifier.broadcast_raw(msg))
                except RuntimeError:
                    pass
        except Exception as exc:
            logger.debug(f"Status change broadcast skipped: {exc}")

    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Generates unified dashboard security posture summary accurately aggregated across full database."""
        session_factory = get_session_factory(self.db_path)
        with session_factory() as db:
            from sqlalchemy import func
            
            total_incidents = db.query(func.count(IncidentModel.id)).scalar() or 0
            open_statuses = ["NEW", "INVESTIGATING", "CONTAINED"]
            open_incidents = db.query(func.count(IncidentModel.id)).filter(
                IncidentModel.status.in_(open_statuses)
            ).scalar() or 0
            
            total_events = db.query(func.count(ThreatEventModel.id)).scalar() or 0
            
            # Active high/critical threats (open incidents with HIGH or CRITICAL risk)
            active_high_critical = db.query(func.count(IncidentModel.id)).filter(
                IncidentModel.status.in_(open_statuses),
                IncidentModel.risk.in_(["HIGH", "CRITICAL"])
            ).scalar() or 0
            
            high_critical = db.query(func.count(IncidentModel.id)).filter(
                IncidentModel.risk.in_(["HIGH", "CRITICAL"])
            ).scalar() or 0

            critical_threats = db.query(func.count(IncidentModel.id)).filter(
                IncidentModel.risk == "CRITICAL"
            ).scalar() or 0
            
            category_counts = db.query(
                IncidentModel.category, func.count(IncidentModel.id)
            ).group_by(IncidentModel.category).all()
            categories = {cat: count for cat, count in category_counts if cat}
            
            risk_counts = db.query(
                IncidentModel.risk, func.count(IncidentModel.id)
            ).group_by(IncidentModel.risk).all()
            severities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0}
            for risk, count in risk_counts:
                r_up = (risk or "").upper()
                if r_up in severities:
                    severities[r_up] = count
                elif r_up:
                    severities["LOW"] += count
            
            recent_models = db.query(IncidentModel).order_by(IncidentModel.last_seen.desc()).limit(10).all()
            recent_incidents = [self._incident_to_dict(self._model_to_incident(m, db=db)) for m in recent_models]
            
            return {
                "total_incidents": total_incidents,
                "open_incidents": open_incidents,
                "total_events_analyzed": total_events,
                "high_critical_threats": high_critical,
                "active_high_critical_threats": active_high_critical,
                "critical_threats": critical_threats,
                "categories": categories,
                "severities": severities,
                "recent_incidents": recent_incidents,
            }

    def get_activity_timeline(self, range_mode: str = "ALL") -> Dict[str, Any]:
        """Calculates aggregated chronological time-series buckets for the Threat Activity Timeline."""
        range_upper = (range_mode or "ALL").upper()
        now_ts = time.time()
        session_factory = get_session_factory(self.db_path)
        with session_factory() as db:
            from sqlalchemy import func
            
            now_dt = datetime.datetime.fromtimestamp(now_ts, datetime.timezone.utc)
            if range_upper == "1H":
                start_dt = now_dt - datetime.timedelta(hours=1)
                num_buckets = 12
                label_fmt = "%H:%M"
            elif range_upper == "6H":
                start_dt = now_dt - datetime.timedelta(hours=6)
                num_buckets = 12
                label_fmt = "%H:%M"
            elif range_upper == "24H":
                start_dt = now_dt - datetime.timedelta(hours=24)
                num_buckets = 12
                label_fmt = "%H:%M"
            elif range_upper == "7D":
                start_dt = now_dt - datetime.timedelta(days=7)
                num_buckets = 7
                label_fmt = "%a %d"
            else:  # ALL
                earliest = db.query(func.min(ThreatEventModel.timestamp)).scalar()
                if earliest:
                    start_dt = earliest.replace(tzinfo=datetime.timezone.utc) if earliest.tzinfo is None else earliest
                else:
                    start_dt = now_dt - datetime.timedelta(days=14)
                num_buckets = 14
                label_fmt = "%b %d"

            start_ts = start_dt.timestamp()
            span = max(now_ts - start_ts, 60.0)
            bucket_size = span / num_buckets

            q = db.query(ThreatEventModel.timestamp, ThreatEventModel.severity)
            if range_upper != "ALL":
                q = q.filter(ThreatEventModel.timestamp >= start_dt.replace(tzinfo=None))
            events = q.order_by(ThreatEventModel.timestamp.asc()).all()

            telemetry = [0] * num_buckets
            threats = [0] * num_buckets
            labels = []

            for i in range(num_buckets):
                b_start = start_ts + i * bucket_size
                b_end = b_start + bucket_size
                dt = datetime.datetime.fromtimestamp(b_start)
                labels.append(dt.strftime(label_fmt))

                for ev_time, sev in events:
                    if not ev_time:
                        continue
                    ev_ts = _to_utc_timestamp(ev_time)
                    if ev_ts is not None and (b_start <= ev_ts < b_end or (i == num_buckets - 1 and b_start <= ev_ts <= b_end + 2.0)):
                        telemetry[i] += 1
                        if (sev or "").upper() in ("HIGH", "CRITICAL"):
                            threats[i] += 1

            return {
                "range": range_upper,
                "labels": labels,
                "telemetry": telemetry,
                "threats": threats,
                "total_events": len(events),
                "total_threats": sum(threats)
            }

    def _save_event_to_db(self, event: ThreatEvent):
        """Persist ThreatEvent and its Evidence to SQLite."""
        session_factory = get_session_factory(self.db_path)
        with session_factory() as db:
            ts = datetime.datetime.fromtimestamp(event.timestamp, datetime.timezone.utc)
            
            ev_model = ThreatEventModel(
                event_id=event.event_id,
                timestamp=ts,
                source=event.source,
                source_type=event.source_type,
                modality=event.modality,
                threat_category=event.threat_category.value if hasattr(event.threat_category, "value") else str(event.threat_category),
                subcategory=event.subcategory,
                severity=event.severity.value if hasattr(event.severity, "value") else str(event.severity),
                confidence=event.confidence,
                classification=event.classification,
                explanation_summary=event.explanation.summary if event.explanation else None,
                explanation_reasoning=event.explanation.reasoning if event.explanation else None,
                explanation_limitations=event.explanation.limitations if event.explanation else None,
                recommended_actions_json=json.dumps(event.recommended_actions),
                incident_id=event.correlation_id,
                affected_user=event.affected_user,
                affected_asset=event.affected_asset,
                detector=event.detector,
                detector_version=event.detector_version,
                processing_time_ms=event.processing_time_ms,
                capability_status=event.capability_status,
                correlation_id=event.correlation_id,
                mitre_technique_id=event.mitre_technique_id,
                mitre_technique_name=event.mitre_technique_name
            )
            db.add(ev_model)
            
            for ev in event.evidence:
                ev_data = ThreatEvidenceModel(
                    event_id=event.event_id,
                    evidence_type=ev.evidence_type,
                    description=ev.description,
                    value=ev.value,
                    severity_contribution=ev.severity_contribution,
                    confidence=ev.confidence,
                    source=ev.source
                )
                db.add(ev_data)
                
            db.commit()

    def _save_incident_to_db(self, incident: Incident):
        """Persist Incident to SQLite."""
        session_factory = get_session_factory(self.db_path)
        with session_factory() as db:
            inc_model = db.query(IncidentModel).filter(IncidentModel.incident_id == incident.incident_id).first()
            last_ts = datetime.datetime.fromtimestamp(incident.last_seen, datetime.timezone.utc)
            
            cat_val = incident.category.value if hasattr(incident.category, "value") else str(incident.category)
            risk_val = incident.risk.value if hasattr(incident.risk, "value") else str(incident.risk)
            status_val = incident.status.value if hasattr(incident.status, "value") else str(incident.status)
            
            if inc_model:
                inc_model.last_seen = last_ts
                inc_model.category = cat_val
                inc_model.risk = risk_val
                inc_model.status = status_val
                inc_model.affected_assets_json = json.dumps(incident.affected_assets)
                inc_model.recommendations_json = json.dumps(incident.recommendations)
                inc_model.analyst_notes = incident.analyst_notes
            else:
                first_ts = datetime.datetime.fromtimestamp(incident.first_seen, datetime.timezone.utc)
                inc_model = IncidentModel(
                    incident_id=incident.incident_id,
                    first_seen=first_ts,
                    last_seen=last_ts,
                    category=cat_val,
                    risk=risk_val,
                    status=status_val,
                    affected_assets_json=json.dumps(incident.affected_assets),
                    recommendations_json=json.dumps(incident.recommendations),
                    analyst_notes=incident.analyst_notes
                )
                db.add(inc_model)
                
            db.commit()

    def _risk_level_to_int(self, level: Union[RiskLevel, str]) -> int:
        val = level.value if hasattr(level, "value") else str(level)
        order = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return order.get(val, 0)
        
    def _model_to_incident(self, m: IncidentModel, db=None) -> Incident:
        first_seen = _to_utc_timestamp(m.first_seen) or time.time()
        last_seen = _to_utc_timestamp(m.last_seen) or time.time()
        resolved_at = _to_utc_timestamp(m.resolved_at)

        inc = Incident(
            incident_id=m.incident_id,
            first_seen=first_seen,
            last_seen=last_seen,
            category=ThreatCategory(m.category) if m.category in [c.value for c in ThreatCategory] else ThreatCategory.UNKNOWN,
            risk=RiskLevel(m.risk) if m.risk in [r.value for r in RiskLevel] else RiskLevel.LOW,
            status=IncidentStatus(m.status) if m.status in [s.value for s in IncidentStatus] else IncidentStatus.NEW,
            analyst_notes=m.analyst_notes,
            resolved_at=resolved_at,
        )
        if m.affected_assets_json:
            try:
                inc.affected_assets = json.loads(m.affected_assets_json)
            except Exception:
                inc.affected_assets = []
        if m.recommendations_json:
            try:
                inc.recommendations = json.loads(m.recommendations_json)
            except Exception:
                inc.recommendations = []

        if db:
            event_models = db.query(ThreatEventModel).filter(ThreatEventModel.incident_id == m.incident_id).all()
            inc.event_count = len(event_models)
            inc.events = [self._model_to_threat_event(ev_m, db) for ev_m in event_models]
        return inc

    def _model_to_threat_event(self, m: ThreatEventModel, db=None) -> ThreatEvent:
        ts = _to_utc_timestamp(m.timestamp) or time.time()
        
        evidence_list = []
        if db:
            ev_rows = db.query(ThreatEvidenceModel).filter(ThreatEvidenceModel.event_id == m.event_id).all()
            for r in ev_rows:
                evidence_list.append(Evidence(
                    evidence_type=r.evidence_type,
                    description=r.description,
                    value=r.value,
                    severity_contribution=r.severity_contribution or 0.0,
                    confidence=r.confidence or 1.0,
                    source=r.source or "IncidentManager"
                ))

        actions = []
        if m.recommended_actions_json:
            try:
                actions = json.loads(m.recommended_actions_json)
            except Exception:
                actions = []

        return ThreatEvent(
            event_id=m.event_id,
            timestamp=ts,
            source=m.source,
            source_type=m.source_type,
            modality=m.modality,
            threat_category=ThreatCategory(m.threat_category) if m.threat_category in [c.value for c in ThreatCategory] else ThreatCategory.UNKNOWN,
            subcategory=m.subcategory,
            severity=RiskLevel(m.severity) if m.severity in [r.value for r in RiskLevel] else RiskLevel.SAFE,
            confidence=m.confidence or 0.0,
            classification=m.classification or "SAFE",
            evidence=evidence_list,
            explanation=Explanation(
                summary=m.explanation_summary or "",
                reasoning=m.explanation_reasoning or "",
                limitations=m.explanation_limitations
            ),
            recommended_actions=actions,
            affected_user=m.affected_user,
            affected_asset=m.affected_asset,
            detector=m.detector,
            detector_version=m.detector_version or "1.0",
            processing_time_ms=m.processing_time_ms or 0.0,
            capability_status=m.capability_status or "READY",
            correlation_id=m.correlation_id,
            mitre_technique_id=m.mitre_technique_id,
            mitre_technique_name=m.mitre_technique_name
        )

    def _incident_to_dict(self, inc: Incident) -> Dict[str, Any]:
        return {
            "incident_id": inc.incident_id,
            "first_seen": inc.first_seen,
            "last_seen": inc.last_seen,
            "category": inc.category.value if hasattr(inc.category, "value") else str(inc.category),
            "risk": inc.risk.value if hasattr(inc.risk, "value") else str(inc.risk),
            "status": inc.status.value if hasattr(inc.status, "value") else str(inc.status),
            "affected_assets": inc.affected_assets,
            "recommendations": inc.recommendations,
            "event_count": inc.event_count or len(inc.events),
            "analyst_notes": inc.analyst_notes,
            "resolved_at": inc.resolved_at
        }
