from fastapi import APIRouter, HTTPException, Path, Body
from typing import List, Dict, Any, Optional
from pydantic import BaseModel

from backend.config import get_settings
from backend.incidents.incident_manager import IncidentManager
from backend.threats.models import Incident, IncidentStatus, ThreatEvent
from backend.main import get_app_incident_manager

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])


class IncidentUpdateModel(BaseModel):
    status: IncidentStatus
    analyst_notes: Optional[str] = None


@router.get("/", response_model=List[Incident])
async def get_all_incidents(limit: int = 50):
    incident_manager = get_app_incident_manager()
    if not incident_manager:
        raise HTTPException(status_code=503, detail="Incident Management is disabled.")
    return incident_manager.get_all_incidents(limit=limit)


@router.get("/events", response_model=List[ThreatEvent])
async def get_recent_threat_events(limit: int = 50):
    incident_manager = get_app_incident_manager()
    if not incident_manager:
        return []
    return incident_manager.get_recent_threat_events(limit=limit)


@router.get("/dashboard/summary")
async def get_dashboard_summary():
    """Generates the CyberGuard dashboard summary."""
    incident_manager = get_app_incident_manager()
    if not incident_manager:
        return {
            "status": "disabled",
            "message": "Incident Management is disabled.",
            "total_incidents": 0,
            "open_incidents": 0,
            "total_events_analyzed": 0,
            "high_critical_threats": 0,
            "active_high_critical_threats": 0,
            "critical_threats": 0,
            "categories": {},
            "severities": {},
            "recent_incidents": [],
        }
    return incident_manager.get_dashboard_summary()


@router.get("/activity/timeline")
async def get_activity_timeline(range: str = "ALL"):
    """Fetches real chronological time-bucketed telemetry for the Threat Activity Timeline."""
    incident_manager = get_app_incident_manager()
    if not incident_manager:
        return {
            "range": range,
            "labels": [],
            "telemetry": [],
            "threats": [],
            "total_events": 0,
            "total_threats": 0
        }
    return incident_manager.get_activity_timeline(range_mode=range)



@router.get("/{incident_id}", response_model=Incident)
async def get_incident(incident_id: str = Path(...)):
    incident_manager = get_app_incident_manager()
    if not incident_manager:
        raise HTTPException(status_code=503, detail="Incident Management is disabled.")
        
    incident = incident_manager.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return incident


@router.put("/{incident_id}/status")
async def update_incident_status(
    incident_id: str = Path(...),
    update_data: IncidentUpdateModel = Body(...)
):
    incident_manager = get_app_incident_manager()
    if not incident_manager:
        raise HTTPException(status_code=503, detail="Incident Management is disabled.")
        
    success = incident_manager.update_incident_status(
        incident_id, 
        update_data.status, 
        update_data.analyst_notes
    )
    
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found or could not be updated.")
        
    return {"status": "success", "incident_id": incident_id, "new_status": update_data.status.value}
