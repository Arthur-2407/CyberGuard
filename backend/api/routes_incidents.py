from fastapi import APIRouter, Depends, HTTPException, Path, Body
from typing import List, Dict, Any, Optional
from pydantic import BaseModel

from backend.config import get_settings
from backend.incidents.incident_manager import IncidentManager, get_incident_manager_for_user
from backend.threats.models import Incident, IncidentStatus, ThreatEvent
from backend.storage.auth import require_user, get_optional_user
from backend.storage.database import UserModel

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])


class IncidentUpdateModel(BaseModel):
    status: IncidentStatus
    analyst_notes: Optional[str] = None


@router.get("/", response_model=List[Incident])
async def get_all_incidents(
    limit: int = 50,
    current_user: UserModel = Depends(require_user),
):
    """Retrieve incidents strictly scoped to caller's ownership boundary."""
    incident_manager = get_incident_manager_for_user(current_user)
    if not incident_manager:
        return []
    is_admin = getattr(current_user, "role", "").lower() in ["admin", "role_admin"]
    return incident_manager.get_all_incidents(limit=limit, user_id=current_user.id, is_admin=is_admin)


@router.get("/events", response_model=List[ThreatEvent])
async def get_recent_threat_events(
    limit: int = 50,
    current_user: UserModel = Depends(require_user),
):
    """Retrieve recent threat events strictly scoped to caller's ownership boundary."""
    incident_manager = get_incident_manager_for_user(current_user)
    if not incident_manager:
        return []
    is_admin = getattr(current_user, "role", "").lower() in ["admin", "role_admin"]
    return incident_manager.get_recent_threat_events(limit=limit, user_id=current_user.id, is_admin=is_admin)


@router.get("/dashboard/summary")
async def get_dashboard_summary(
    current_user: Optional[UserModel] = Depends(get_optional_user),
):
    """Generates the CyberGuard dashboard summary strictly aggregated within caller's authorized scope."""
    if current_user is None or not getattr(current_user, "is_active", False):
        return {
            "total_incidents": 0,
            "open_incidents": 0,
            "total_events_analyzed": 0,
            "high_critical_threats": 0,
            "active_high_critical_threats": 0,
            "critical_threats": 0,
            "categories": {},
            "severities": {},
            "recent_incidents": [],
            "requires_authentication": True,
        }
    incident_manager = get_incident_manager_for_user(current_user)
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
    is_admin = getattr(current_user, "role", "").lower() in ["admin", "role_admin"]
    return incident_manager.get_dashboard_summary(user_id=current_user.id, is_admin=is_admin)


@router.get("/activity/timeline")
async def get_activity_timeline(
    range: str = "ALL",
    current_user: Optional[UserModel] = Depends(get_optional_user),
):
    """Fetches real chronological time-bucketed telemetry strictly within caller's authorized scope."""
    if current_user is None or not getattr(current_user, "is_active", False):
        return {
            "range": range,
            "labels": [],
            "telemetry": [],
            "threats": [],
            "total_events": 0,
            "total_threats": 0,
            "requires_authentication": True,
        }
    incident_manager = get_incident_manager_for_user(current_user)
    if not incident_manager:
        return {
            "range": range,
            "labels": [],
            "telemetry": [],
            "threats": [],
            "total_events": 0,
            "total_threats": 0
        }
    is_admin = getattr(current_user, "role", "").lower() in ["admin", "role_admin"]
    return incident_manager.get_activity_timeline(range_mode=range, user_id=current_user.id, is_admin=is_admin)


@router.get("/{incident_id}", response_model=Incident)
async def get_incident(
    incident_id: str = Path(...),
    current_user: UserModel = Depends(require_user),
):
    """Retrieve incident details with ownership boundary validation."""
    incident_manager = get_incident_manager_for_user(current_user)
    if not incident_manager:
        raise HTTPException(status_code=503, detail="Incident Management is disabled.")
        
    is_admin = getattr(current_user, "role", "").lower() in ["admin", "role_admin"]
    incident = incident_manager.get_incident(incident_id, user_id=current_user.id, is_admin=is_admin)
    if not incident and is_admin:
        from backend.main import get_app_incident_manager
        app_mgr = get_app_incident_manager()
        if app_mgr and app_mgr != incident_manager:
            incident = app_mgr.get_incident(incident_id, user_id=current_user.id, is_admin=is_admin)

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return incident


@router.put("/{incident_id}/status")
async def update_incident_status(
    incident_id: str = Path(...),
    update_data: IncidentUpdateModel = Body(...),
    current_user: UserModel = Depends(require_user),
):
    """Updates status and analyst notes with ownership boundary validation."""
    incident_manager = get_incident_manager_for_user(current_user)
    if not incident_manager:
        raise HTTPException(status_code=503, detail="Incident Management is disabled.")
        
    is_admin = getattr(current_user, "role", "").lower() in ["admin", "role_admin"]
    success = incident_manager.update_incident_status(
        incident_id, 
        update_data.status, 
        update_data.analyst_notes,
        user_id=current_user.id,
        is_admin=is_admin
    )
    if not success and is_admin:
        from backend.main import get_app_incident_manager
        app_mgr = get_app_incident_manager()
        if app_mgr and app_mgr != incident_manager:
            success = app_mgr.update_incident_status(
                incident_id,
                update_data.status,
                update_data.analyst_notes,
                user_id=current_user.id,
                is_admin=is_admin
            )
    
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found or could not be updated.")
        
    return {"status": "success", "incident_id": incident_id, "new_status": update_data.status.value}


@router.post("/containment/emergency")
async def emergency_contain_threats(
    current_user: UserModel = Depends(require_user),
):
    """Emergency quarantine protocol in caller's isolated boundary."""
    incident_manager = get_incident_manager_for_user(current_user)
    if not incident_manager:
        raise HTTPException(status_code=503, detail="Incident Management is disabled.")
    is_admin = getattr(current_user, "role", "").lower() in ["admin", "role_admin"]
    count = incident_manager.emergency_contain_active_incidents(
        notes=f"Emergency Containment protocol triggered by {current_user.username}",
        user_id=current_user.id,
        is_admin=is_admin
    )
    return {"status": "success", "contained_count": count}
