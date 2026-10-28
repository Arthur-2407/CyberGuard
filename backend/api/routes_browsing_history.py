"""
routes_browsing_history.py — User-Specific Browsing History & Domain Intelligence REST API.

Key Guarantees:
  1. Strict Multi-User Isolation: User X cannot view, mutate, or purge User Y's history.
     Server-side ownership is enforced via authenticated UserModel session; client user_id is never trusted.
  2. Truthful Observation Context: Explicit disclosures that records reflect on-device
     DNS resolution queries, not confirmed interactive webpage visits.
  3. Safe Public Web Enrichment: SSRF protections prevent queries to private/metadata IPs.
  4. Grounded LLM Analysis: Verified technical citations with prompt-injection defense.
"""

from __future__ import annotations

import datetime
import json
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.storage.auth import require_user
from backend.storage.database import BrowsingHistoryModel, UserModel, get_db_session
from backend.threats.domain_intelligence import (
    enrich_domain_comprehensive,
    generate_grounded_domain_llm_report,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/browsing-history", tags=["Browsing History & DNS Forensics"])


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


# ── Pydantic Request / Response Schemas ──

class HistoryItemIn(BaseModel):
    domain: str = Field(..., min_length=1, max_length=256)
    action: str = Field(default="ALLOWED")
    block_reason: Optional[str] = None
    resolved_ips: Optional[List[str]] = Field(default_factory=list)
    timestamp: Optional[str] = None


class BatchSyncRequest(BaseModel):
    observations: List[HistoryItemIn] = Field(..., max_length=500)


class HistoryItemResponse(BaseModel):
    id: int
    user_id: int
    domain: str
    action: str
    block_reason: Optional[str]
    query_count: int
    resolved_ips: List[str]
    first_seen: str
    last_seen: str
    has_enrichment: bool
    has_llm_report: bool


class HistorySummaryResponse(BaseModel):
    items: List[HistoryItemResponse]
    total_count: int
    stats: Dict[str, int]
    disclosure: str


@router.get("", response_model=HistorySummaryResponse)
async def list_user_browsing_history(
    search: Optional[str] = Query(None, description="Domain substring search query"),
    action: Optional[str] = Query(None, description="Filter by action: ALLOWED or BLOCKED"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: UserModel = Depends(require_user),
    db: Session = Depends(get_db_session),
):
    """
    Retrieves the authenticated user's DNS-observed browsing history.
    Strict tenant boundary: records are filtered strictly by current_user.id.
    """
    if db is None:
        return HistorySummaryResponse(
            items=[],
            total_count=0,
            stats={"total_domains": 0, "allowed_count": 0, "blocked_count": 0},
            disclosure="Database unavailable.",
        )

    query = db.query(BrowsingHistoryModel).filter(BrowsingHistoryModel.user_id == current_user.id)

    if action and action.upper() in ("ALLOWED", "BLOCKED"):
        query = query.filter(BrowsingHistoryModel.action == action.upper())

    if search and search.strip():
        term = f"%{search.strip().lower()}%"
        query = query.filter(BrowsingHistoryModel.domain.like(term))

    total_count = query.count()
    rows = (
        query.order_by(BrowsingHistoryModel.last_seen.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    # Compute user-specific summary metrics
    total_domains = db.query(BrowsingHistoryModel).filter(BrowsingHistoryModel.user_id == current_user.id).count()
    allowed_count = (
        db.query(BrowsingHistoryModel)
        .filter(BrowsingHistoryModel.user_id == current_user.id, BrowsingHistoryModel.action == "ALLOWED")
        .count()
    )
    blocked_count = (
        db.query(BrowsingHistoryModel)
        .filter(BrowsingHistoryModel.user_id == current_user.id, BrowsingHistoryModel.action == "BLOCKED")
        .count()
    )

    items = []
    for r in rows:
        ips = []
        if r.resolved_ips_json:
            try:
                ips = json.loads(r.resolved_ips_json)
            except Exception:
                ips = []
        items.append(
            HistoryItemResponse(
                id=r.id,
                user_id=r.user_id,
                domain=r.domain,
                action=r.action,
                block_reason=r.block_reason,
                query_count=r.query_count,
                resolved_ips=ips if isinstance(ips, list) else [],
                first_seen=r.first_seen.isoformat() if r.first_seen else "",
                last_seen=r.last_seen.isoformat() if r.last_seen else "",
                has_enrichment=bool(r.enrichment_json),
                has_llm_report=bool(r.llm_report_json),
            )
        )

    return HistorySummaryResponse(
        items=items,
        total_count=total_count,
        stats={
            "total_domains": total_domains,
            "allowed_count": allowed_count,
            "blocked_count": blocked_count,
        },
        disclosure=(
            "CyberGuard DNS Forensics: Entries reflect on-device DNS resolution queries. "
            "A logged query confirms domain name resolution, but does not prove interactive "
            "user navigation, webpage visitation, or click activity."
        ),
    )


@router.post("/sync")
async def sync_browsing_history(
    payload: BatchSyncRequest,
    current_user: UserModel = Depends(require_user),
    db: Session = Depends(get_db_session),
):
    """
    Ingests batch DNS query observations from Android or client endpoints.
    Enforces current_user.id on all inserted/updated records.
    """
    if db is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database offline.")

    synced_count = 0
    now = _utcnow()

    for obs in payload.observations:
        clean_domain = obs.domain.strip().lower().rstrip(".")
        if not clean_domain:
            continue

        action_clean = "BLOCKED" if obs.action.upper() == "BLOCKED" else "ALLOWED"
        ips_json = json.dumps(obs.resolved_ips or [])

        # Parse client timestamp if valid, else default to now
        obs_time = now
        if obs.timestamp:
            try:
                obs_time = datetime.datetime.fromisoformat(obs.timestamp.replace("Z", "+00:00"))
            except Exception:
                obs_time = now

        # Upsert by (user_id, domain)
        existing = (
            db.query(BrowsingHistoryModel)
            .filter(
                BrowsingHistoryModel.user_id == current_user.id,
                BrowsingHistoryModel.domain == clean_domain,
            )
            .first()
        )

        if existing:
            existing.query_count += 1
            existing.last_seen = obs_time
            if action_clean == "BLOCKED":
                existing.action = "BLOCKED"
                if obs.block_reason:
                    existing.block_reason = obs.block_reason
            if obs.resolved_ips:
                try:
                    curr_ips = json.loads(existing.resolved_ips_json or "[]")
                    merged = list(dict.fromkeys(curr_ips + obs.resolved_ips))
                    existing.resolved_ips_json = json.dumps(merged)
                except Exception:
                    existing.resolved_ips_json = ips_json
            existing.updated_at = now
        else:
            new_entry = BrowsingHistoryModel(
                user_id=current_user.id,
                domain=clean_domain,
                action=action_clean,
                block_reason=obs.block_reason,
                query_count=1,
                resolved_ips_json=ips_json,
                first_seen=obs_time,
                last_seen=obs_time,
                created_at=now,
                updated_at=now,
            )
            db.add(new_entry)
        synced_count += 1

    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to commit synced browsing history: {e}")
        raise HTTPException(status_code=500, detail="Database commit failure during sync.")

    return {"status": "SYNCED", "synced_count": synced_count, "user_id": current_user.id}


@router.get("/{domain}")
async def get_domain_history_detail(
    domain: str,
    current_user: UserModel = Depends(require_user),
    db: Session = Depends(get_db_session),
):
    """
    Returns specific domain history entry and cached intelligence for authenticated user.
    """
    if db is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database offline.")

    clean_domain = domain.strip().lower().rstrip(".")
    entry = (
        db.query(BrowsingHistoryModel)
        .filter(
            BrowsingHistoryModel.user_id == current_user.id,
            BrowsingHistoryModel.domain == clean_domain,
        )
        .first()
    )

    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain '{clean_domain}' not found in user history.",
        )

    enrichment = None
    if entry.enrichment_json:
        try:
            enrichment = json.loads(entry.enrichment_json)
        except Exception:
            pass

    llm_report = None
    if entry.llm_report_json:
        try:
            llm_report = json.loads(entry.llm_report_json)
        except Exception:
            pass

    ips = []
    if entry.resolved_ips_json:
        try:
            ips = json.loads(entry.resolved_ips_json)
        except Exception:
            pass

    return {
        "id": entry.id,
        "user_id": entry.user_id,
        "domain": entry.domain,
        "action": entry.action,
        "block_reason": entry.block_reason,
        "query_count": entry.query_count,
        "resolved_ips": ips,
        "first_seen": entry.first_seen.isoformat() if entry.first_seen else "",
        "last_seen": entry.last_seen.isoformat() if entry.last_seen else "",
        "enrichment": enrichment,
        "enrichment_updated_at": entry.enrichment_updated_at.isoformat() if entry.enrichment_updated_at else None,
        "llm_report": llm_report,
        "llm_report_updated_at": entry.llm_report_updated_at.isoformat() if entry.llm_report_updated_at else None,
    }


@router.post("/{domain}/enrich")
async def trigger_domain_enrichment(
    domain: str,
    force_refresh: bool = Query(False),
    current_user: UserModel = Depends(require_user),
    db: Session = Depends(get_db_session),
):
    """
    Performs comprehensive technical enrichment (DNS, RDAP, TLS, safe HTTP, ThreatIntel)
    under strict SSRF defenses. Caches results into the user's domain record.
    """
    clean_domain = domain.strip().lower().rstrip(".")
    entry = None
    if db:
        entry = (
            db.query(BrowsingHistoryModel)
            .filter(
                BrowsingHistoryModel.user_id == current_user.id,
                BrowsingHistoryModel.domain == clean_domain,
            )
            .first()
        )

    # Perform enrichment
    intel = await enrich_domain_comprehensive(clean_domain, force_refresh=force_refresh)

    if entry and db:
        entry.enrichment_json = json.dumps(intel)
        entry.enrichment_updated_at = _utcnow()
        try:
            db.commit()
        except Exception as e:
            db.rollback()
            logger.warning(f"Failed to persist domain enrichment cache: {e}")

    return {
        "status": "ENRICHED",
        "domain": clean_domain,
        "enrichment": intel,
    }


@router.post("/{domain}/llm-report")
async def trigger_domain_llm_report(
    domain: str,
    force_refresh: bool = Query(False),
    current_user: UserModel = Depends(require_user),
    db: Session = Depends(get_db_session),
):
    """
    Generates a grounded LLM domain assessment report with citations.
    Integrates verified technical facts while protecting against prompt injection.
    """
    clean_domain = domain.strip().lower().rstrip(".")
    entry = None
    existing_intel = None

    if db:
        entry = (
            db.query(BrowsingHistoryModel)
            .filter(
                BrowsingHistoryModel.user_id == current_user.id,
                BrowsingHistoryModel.domain == clean_domain,
            )
            .first()
        )
        if entry and entry.enrichment_json and not force_refresh:
            try:
                existing_intel = json.loads(entry.enrichment_json)
            except Exception:
                pass

    if not existing_intel:
        existing_intel = await enrich_domain_comprehensive(clean_domain, force_refresh=force_refresh)
        if entry and db:
            entry.enrichment_json = json.dumps(existing_intel)
            entry.enrichment_updated_at = _utcnow()

    # Generate grounded report
    report = generate_grounded_domain_llm_report(clean_domain, existing_intel)

    if entry and db:
        entry.llm_report_json = json.dumps(report)
        entry.llm_report_updated_at = _utcnow()
        try:
            db.commit()
        except Exception as e:
            db.rollback()
            logger.warning(f"Failed to persist LLM report cache: {e}")

    return {
        "status": "GENERATED",
        "domain": clean_domain,
        "report": report,
    }


@router.delete("")
async def clear_all_browsing_history(
    current_user: UserModel = Depends(require_user),
    db: Session = Depends(get_db_session),
):
    """
    Purges all browsing history entries belonging exclusively to the authenticated user.
    Never alters other users' records.
    """
    if db is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database offline.")

    deleted = (
        db.query(BrowsingHistoryModel)
        .filter(BrowsingHistoryModel.user_id == current_user.id)
        .delete(synchronize_session=False)
    )

    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to commit history purge: {e}")
        raise HTTPException(status_code=500, detail="Database purge error.")

    return {"status": "CLEARED", "deleted_count": deleted, "user_id": current_user.id}


@router.delete("/{item_id}")
async def delete_history_item(
    item_id: int,
    current_user: UserModel = Depends(require_user),
    db: Session = Depends(get_db_session),
):
    """
    Deletes a specific history record, strictly enforcing ownership by current_user.id.
    """
    if db is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database offline.")

    entry = (
        db.query(BrowsingHistoryModel)
        .filter(
            BrowsingHistoryModel.id == item_id,
            BrowsingHistoryModel.user_id == current_user.id,
        )
        .first()
    )

    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="History entry not found or does not belong to the current user.",
        )

    db.delete(entry)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to delete history item: {e}")
        raise HTTPException(status_code=500, detail="Database deletion error.")

    return {"status": "DELETED", "item_id": item_id}
