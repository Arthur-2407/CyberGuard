"""
websocket_notifier.py — Real-time WebSocket alert push for CyberGuard.

Manages connected WebSocket clients and delivers detection updates
to the specific session or authorized user — NOT to all clients.

Zero-Trust Isolation design:
  - Each WebSocket connection is registered with its session_id, user_id, and role on connect().
  - notify() delivers session risk updates only to the originating session.
  - notify_threat_event() delivers threat telemetry only to the owning user or administrators.
  - notify_incident_event() delivers incident updates only to the owning user or administrators.
  - notify_alert_event() delivers alerts only to the owning session, owning user, or administrators.
  - broadcast_raw() remains strictly available for system-wide notices (health, shutdown).
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional, Set

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class WebSocketNotifier:
    """
    Manages active WebSocket connections with strict user- and session-level routing.

    Alerts and threat telemetry are delivered ONLY to the owning session or user,
    preventing cross-session and cross-user data leakage when multiple clients are connected.
    """

    def __init__(self):
        # ws → session_id mapping (one-to-one)
        self._ws_to_session: Dict[WebSocket, str] = {}
        # session_id → ws mapping (for fast lookup by session)
        self._session_to_ws: Dict[str, WebSocket] = {}
        # ws → metadata dictionary (session_id, user_id, role)
        self._ws_metadata: Dict[WebSocket, Dict[str, Any]] = {}

    async def connect(
        self,
        websocket: WebSocket,
        session_id: str,
        user_id: Optional[int] = None,
        role: Optional[str] = "user"
    ) -> None:
        """
        Accept and register a new WebSocket connection bound to session_id and user identity.

        Args:
            websocket:  the incoming WebSocket connection
            session_id: the unique session identifier for this connection
            user_id:    the authenticated user ID, or None if guest
            role:       the user role ('admin', 'user', 'guest')
        """
        await websocket.accept()
        self._ws_to_session[websocket] = session_id
        self._session_to_ws[session_id] = websocket
        self._ws_metadata[websocket] = {
            "session_id": session_id,
            "user_id": user_id,
            "role": (role or "user").lower(),
        }
        logger.info(
            f"WebSocket client connected (session={session_id}, user_id={user_id}, role={role}). "
            f"Total: {len(self._ws_to_session)}"
        )

    async def disconnect(self, websocket: WebSocket) -> None:
        """Deregister a WebSocket connection and its session/metadata mappings."""
        session_id = self._ws_to_session.pop(websocket, None)
        if session_id is not None:
            self._session_to_ws.pop(session_id, None)
        self._ws_metadata.pop(websocket, None)
        logger.info(
            f"WebSocket client disconnected (session={session_id}). "
            f"Total: {len(self._ws_to_session)}"
        )

    async def notify(self, event) -> None:
        """
        Deliver an alert event only to the WebSocket that owns event.session_id.

        This replaces the old broadcast-to-all design. Each client receives
        only its own session's risk updates, preventing cross-session leakage.
        """
        session_id = getattr(event, "session_id", None)
        if not session_id:
            logger.warning("notify() called with event missing session_id — skipping.")
            return

        ws = self._session_to_ws.get(session_id)
        if ws is None:
            # Session's WebSocket already disconnected; nothing to do.
            return

        voice_cls = getattr(event, "voice_classification", None)
        if not voice_cls:
            voice_cls = "CLONED_VOICE" if event.risk_score >= 0.60 else "GENUINE_VOICE"

        active_det = getattr(event, "active_detector", None)
        if not active_det:
            try:
                from backend.services.continuous_learning import ContinuousLearningService
                active_det = ContinuousLearningService.get_active_model_version()
            except Exception:
                active_det = "v025"

        payload = json.dumps({
            "type": "risk_update",
            "session_id": event.session_id,
            "chunk_id": event.chunk_id,
            "timestamp": event.timestamp,
            "risk_score": event.risk_score,
            "alert_level": event.alert_level,
            "detection_score": event.detection_score,
            "voice_classification": voice_cls,
            "active_detector": active_det,
            "rms": getattr(event, "rms", None),
            "speaker_id": event.speaker_id,
            "speaker_similarity": event.speaker_similarity,
            "recommendation": event.recommendation,
        })

        try:
            await ws.send_text(payload)
        except Exception as exc:
            logger.debug(f"Failed to send to session {session_id}: {exc}. Removing stale connection.")
            await self.disconnect(ws)

    async def notify_threat_event(self, event) -> None:
        """
        Deliver threat event ONLY to the owning user and administrators.
        Guarantees zero-trust data isolation across users.
        """
        target_user_id = getattr(event, "user_id", None)
        event_dict = event.model_dump() if hasattr(event, "model_dump") else (event.dict() if hasattr(event, "dict") else dict(event))
        payload = json.dumps({
            "type": "threat_event",
            "event": event_dict
        })
        dead: Set[WebSocket] = set()
        for ws, meta in list(self._ws_metadata.items()):
            conn_user_id = meta.get("user_id")
            conn_role = meta.get("role", "user")
            is_admin = conn_role in ("admin", "role_admin")

            should_deliver = False
            if is_admin:
                should_deliver = True
            elif target_user_id is not None and conn_user_id == target_user_id:
                should_deliver = True

            if should_deliver:
                try:
                    await ws.send_text(payload)
                except Exception:
                    dead.add(ws)

        for ws in dead:
            await self.disconnect(ws)

    async def notify_incident_event(self, message: dict, user_id: Optional[int] = None) -> None:
        """
        Deliver incident update ONLY to the owning user and administrators.
        """
        target_uid = user_id
        if target_uid is None and isinstance(message, dict):
            target_uid = message.get("user_id")
            if target_uid is None and isinstance(message.get("incident"), dict):
                target_uid = message["incident"].get("user_id")

        payload = json.dumps(message)
        dead: Set[WebSocket] = set()
        for ws, meta in list(self._ws_metadata.items()):
            conn_user_id = meta.get("user_id")
            conn_role = meta.get("role", "user")
            is_admin = conn_role in ("admin", "role_admin")

            should_deliver = False
            if is_admin:
                should_deliver = True
            elif target_uid is not None and conn_user_id == target_uid:
                should_deliver = True

            if should_deliver:
                try:
                    await ws.send_text(payload)
                except Exception:
                    dead.add(ws)

        for ws in dead:
            await self.disconnect(ws)

    async def notify_alert_event(
        self,
        alert_payload: dict,
        session_id: Optional[str] = None,
        user_id: Optional[int] = None
    ) -> None:
        """
        Deliver security alert event strictly to the owning session, owning user, or administrators.
        """
        payload = json.dumps(alert_payload)
        dead: Set[WebSocket] = set()
        for ws, meta in list(self._ws_metadata.items()):
            conn_sid = meta.get("session_id")
            conn_user_id = meta.get("user_id")
            conn_role = meta.get("role", "user")
            is_admin = conn_role in ("admin", "role_admin")

            should_deliver = False
            if is_admin:
                should_deliver = True
            elif session_id and conn_sid == session_id:
                should_deliver = True
            elif user_id is not None and conn_user_id == user_id:
                should_deliver = True

            if should_deliver:
                try:
                    await ws.send_text(payload)
                except Exception:
                    dead.add(ws)

        for ws in dead:
            await self.disconnect(ws)

    async def broadcast_raw(self, message: dict) -> None:
        """
        Send an arbitrary JSON message to ALL connected clients.
        Use only for system-wide messages (health pings, server shutdowns, etc.).
        Do NOT use for session-specific or user-private data.
        """
        payload = json.dumps(message)
        dead: Set[WebSocket] = set()
        for ws in list(self._ws_to_session.keys()):
            try:
                await ws.send_text(payload)
            except Exception:
                dead.add(ws)
        for ws in dead:
            await self.disconnect(ws)

    @property
    def connection_count(self) -> int:
        return len(self._ws_to_session)
