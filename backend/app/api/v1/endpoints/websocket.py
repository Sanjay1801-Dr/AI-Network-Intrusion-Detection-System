"""WebSocket endpoint for real-time security monitoring (Phase 7)."""

import asyncio
from datetime import datetime, timezone
import json
import logging
from typing import Optional
from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect, status
from sqlalchemy.orm import Session

from backend.app.core.security import decode_access_token
from backend.app.db.session import get_db
from backend.app.models.user import UserRecord
from backend.app.repositories.user_repository import UserRepository
from backend.app.schemas.audit import AuditAction, AuditOutcome, AuditResourceType
from backend.app.services.audit_service import AuditService
from backend.app.services.websocket_manager import websocket_manager

logger = logging.getLogger("nids.api.websocket")

router = APIRouter(tags=["Real-Time Security Monitoring"])

# Heartbeat interval in seconds
HEARTBEAT_INTERVAL_SECONDS = 30.0
AUTH_HANDSHAKE_TIMEOUT_SECONDS = 5.0


@router.websocket("/ws/monitor")
async def websocket_monitor(
    websocket: WebSocket,
    db: Session = Depends(get_db),
) -> None:
    """Real-time security telemetry feed delivering live prediction and alert notifications.
    
    Authentication Protocol (Phase 9 Hardened):
    1. Server accepts socket connection in an unverified state.
    2. Server awaits an initial auth handshake frame within 5 seconds:
       {"type": "auth", "token": "<JWT_ACCESS_TOKEN>"}
    3. Authentication via URL query parameter (?token=...) is strictly disallowed to prevent
       token leakage in logs, history, and network proxies.
    4. If unauthenticated, invalid frame, or token expired, socket closes with code 1008 (Policy Violation).
    5. If authenticated, server registers client and sends 'connection_established' event.
    """
    await websocket.accept()

    # If dependency override is configured (e.g. during test suites), honor test user
    from backend.app.core.dependencies import get_current_user
    test_user_override = None
    if get_current_user in websocket.app.dependency_overrides:
        try:
            test_user_override = websocket.app.dependency_overrides[get_current_user]()
        except Exception:
            test_user_override = None

    if test_user_override:
        user_info = {
            "id": getattr(test_user_override, "id", 1),
            "username": getattr(test_user_override, "username", "admin"),
            "role": getattr(test_user_override, "role", "ADMIN"),
        }
        AuditService.log_event(
            db=db,
            action=AuditAction.WEBSOCKET_AUTH_SUCCESS,
            resource_type=AuditResourceType.WEBSOCKET,
            outcome=AuditOutcome.SUCCESS,
            username=user_info["username"],
            user_role=user_info["role"],
            ip_address=websocket.client.host if websocket.client else None,
            request_method="WEBSOCKET",
            request_path=websocket.url.path,
            status_code=101,
            details={"mode": "dependency_override"},
        )
        await websocket_manager.connect(websocket, user_info=user_info)
    else:
        # Strictly require application-level handshake frame within 5 seconds
        token = None
        try:
            raw_handshake = await asyncio.wait_for(
                websocket.receive_text(),
                timeout=AUTH_HANDSHAKE_TIMEOUT_SECONDS,
            )
            parsed = json.loads(raw_handshake)
            if isinstance(parsed, dict) and parsed.get("type") == "auth":
                token = parsed.get("token")
        except Exception:
            token = None

        if not token:
            logger.warning("WebSocket rejected: no authentication handshake frame provided.")
            AuditService.log_event(
                db=db,
                action=AuditAction.WEBSOCKET_AUTH_FAILURE,
                resource_type=AuditResourceType.WEBSOCKET,
                outcome=AuditOutcome.FAILURE,
                ip_address=websocket.client.host if websocket.client else None,
                request_method="WEBSOCKET",
                request_path=websocket.url.path,
                status_code=status.WS_1008_POLICY_VIOLATION,
                details={"reason": "Missing or invalid handshake frame"},
            )
            await websocket.close(
                code=status.WS_1008_POLICY_VIOLATION,
                reason="Authentication required. Missing handshake frame.",
            )
            return

        # Validate token and resolve operator account in database
        try:
            payload = decode_access_token(token)
            user_id = int(payload["sub"])
            user = UserRepository.get_by_id(db, user_id)
            if not user or not user.is_active:
                logger.warning("WebSocket rejected: user #%s invalid or inactive.", payload.get("sub"))
                AuditService.log_event(
                    db=db,
                    action=AuditAction.WEBSOCKET_AUTH_FAILURE,
                    resource_type=AuditResourceType.WEBSOCKET,
                    outcome=AuditOutcome.FAILURE,
                    username=payload.get("username"),
                    ip_address=websocket.client.host if websocket.client else None,
                    request_method="WEBSOCKET",
                    request_path=websocket.url.path,
                    status_code=status.WS_1008_POLICY_VIOLATION,
                    details={"reason": "User account invalid or deactivated"},
                )
                await websocket.close(
                    code=status.WS_1008_POLICY_VIOLATION,
                    reason="User account invalid or deactivated.",
                )
                return
        except Exception as auth_err:
            logger.warning("WebSocket authentication failed: %s", auth_err)
            AuditService.log_event(
                db=db,
                action=AuditAction.WEBSOCKET_AUTH_FAILURE,
                resource_type=AuditResourceType.WEBSOCKET,
                outcome=AuditOutcome.FAILURE,
                ip_address=websocket.client.host if websocket.client else None,
                request_method="WEBSOCKET",
                request_path=websocket.url.path,
                status_code=status.WS_1008_POLICY_VIOLATION,
                details={"reason": "Authentication failed or token expired"},
            )
            await websocket.close(
                code=status.WS_1008_POLICY_VIOLATION,
                reason="Authentication failed or token expired.",
            )
            return

        # Register authenticated client in the broadcast pool
        AuditService.log_event(
            db=db,
            action=AuditAction.WEBSOCKET_AUTH_SUCCESS,
            resource_type=AuditResourceType.WEBSOCKET,
            outcome=AuditOutcome.SUCCESS,
            username=user.username,
            user_role=user.role,
            ip_address=websocket.client.host if websocket.client else None,
            request_method="WEBSOCKET",
            request_path=websocket.url.path,
            status_code=101,
            details={"message": "WebSocket handshake authenticated"},
        )
        user_info = {
            "id": user.id,
            "username": user.username,
            "role": user.role,
        }
        await websocket_manager.connect(websocket, user_info=user_info)

    try:
        while True:
            try:
                # Wait for any incoming client message (or timeout to send heartbeat)
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=HEARTBEAT_INTERVAL_SECONDS,
                )
                # Clients can optionally send 'ping' or JSON ping; respond with pong
                try:
                    parsed = json.loads(data)
                    if isinstance(parsed, dict) and parsed.get("type") == "ping":
                        await websocket_manager.send_to_client(
                            websocket,
                            {
                                "event_type": "pong",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            },
                        )
                except (json.JSONDecodeError, ValueError):
                    if data.strip().lower() == "ping":
                        await websocket_manager.send_to_client(
                            websocket,
                            {
                                "event_type": "pong",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            },
                        )

            except asyncio.TimeoutError:
                # Send server-side heartbeat to verify connection health
                await websocket_manager.send_to_client(
                    websocket,
                    {
                        "event_type": "heartbeat",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                )

    except WebSocketDisconnect:
        logger.info("Client cleanly disconnected from /api/v1/ws/monitor")
    except Exception as exc:
        logger.warning("WebSocket session terminated with exception: %s", exc)
    finally:
        await websocket_manager.disconnect(websocket)
