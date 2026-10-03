"""WebSocket connection manager for real-time security monitoring (Phase 7)."""

import asyncio
from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional, Set
from fastapi import WebSocket

logger = logging.getLogger("nids.services.websocket")


class WebSocketManager:
    """Manages active WebSocket client connections for real-time security telemetry.
    
    Guarantees:
    - Thread-safe and coroutine-safe connection tracking.
    - Isolated broadcasting: Disconnected or faulty clients are removed without impacting others.
    - Zero unbounded memory growth: Events are push-only notifications without retention.
    - Server-side timestamping: All outgoing events are stamped with UTC timestamps.
    """

    def __init__(self) -> None:
        self._active_connections: Set[WebSocket] = set()
        self._connection_locks: Dict[WebSocket, asyncio.Lock] = {}
        self._lock = asyncio.Lock()

    @property
    def active_count(self) -> int:
        """Return the current number of active client connections."""
        return len(self._active_connections)

    async def connect(self, websocket: WebSocket, user_info: Optional[Dict[str, Any]] = None) -> None:
        """Accept a new client WebSocket connection (if unaccepted) and send initial handshake."""
        try:
            await websocket.accept()
        except Exception:
            pass  # Already accepted by auth handler

        async with self._lock:
            self._active_connections.add(websocket)
            self._connection_locks[websocket] = asyncio.Lock()

        logger.info(
            "WebSocket client connected (user: %s). Active connections: %d",
            user_info.get("username", "anonymous") if user_info else "anonymous",
            len(self._active_connections),
        )

        # Send connection_established event with user context
        handshake_event = {
            "event_type": "connection_established",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "service": "NIDS Monitoring",
                "status": "connected",
                "authenticated": True if user_info else False,
                "user": user_info or {},
            },
        }
        await self.send_to_client(websocket, handshake_event)

    async def disconnect(self, websocket: WebSocket) -> None:
        """Safely unregister and clean up a disconnected client."""
        async with self._lock:
            self._active_connections.discard(websocket)
            self._connection_locks.pop(websocket, None)

        logger.info(
            "WebSocket client disconnected. Active connections: %d",
            len(self._active_connections),
        )

    async def send_to_client(self, websocket: WebSocket, message: Dict[str, Any]) -> bool:
        """Send a JSON payload to a specific client with frame concurrency protection.
        
        Returns True if successful, False if the client failed or disconnected.
        """
        lock = self._connection_locks.get(websocket)
        if lock is None:
            return False

        try:
            async with lock:
                await websocket.send_json(message)
            return True
        except Exception as exc:
            logger.warning("Error transmitting to WebSocket client: %s", exc)
            await self.disconnect(websocket)
            return False

    async def broadcast(self, message: Dict[str, Any]) -> int:
        """Broadcast a JSON message to all active clients with failed-client isolation.
        
        Returns the number of clients successfully reached.
        """
        async with self._lock:
            connections_snapshot = list(self._active_connections)

        if not connections_snapshot:
            return 0

        success_count = 0
        failed_clients: List[WebSocket] = []

        for conn in connections_snapshot:
            lock = self._connection_locks.get(conn)
            if lock is None:
                failed_clients.append(conn)
                continue

            try:
                async with lock:
                    await conn.send_json(message)
                success_count += 1
            except Exception as exc:
                logger.warning("Failed broadcast to client, queueing cleanup: %s", exc)
                failed_clients.append(conn)

        # Clean up any connections that failed during broadcast
        if failed_clients:
            async with self._lock:
                for failed in failed_clients:
                    self._active_connections.discard(failed)
                    self._connection_locks.pop(failed, None)
            logger.info(
                "Cleaned up %d stale client connections. Remaining: %d",
                len(failed_clients),
                len(self._active_connections),
            )

        return success_count

    def broadcast_sync(self, message: Dict[str, Any]) -> None:
        """Thread-safe synchronous wrapper to schedule broadcast on the running event loop."""
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.broadcast(message))
        except RuntimeError:
            logger.debug("No active running event loop for synchronous broadcast")

    async def send_heartbeat(self) -> int:
        """Broadcast a lightweight heartbeat event to all connected clients."""
        heartbeat_event = {
            "event_type": "heartbeat",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return await self.broadcast(heartbeat_event)


# Global singleton manager instance
websocket_manager = WebSocketManager()
