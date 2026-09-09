"""WebSocket endpoint for live pipeline progress.

CRITICAL: Uses global _connections inside broadcast() to avoid Python
UnboundLocalError when modifying the list.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

# Module-level connections list (NOT a set — per spec)
_connections: list[WebSocket] = []


async def ws_endpoint(websocket: WebSocket) -> None:
    """WebSocket handler at /ws/live."""
    await websocket.accept()
    global _connections
    _connections.append(websocket)
    logger.info(f"WebSocket connected. Total: {len(_connections)}")

    try:
        while True:
            # Keep connection alive; client can also send messages
            data = await websocket.receive_text()
            # Echo or handle client messages if needed
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in _connections:
            _connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total: {len(_connections)}")


async def broadcast(message: dict[str, Any]) -> None:
    """Send JSON to all connected WebSocket clients.

    Silently removes dead connections.
    """
    global _connections
    dead: list[WebSocket] = []

    for ws in _connections:
        try:
            await ws.send_text(json.dumps(message))
        except Exception:
            dead.append(ws)

    for ws in dead:
        if ws in _connections:
            _connections.remove(ws)
