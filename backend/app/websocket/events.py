"""
NetGuard AI — WebSocket Events.

Registers Socket.IO event handlers for real-time client communication
and provides broadcast helpers used by other parts of the application.
"""

from __future__ import annotations

import logging
from typing import Any

from flask_socketio import SocketIO, emit

logger: logging.Logger = logging.getLogger(__name__)

# Module-level reference set by ``register_events``.
_socketio: SocketIO | None = None


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_events(socketio: SocketIO) -> None:
    """Register all Socket.IO event handlers on the given *socketio* instance.

    Parameters
    ----------
    socketio : SocketIO
        The Flask-SocketIO server instance.
    """
    global _socketio  # noqa: PLW0603
    _socketio = socketio

    @socketio.on("connect")
    def handle_connect() -> None:
        """Log a new WebSocket connection."""
        logger.info("Client connected")

    @socketio.on("disconnect")
    def handle_disconnect() -> None:
        """Log a WebSocket disconnection."""
        logger.info("Client disconnected")

    @socketio.on("ai:query")
    def handle_ai_query(data: dict[str, Any]) -> None:
        """Handle an AI chat query received over WebSocket.

        Parameters
        ----------
        data : dict
            Expected keys: ``session_id``, ``message``.
        """
        from app.services import ai_service

        session_id: str = data.get("session_id", "")
        message: str = data.get("message", "")

        try:
            response: str = ai_service.process_chat(session_id=session_id, message=message)
            emit("ai:response", {"session_id": session_id, "response": response})
        except Exception as exc:
            logger.exception("Error handling ai:query")
            emit("ai:response", {"session_id": session_id, "error": str(exc)})


# ---------------------------------------------------------------------------
# Broadcast helpers
# ---------------------------------------------------------------------------

def broadcast_packet(packet_data: dict[str, Any]) -> None:
    """Broadcast a new packet event to all connected clients.

    Parameters
    ----------
    packet_data : dict
        Serialised packet payload.
    """
    if _socketio is not None:
        _socketio.emit("packet:new", packet_data)


def broadcast_alert(alert_data: dict[str, Any]) -> None:
    """Broadcast a new alert event to all connected clients.

    Parameters
    ----------
    alert_data : dict
        Serialised alert payload.
    """
    if _socketio is not None:
        _socketio.emit("alert:new", alert_data)


def broadcast_health(health_data: dict[str, Any]) -> None:
    """Broadcast a health-score update to all connected clients.

    Parameters
    ----------
    health_data : dict
        Health score payload.
    """
    if _socketio is not None:
        _socketio.emit("health:update", health_data)


def broadcast_topology(topology_data: dict[str, Any]) -> None:
    """Broadcast a topology change to all connected clients.

    Parameters
    ----------
    topology_data : dict
        Topology graph payload.
    """
    if _socketio is not None:
        _socketio.emit("topology:update", topology_data)


def broadcast_stats(stats_data: dict[str, Any]) -> None:
    """Broadcast updated statistics to all connected clients.

    Parameters
    ----------
    stats_data : dict
        Aggregated stats payload.
    """
    if _socketio is not None:
        _socketio.emit("stats:update", stats_data)
