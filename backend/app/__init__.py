"""NetGuard AI — Flask application factory.

Usage::

    from app import create_app
    app = create_app("development")
"""

from __future__ import annotations

import os
from typing import Optional

from flask import Flask, jsonify

from app.config import BaseConfig, config_map
from app.extensions import db, socketio, migrate, cors, limiter, redis_client, init_extensions


def create_app(config_name: Optional[str] = None) -> Flask:
    """Create and configure the Flask application.

    Parameters
    ----------
    config_name:
        Key into ``config_map`` (e.g. ``"development"``, ``"production"``,
        ``"testing"``).  Falls back to the ``FLASK_ENV`` environment variable,
        then to ``"default"``.

    Returns
    -------
    Flask
        The fully-configured Flask application instance.
    """
    app = Flask(__name__)

    # ── Load configuration ────────────────────────────────────────────
    config_name = config_name or os.environ.get("FLASK_ENV", "default")
    app.config.from_object(config_map.get(config_name, config_map["default"]))

    # ── Initialise extensions ─────────────────────────────────────────
    init_extensions(app)

    # Import models so they are registered with SQLAlchemy db.metadata
    from app import models  # noqa: F401

    # ── Register API blueprints ───────────────────────────────────────
    _register_blueprints(app)

    # ── Register WebSocket events ─────────────────────────────────────
    _register_websocket_events(app)

    # ── Register error handlers ───────────────────────────────────────
    _register_error_handlers(app)

    return app


def _register_blueprints(app: Flask) -> None:
    """Import and register all API blueprints.

    Each blueprint lives under ``app.api.<module>`` and exposes a
    ``bp`` attribute.
    """
    from app.api import register_blueprints
    register_blueprints(app)


def _register_websocket_events(app: Flask) -> None:
    """Import WebSocket event handlers so they are registered with SocketIO."""
    from app.websocket.events import register_events
    register_events(socketio)


def _register_error_handlers(app: Flask) -> None:
    """Attach JSON-returning error handlers for common HTTP status codes."""

    @app.errorhandler(400)
    def bad_request(error):  # type: ignore[no-untyped-def]
        return jsonify({"error": "Bad request", "message": str(error)}), 400

    @app.errorhandler(404)
    def not_found(error):  # type: ignore[no-untyped-def]
        return jsonify({"error": "Not found", "message": str(error)}), 404

    @app.errorhandler(429)
    def rate_limited(error):  # type: ignore[no-untyped-def]
        return jsonify({"error": "Rate limit exceeded", "message": str(error)}), 429

    @app.errorhandler(500)
    def internal_error(error):  # type: ignore[no-untyped-def]
        return jsonify({"error": "Internal server error", "message": str(error)}), 500
