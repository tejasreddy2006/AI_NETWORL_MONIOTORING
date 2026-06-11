"""
NetGuard AI — System API Blueprint.

Exposes REST endpoints for system health checks
and non-sensitive configuration retrieval.
"""

from __future__ import annotations

import time

from flask import Blueprint, current_app, jsonify

bp = system_bp = Blueprint("system", __name__)

# Module-level sentinel to approximate uptime (set once at import time).
_START_TIME: float = time.time()


@bp.route("/status", methods=["GET"])
def system_status():
    """Return system health status including uptime, DB connectivity, and engine status."""
    try:
        uptime_seconds: float = time.time() - _START_TIME
        
        # probe database
        db_status = "ok"
        try:
            from sqlalchemy import text
            from app.extensions import db
            db.session.execute(text("SELECT 1"))
        except Exception:
            db_status = "error"
            
        result: dict = {
            "status": "ok" if db_status == "ok" else "degraded",
            "uptime_seconds": round(uptime_seconds, 2),
            "database": db_status,
            "engine": "active" if current_app.config.get("DEMO_MODE") else "passive",
        }
        return jsonify(result), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/config", methods=["GET"])
def system_config():
    """Return current non-sensitive application configuration."""
    try:
        safe_keys: list[str] = [
            "DEBUG",
            "TESTING",
            "ENV",
            "SERVER_NAME",
        ]
        config: dict = {
            key: current_app.config.get(key)
            for key in safe_keys
            if key in current_app.config
        }
        return jsonify(config), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
