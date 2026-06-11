"""
NetGuard AI — Health API Blueprint.

Exposes REST endpoints for current health score, historical scores,
and detailed metric breakdowns.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.services import health_service

bp = health_bp = Blueprint("health", __name__)


@bp.route("/score", methods=["GET"])
def current_health():
    """Return the current network health score."""
    try:
        result = health_service.get_current_health()
        return jsonify(result), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/history", methods=["GET"])
def health_history():
    """Return historical health scores.

    Query Parameters
    ----------------
    time_range : str
    """
    try:
        time_range: str = request.args.get("time_range", "24h")
        result = health_service.get_health_history(time_range=time_range)
        return jsonify(result), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/metrics", methods=["GET"])
def health_metrics():
    """Return a detailed breakdown of individual health metrics."""
    try:
        result = health_service.get_health_metrics()
        return jsonify(result), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
