"""
NetGuard AI — Alerts API Blueprint.

Exposes REST endpoints for alert listing, detail retrieval,
resolution, and statistics.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.services import alert_service

bp = alerts_bp = Blueprint("alerts", __name__)


@bp.route("/", methods=["GET"])
def list_alerts():
    """Return a paginated list of alerts.

    Query Parameters
    ----------------
    page : int
    per_page : int
    severity : str
    threat_type : str
    is_resolved : bool
    """
    try:
        page: int = request.args.get("page", 1, type=int)
        per_page: int = request.args.get("per_page", 50, type=int)
        filters: dict = {
            "severity": request.args.get("severity"),
            "threat_type": request.args.get("threat_type"),
            "is_resolved": request.args.get("is_resolved"),
        }
        result = alert_service.get_alerts(page=page, per_page=per_page, filters=filters)
        return jsonify(result), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/<int:alert_id>", methods=["GET"])
def get_alert(alert_id: int):
    """Return detail for a single alert.

    Parameters
    ----------
    alert_id : int
        Alert primary key (URL path parameter).
    """
    try:
        result = alert_service.get_alert_by_id(alert_id)
        return jsonify(result), 200
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/<int:alert_id>/resolve", methods=["PUT"])
def resolve_alert(alert_id: int):
    """Mark an alert as resolved.

    Parameters
    ----------
    alert_id : int
        Alert primary key (URL path parameter).
    """
    try:
        resolved_by: str = request.json.get("resolved_by", "system") if request.json else "system"
        alert = alert_service.resolve_alert(alert_id, resolved_by=resolved_by)
        return jsonify({"message": "Alert resolved", "alert_id": alert.id}), 200
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/stats", methods=["GET"])
def alert_stats():
    """Return aggregate alert statistics."""
    try:
        result = alert_service.get_alert_stats()
        return jsonify(result), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
