"""
NetGuard AI — Topology API Blueprint.

Exposes REST endpoints for network device listing, link listing,
and full topology graph retrieval.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.services import topology_service

bp = topology_bp = Blueprint("topology", __name__)


@bp.route("/devices", methods=["GET"])
def list_devices():
    """Return a list of discovered network devices.

    Query Parameters
    ----------------
    device_type : str
    status : str
    """
    try:
        filters: dict = {
            "device_type": request.args.get("device_type"),
            "status": request.args.get("status"),
        }
        result = topology_service.get_devices(filters=filters)
        return jsonify(result), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/links", methods=["GET"])
def list_links():
    """Return all known links between network devices."""
    try:
        result = topology_service.get_device_links()
        return jsonify(result), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/graph", methods=["GET"])
def topology_graph():
    """Return the full topology graph (nodes + edges)."""
    try:
        result = topology_service.get_topology_graph()
        return jsonify(result), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
