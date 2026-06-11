"""
NetGuard AI — Packets API Blueprint.

Exposes REST endpoints for packet listing, traffic statistics,
protocol distribution, and traffic timeline.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.services import packet_service

bp = packets_bp = Blueprint("packets", __name__)


@bp.route("/", methods=["GET"])
def list_packets():
    """Return a paginated list of captured packets.

    Query Parameters
    ----------------
    page : int
    per_page : int
    protocol : str
    src_ip : str
    dst_ip : str
    time_range : str
    """
    try:
        page: int = request.args.get("page", 1, type=int)
        per_page: int = request.args.get("per_page", 50, type=int)
        filters: dict = {
            "protocol": request.args.get("protocol"),
            "src_ip": request.args.get("src_ip"),
            "dst_ip": request.args.get("dst_ip"),
            "time_range": request.args.get("time_range", "1h"),
        }
        result = packet_service.get_packets(page=page, per_page=per_page, filters=filters)
        return jsonify(result), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/stats", methods=["GET"])
def packet_stats():
    """Return aggregate traffic statistics.

    Query Parameters
    ----------------
    time_range : str
    """
    try:
        time_range: str = request.args.get("time_range", "1h")
        result = packet_service.get_packet_stats(time_range=time_range)
        return jsonify(result), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/protocols", methods=["GET"])
def protocol_distribution():
    """Return protocol distribution breakdown.

    Query Parameters
    ----------------
    time_range : str
    """
    try:
        time_range: str = request.args.get("time_range", "1h")
        result = packet_service.get_protocol_distribution(time_range=time_range)
        return jsonify(result), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/timeline", methods=["GET"])
def traffic_timeline():
    """Return time-series traffic data.

    Query Parameters
    ----------------
    time_range : str
    interval : str
    """
    try:
        time_range: str = request.args.get("time_range", "1h")
        interval: str = request.args.get("interval", "1m")
        result = packet_service.get_traffic_timeline(time_range=time_range, interval=interval)
        return jsonify(result), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
