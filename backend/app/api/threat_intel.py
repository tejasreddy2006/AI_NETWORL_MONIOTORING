"""
NetGuard AI — Threat Intelligence API Blueprint.

Exposes REST endpoints for geo traffic data, map visualisation,
suspicious IP listing, country statistics, and IP lookups.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.services import threat_intel_service

bp = threat_intel_bp = Blueprint("threat_intel", __name__)


@bp.route("/geo", methods=["GET"])
def geo_traffic():
    """Return geo-located traffic records.

    Query Parameters
    ----------------
    country : str
    time_range : str
    """
    try:
        filters: dict = {
            "country": request.args.get("country"),
            "time_range": request.args.get("time_range"),
        }
        result = threat_intel_service.get_geo_traffic(filters=filters)
        return jsonify(result), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/map", methods=["GET"])
def map_data():
    """Return traffic data formatted for map visualisation."""
    try:
        result = threat_intel_service.get_map_data()
        return jsonify(result), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/suspicious", methods=["GET"])
def suspicious_ips():
    """Return a list of IP addresses flagged as suspicious."""
    try:
        result = threat_intel_service.get_suspicious_ips()
        return jsonify(result), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/countries", methods=["GET"])
def country_stats():
    """Return aggregated traffic statistics grouped by country."""
    try:
        result = threat_intel_service.get_country_stats()
        return jsonify(result), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/lookup/<ip_address>", methods=["GET"])
def lookup_ip(ip_address: str):
    """Perform a detailed lookup for a specific IP address.

    Parameters
    ----------
    ip_address : str
        The IP to look up (URL path parameter).
    """
    try:
        result = threat_intel_service.lookup_ip(ip_address)
        return jsonify(result), 200
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
