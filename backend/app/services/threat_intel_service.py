"""
NetGuard AI — Threat Intelligence Service.

Provides business logic for geo-located traffic analysis,
suspicious IP identification, country-level statistics, and IP lookups.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import func

from app.extensions import db
from app.models.geo_traffic import GeoTraffic
from app.models.alert import Alert
from app.models.packet import Packet


def get_geo_traffic(
    filters: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    """Return geo-located traffic records, optionally filtered.

    Parameters
    ----------
    filters : dict, optional
        Filter criteria (e.g. country_code).

    Returns
    -------
    list[dict]
        Serialised geo-traffic records.
    """
    query = GeoTraffic.query
    if filters and filters.get("country_code"):
        query = query.filter(GeoTraffic.country_code == filters["country_code"])
    return [gt.to_dict() for gt in query.all()]


def get_map_data() -> list[dict[str, Any]]:
    """Return traffic data formatted for map visualisation.

    Returns
    -------
    list[dict]
        Each element: ``{"lat": float, "lon": float, "count": int, "country": str, ...}``
    """
    traffic = GeoTraffic.query.all()
    map_data = []
    for t in traffic:
        map_data.append({
            "ip": t.ip_address,
            "lat": t.latitude,
            "lon": t.longitude,
            "count": t.packet_count,
            "bytes": t.total_bytes,
            "country": t.country_name,
            "country_code": t.country_code,
            "reputation": t.reputation_score,
            "status": "malicious" if t.reputation_score < 70 else "clean"
        })
    return map_data


def get_suspicious_ips() -> list[dict[str, Any]]:
    """Return a list of IP addresses flagged as suspicious.

    Returns
    -------
    list[dict]
        Each element: ``{"ip_address": str, "risk_level": str, "reputation_score": float, ...}``
    """
    traffic = (
        GeoTraffic.query.filter(GeoTraffic.reputation_score < 75)
        .order_by(GeoTraffic.reputation_score.asc())
        .all()
    )
    suspicious = []
    for t in traffic:
        suspicious.append({
            "ip_address": t.ip_address,
            "country_name": t.country_name,
            "country_code": t.country_code,
            "packet_count": t.packet_count,
            "reputation_score": t.reputation_score,
            "risk_level": "critical" if t.reputation_score < 50 else "high"
        })
    return suspicious


def get_country_stats() -> list[dict[str, Any]]:
    """Return aggregated traffic statistics grouped by country.

    Returns
    -------
    list[dict]
        Each element: ``{"country": str, "country_code": str, "total_traffic": int, ...}``
    """
    stats = db.session.query(
        GeoTraffic.country_name,
        GeoTraffic.country_code,
        func.sum(GeoTraffic.packet_count).label("packets"),
        func.sum(GeoTraffic.total_bytes).label("bytes"),
        func.avg(GeoTraffic.reputation_score).label("avg_reputation")
    ).group_by(GeoTraffic.country_name, GeoTraffic.country_code).all()

    result = []
    for row in stats:
        result.append({
            "country": row.country_name,
            "country_code": row.country_code,
            "total_packets": row.packets or 0,
            "total_bytes": int(row.bytes) if row.bytes else 0,
            "reputation_score": round(row.avg_reputation, 1) if row.avg_reputation else 100.0
        })
    return sorted(result, key=lambda x: x["total_packets"], reverse=True)


def lookup_ip(ip_address: str) -> dict[str, Any]:
    """Perform a detailed lookup for a specific IP address.

    Parameters
    ----------
    ip_address : str
        The IP address to look up.

    Returns
    -------
    dict
        Enriched information about the IP (geo, reputation, etc.).
    """
    geo = GeoTraffic.query.filter(GeoTraffic.ip_address == ip_address).first()
    alerts_count = Alert.query.filter(Alert.source_ip == ip_address).count()
    packets_count = Packet.query.filter(
        (Packet.src_ip == ip_address) | (Packet.dst_ip == ip_address)
    ).count()

    if geo:
        return {
            "ip": ip_address,
            "registered": True,
            "country_name": geo.country_name,
            "country_code": geo.country_code,
            "city": geo.city,
            "latitude": geo.latitude,
            "longitude": geo.longitude,
            "reputation_score": geo.reputation_score,
            "activity": {
                "total_packets": packets_count,
                "triggered_alerts": alerts_count,
                "last_seen": geo.last_seen.isoformat()
            }
        }

    # Fallback for local / unregistered IPs
    is_private = False
    try:
        is_private = ipaddress.ip_address(ip_address).is_private
    except ValueError:
        pass

    return {
        "ip": ip_address,
        "registered": False,
        "country_name": "Private Network" if is_private else "Unknown Location",
        "country_code": "PV" if is_private else "XX",
        "city": None,
        "latitude": 0.0,
        "longitude": 0.0,
        "reputation_score": 100.0 if is_private else 50.0,
        "activity": {
            "total_packets": packets_count,
            "triggered_alerts": alerts_count,
            "last_seen": datetime.utcnow().isoformat()
        }
    }
