"""
NetGuard AI — Packet Service.

Provides business logic for network packet retrieval, statistics,
protocol distribution, and traffic timeline generation.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy import func

from app.extensions import db
from app.models.packet import Packet
from app.utils.validators import validate_pagination, validate_time_range
from app.utils.formatters import paginate_response


def get_packets(
    page: int = 1,
    per_page: int = 50,
    filters: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Return a paginated list of captured packets.

    Parameters
    ----------
    page : int
        The page number (1-indexed).
    per_page : int
        Number of packets per page.
    filters : dict, optional
        Key/value filter criteria (e.g. protocol, src_ip, dst_ip, time_range).

    Returns
    -------
    dict
        ``{"items": [...], "total": int, "page": int, "per_page": int, "pages": int}``
    """
    page, per_page = validate_pagination(page, per_page)
    query = Packet.query.order_by(Packet.timestamp.desc())

    if filters:
        if filters.get("protocol"):
            query = query.filter(Packet.protocol == filters["protocol"])
        if filters.get("src_ip"):
            query = query.filter(Packet.src_ip == filters["src_ip"])
        if filters.get("dst_ip"):
            query = query.filter(Packet.dst_ip == filters["dst_ip"])
        if filters.get("time_range"):
            try:
                start_time = validate_time_range(filters["time_range"])
                query = query.filter(Packet.timestamp >= start_time)
            except ValueError:
                pass

    return paginate_response(query, page, per_page)


def get_packet_stats(time_range: str = "1h") -> dict[str, Any]:
    """Return aggregate traffic statistics for the given time range.

    Parameters
    ----------
    time_range : str
        Human-readable duration string, e.g. ``'1h'``, ``'24h'``, ``'7d'``.

    Returns
    -------
    dict
        ``{"total_packets": int, "total_bytes": int, "protocol_distribution": dict}``
    """
    start_time = validate_time_range(time_range)

    # Fetch count and sum of bytes
    stats = db.session.query(
        func.count(Packet.id).label("count"),
        func.sum(Packet.packet_size).label("bytes")
    ).filter(Packet.timestamp >= start_time).first()

    total_packets = stats.count or 0
    total_bytes = int(stats.bytes) if stats.bytes else 0

    # Fetch protocol counts
    proto_stats = db.session.query(
        Packet.protocol,
        func.count(Packet.id).label("count")
    ).filter(Packet.timestamp >= start_time).group_by(Packet.protocol).all()

    proto_dist = {row.protocol: row.count for row in proto_stats}

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "protocol_distribution": proto_dist
    }


def get_protocol_distribution(time_range: str = "1h") -> list[dict[str, Any]]:
    """Return a breakdown of packets grouped by protocol.

    Parameters
    ----------
    time_range : str
        Duration string.

    Returns
    -------
    list[dict]
        Each element: ``{"protocol": str, "count": int, "percentage": float}``
    """
    start_time = validate_time_range(time_range)

    proto_stats = db.session.query(
        Packet.protocol,
        func.count(Packet.id).label("count")
    ).filter(Packet.timestamp >= start_time).group_by(Packet.protocol).all()

    total = sum(row.count for row in proto_stats)

    result = []
    for row in proto_stats:
        percentage = round((row.count / total * 100), 2) if total > 0 else 0.0
        result.append({
            "protocol": row.protocol,
            "count": row.count,
            "percentage": percentage
        })

    return sorted(result, key=lambda x: x["count"], reverse=True)


def get_traffic_timeline(
    time_range: str = "1h",
    interval: str = "1m",
) -> list[dict[str, Any]]:
    """Return time-series traffic data bucketed by *interval*.

    Parameters
    ----------
    time_range : str
        Overall window, e.g. ``'1h'``.
    interval : str
        Bucket width, e.g. ``'1m'``, ``'5m'``.

    Returns
    -------
    list[dict]
        Each element: ``{"timestamp": str, "packets": int, "bytes": int}``
    """
    start_time = validate_time_range(time_range)

    # Load matching packets
    packets = db.session.query(Packet.timestamp, Packet.packet_size).filter(
        Packet.timestamp >= start_time
    ).all()

    # Determine interval size in seconds
    match = re.match(r"^(\d+)([mh])$", interval.lower())
    if match:
        val = int(match.group(1))
        unit = match.group(2)
        sec = val * 60 if unit == "m" else val * 3600
    else:
        sec = 60

    buckets: dict[str, dict[str, Any]] = {}
    for pkt in packets:
        ts_epoch = int(pkt.timestamp.timestamp())
        bucket_epoch = (ts_epoch // sec) * sec
        bucket_dt = datetime.fromtimestamp(bucket_epoch)
        bucket_str = bucket_dt.isoformat()

        if bucket_str not in buckets:
            buckets[bucket_str] = {"timestamp": bucket_str, "packets": 0, "bytes": 0}
        buckets[bucket_str]["packets"] += 1
        buckets[bucket_str]["bytes"] += pkt.packet_size

    return sorted(list(buckets.values()), key=lambda x: x["timestamp"])


def save_packets_batch(packets: list[dict[str, Any]]) -> int:
    """Persist a batch of raw packet dicts to the database.

    Parameters
    ----------
    packets : list[dict]
        List of packet dictionaries to save.

    Returns
    -------
    int
        Number of packets successfully saved.
    """
    if not packets:
        return 0

    packet_objs = []
    for p in packets:
        ts = p.get("timestamp")
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts)
            except ValueError:
                ts = datetime.utcnow()
        elif not ts:
            ts = datetime.utcnow()

        packet_objs.append(Packet(
            timestamp=ts,
            src_ip=p.get("src_ip"),
            dst_ip=p.get("dst_ip"),
            src_port=p.get("src_port"),
            dst_port=p.get("dst_port"),
            protocol=p.get("protocol"),
            packet_size=p.get("packet_size", 0),
            ttl=p.get("ttl"),
            src_mac=p.get("src_mac"),
            dst_mac=p.get("dst_mac"),
            payload_preview=p.get("payload_preview"),
        ))

    db.session.bulk_save_objects(packet_objs)
    db.session.commit()
    return len(packet_objs)
