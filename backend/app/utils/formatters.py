"""
NetGuard AI — Output Formatters.

Provides helpers for formatting byte sizes, packet summaries,
timestamps, and paginated API responses.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any


def format_bytes(bytes_count: int) -> str:
    """Convert a raw byte count into a human-readable string.

    Examples: ``1024`` → ``'1.00 KB'``, ``1048576`` → ``'1.00 MB'``.

    Parameters
    ----------
    bytes_count : int
        Number of bytes.

    Returns
    -------
    str
        Human-readable size string (B, KB, MB, GB, TB).
    """
    if not isinstance(bytes_count, (int, float)) or bytes_count <= 0:
        return "0.00 B"

    bytes_float = float(bytes_count)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_float < 1024.0:
            return f"{bytes_float:.2f} {unit}"
        bytes_float /= 1024.0

    return f"{bytes_float:.2f} PB"


def format_packet_summary(packet: dict[str, Any]) -> dict[str, Any]:
    """Produce a slim packet summary suitable for WebSocket broadcast.

    Parameters
    ----------
    packet : dict
        Full packet record.

    Returns
    -------
    dict
        Subset of fields needed for real-time display.
    """
    return {
        "id": packet.get("id"),
        "timestamp": packet.get("timestamp"),
        "src_ip": packet.get("src_ip"),
        "dst_ip": packet.get("dst_ip"),
        "src_port": packet.get("src_port"),
        "dst_port": packet.get("dst_port"),
        "protocol": packet.get("protocol"),
        "packet_size": packet.get("packet_size"),
        "payload_preview": packet.get("payload_preview"),
    }


def format_timestamp(dt: datetime) -> str:
    """Format a ``datetime`` as an ISO-8601 string.

    Parameters
    ----------
    dt : datetime
        The datetime to format.

    Returns
    -------
    str
        ISO-8601 formatted timestamp string.
    """
    if not dt:
        return ""
    return dt.isoformat()


def paginate_response(query: Any, page: int, per_page: int) -> dict[str, Any]:
    """Execute a SQLAlchemy query with pagination and return a standardised dict.

    Parameters
    ----------
    query : Any
        A SQLAlchemy ``Query`` object.
    page : int
        Page number (1-indexed).
    per_page : int
        Items per page.

    Returns
    -------
    dict
        ``{"items": [...], "total": int, "page": int, "per_page": int, "pages": int}``
    """
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    return {
        "items": [item.to_dict() for item in pagination.items],
        "total": pagination.total,
        "page": pagination.page,
        "per_page": pagination.per_page,
        "pages": pagination.pages,
    }
