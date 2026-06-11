"""
NetGuard AI — Input Validators.

Provides reusable validation helpers for IP addresses,
pagination parameters, time-range strings, and user-supplied text.
"""

from __future__ import annotations

import re
import ipaddress
from datetime import datetime, timedelta
from typing import Tuple


def validate_ip(ip: str) -> bool:
    """Return ``True`` if *ip* is a valid IPv4 or IPv6 address.

    Parameters
    ----------
    ip : str
        The IP address string to validate.

    Returns
    -------
    bool
    """
    if not ip:
        return False
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_pagination(page: int, per_page: int) -> Tuple[int, int]:
    """Sanitise and clamp pagination parameters.

    Parameters
    ----------
    page : int
        Requested page number (1-indexed).
    per_page : int
        Requested items per page.

    Returns
    -------
    tuple[int, int]
        ``(page, per_page)`` with safe defaults applied.
    """
    try:
        validated_page = max(1, int(page))
    except (ValueError, TypeError):
        validated_page = 1

    try:
        validated_per_page = max(1, min(100, int(per_page)))
    except (ValueError, TypeError):
        validated_per_page = 50

    return validated_page, validated_per_page


def validate_time_range(time_range: str) -> datetime:
    """Parse a human-readable time-range string and return the start ``datetime``.

    Supported formats: ``'1h'``, ``'24h'``, ``'7d'``, ``'30d'``, etc.

    Parameters
    ----------
    time_range : str
        Duration string.

    Returns
    -------
    datetime
        The computed start timestamp.

    Raises
    ------
    ValueError
        If the format is unrecognised.
    """
    if not time_range:
        return datetime.utcnow() - timedelta(hours=1)

    match = re.match(r"^(\d+)([hdm])$", time_range.lower())
    if not match:
        raise ValueError(f"Unrecognised time range format: {time_range}")

    value = int(match.group(1))
    unit = match.group(2)

    if unit == "h":
        return datetime.utcnow() - timedelta(hours=value)
    elif unit == "d":
        return datetime.utcnow() - timedelta(days=value)
    elif unit == "m":
        return datetime.utcnow() - timedelta(minutes=value)

    raise ValueError(f"Unsupported time unit: {unit}")


def sanitize_string(value: str) -> str:
    """Strip dangerous HTML characters and whitespace from user input.

    Parameters
    ----------
    value : str
        Raw user-supplied string.

    Returns
    -------
    str
        Sanitised string safe for further processing.
    """
    if not value:
        return ""
    # Strip HTML tags
    clean = re.sub(r"<[^>]*>", "", value)
    return clean.strip()
