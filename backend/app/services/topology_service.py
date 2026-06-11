"""
NetGuard AI — Topology Service.

Provides business logic for network device and link management,
as well as full topology graph construction.
"""

from __future__ import annotations

import math
from typing import Any, Optional

from app.extensions import db
from app.models.device import Device, DeviceLink, HealthStatus


def get_devices(filters: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
    """Return a list of discovered network devices.

    Parameters
    ----------
    filters : dict, optional
        Optional filter criteria (e.g. device_type, health_status).

    Returns
    -------
    list[dict]
        Serialised device records.
    """
    query = Device.query
    if filters:
        if filters.get("device_type"):
            query = query.filter(Device.device_type == filters["device_type"])
        if filters.get("health_status"):
            try:
                status = HealthStatus[filters["health_status"].upper()]
                query = query.filter(Device.health_status == status)
            except KeyError:
                pass

    return [d.to_dict() for d in query.all()]


def get_device_links() -> list[dict[str, Any]]:
    """Return all known links between network devices.

    Returns
    -------
    list[dict]
        Each element is a serialised link dict.
    """
    return [link.to_dict() for link in DeviceLink.query.all()]


def get_topology_graph() -> dict[str, Any]:
    """Build and return the full network topology graph.

    Returns
    -------
    dict
        ``{"nodes": [...], "edges": [...]}`` suitable for front-end rendering.
    """
    devices = Device.query.all()
    links = DeviceLink.query.all()

    nodes = []
    for i, dev in enumerate(devices):
        dt = dev.device_type.lower()
        # Arrange nodes based on functional layers:
        # routers in the center, switches clustered outer, other hosts outer.
        angle = i * (2 * math.pi / max(len(devices), 1))
        if dt == "router":
            x = 400 + 100 * math.cos(angle)
            y = 300 + 100 * math.sin(angle)
        elif dt == "switch":
            x = 400 + 220 * math.cos(angle)
            y = 300 + 220 * math.sin(angle)
        else:
            x = 400 + 350 * math.cos(angle)
            y = 300 + 350 * math.sin(angle)

        nodes.append({
            "id": str(dev.id),
            "type": "customNode",
            "data": {
                "label": dev.hostname or dev.ip_address,
                "ip": dev.ip_address,
                "mac": dev.mac_address,
                "type": dev.device_type,
                "status": (
                    dev.health_status.value
                    if isinstance(dev.health_status, HealthStatus)
                    else str(dev.health_status)
                ),
                "vendor": dev.vendor,
                "os": dev.os_guess,
            },
            "position": {"x": int(x), "y": int(y)},
        })

    edges = []
    for link in links:
        edges.append({
            "id": f"e-{link.source_device_id}-{link.target_device_id}",
            "source": str(link.source_device_id),
            "target": str(link.target_device_id),
            "data": {
                "packet_count": link.packet_count,
                "total_bytes": link.total_bytes,
            },
            "animated": link.packet_count > 1000,
        })

    return {"nodes": nodes, "edges": edges}


def update_device(ip_address: str, data: dict[str, Any]) -> Device:
    """Update attributes of an existing device identified by IP address.

    Parameters
    ----------
    ip_address : str
        IP address of the device to update.
    data : dict
        Key/value pairs to update on the device record.

    Returns
    -------
    Device
        The updated Device model instance.

    Raises
    ------
    ValueError
        If no device with the given IP exists.
    """
    dev = Device.query.filter(Device.ip_address == ip_address).first()
    if not dev:
        raise ValueError(f"Device with IP {ip_address} not found.")

    for k, v in data.items():
        if hasattr(dev, k):
            if k == "health_status" and isinstance(v, str):
                try:
                    v = HealthStatus[v.upper()]
                except KeyError:
                    continue
            setattr(dev, k, v)

    db.session.commit()
    return dev
