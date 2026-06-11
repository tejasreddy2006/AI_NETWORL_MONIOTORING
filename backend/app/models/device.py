"""NetGuard AI — Device and DeviceLink models.

Tracks discovered network devices and the communication links
between them to build a live topology map.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Dict, Any

from app.extensions import db


class HealthStatus(enum.Enum):
    """Device health statuses."""

    HEALTHY = "HEALTHY"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class Device(db.Model):  # type: ignore[name-defined]
    """Represents a discovered network device."""

    __tablename__ = "devices"

    id: int = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip_address: str = db.Column(db.String(45), unique=True, nullable=False, index=True)
    mac_address: str | None = db.Column(db.String(17), nullable=True)
    device_type: str = db.Column(
        db.String(30),
        nullable=False,
        default="unknown",
        comment="router | switch | server | pc | iot | firewall | unknown",
    )
    hostname: str | None = db.Column(db.String(255), nullable=True)
    vendor: str | None = db.Column(db.String(100), nullable=True)
    os_guess: str | None = db.Column(db.String(100), nullable=True)
    health_status: str = db.Column(
        db.Enum(HealthStatus), nullable=False, default=HealthStatus.UNKNOWN
    )
    first_seen: datetime = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_seen: datetime = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    created_at: datetime = db.Column(db.DateTime, default=datetime.utcnow)

    # ── Serialisation ─────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dictionary of this device."""
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "device_type": self.device_type,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "os_guess": self.os_guess,
            "health_status": (
                self.health_status.value
                if isinstance(self.health_status, HealthStatus)
                else self.health_status
            ),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<Device {self.id} {self.ip_address} ({self.device_type})>"


class DeviceLink(db.Model):  # type: ignore[name-defined]
    """Represents a directional communication link between two devices."""

    __tablename__ = "device_links"

    id: int = db.Column(db.Integer, primary_key=True, autoincrement=True)
    source_device_id: int = db.Column(
        db.Integer, db.ForeignKey("devices.id"), nullable=False, index=True
    )
    target_device_id: int = db.Column(
        db.Integer, db.ForeignKey("devices.id"), nullable=False, index=True
    )
    packet_count: int = db.Column(db.Integer, default=0)
    total_bytes: int = db.Column(db.BigInteger, default=0)
    first_seen: datetime = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_seen: datetime = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # ORM relationships (back-populated from Device if needed later)
    source_device = db.relationship(
        "Device", foreign_keys=[source_device_id], backref="outgoing_links", lazy="select"
    )
    target_device = db.relationship(
        "Device", foreign_keys=[target_device_id], backref="incoming_links", lazy="select"
    )

    # ── Serialisation ─────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dictionary of this link."""
        return {
            "id": self.id,
            "source_device_id": self.source_device_id,
            "target_device_id": self.target_device_id,
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }

    def __repr__(self) -> str:
        return (
            f"<DeviceLink {self.id} "
            f"dev:{self.source_device_id} → dev:{self.target_device_id}>"
        )
