"""NetGuard AI — Packet model.

Stores parsed network packet metadata captured by the packet-capture
engine.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, Any

from app.extensions import db


class Packet(db.Model):  # type: ignore[name-defined]
    """Represents a single captured network packet."""

    __tablename__ = "packets"

    id: int = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp: datetime = db.Column(db.DateTime, nullable=False, index=True)
    src_ip: str = db.Column(db.String(45), nullable=False, index=True)
    dst_ip: str = db.Column(db.String(45), nullable=False, index=True)
    src_port: int | None = db.Column(db.Integer, nullable=True)
    dst_port: int | None = db.Column(db.Integer, nullable=True)
    protocol: str = db.Column(db.String(20), nullable=False, index=True)
    packet_size: int = db.Column(db.Integer, nullable=False)
    ttl: int | None = db.Column(db.Integer, nullable=True)
    src_mac: str | None = db.Column(db.String(17), nullable=True)
    dst_mac: str | None = db.Column(db.String(17), nullable=True)
    payload_preview: str | None = db.Column(db.Text, nullable=True)
    created_at: datetime = db.Column(db.DateTime, default=datetime.utcnow)

    # ── Serialisation ─────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dictionary of this packet."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packet_size": self.packet_size,
            "ttl": self.ttl,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "payload_preview": self.payload_preview,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<Packet {self.id} {self.protocol} "
            f"{self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port}>"
        )
