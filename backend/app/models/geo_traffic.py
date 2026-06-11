"""NetGuard AI — GeoTraffic model.

Maps IP addresses to geographic locations and tracks per-location
traffic volume and reputation scores for the threat-intel globe view.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

from app.extensions import db


class GeoTraffic(db.Model):  # type: ignore[name-defined]
    """Geographic traffic record linking an IP to a location."""

    __tablename__ = "geo_traffic"

    id: int = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip_address: str = db.Column(db.String(45), nullable=False, index=True)
    country_code: str = db.Column(db.String(2), nullable=False, index=True)
    country_name: str = db.Column(db.String(100), nullable=False)
    city: str | None = db.Column(db.String(100), nullable=True)
    latitude: float = db.Column(db.Float, nullable=False)
    longitude: float = db.Column(db.Float, nullable=False)
    packet_count: int = db.Column(db.Integer, default=0)
    total_bytes: int = db.Column(db.BigInteger, default=0)
    reputation_score: float = db.Column(db.Float, default=50.0)
    last_seen: datetime = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    created_at: datetime = db.Column(db.DateTime, default=datetime.utcnow)

    # ── Serialisation ─────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dictionary."""
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "reputation_score": self.reputation_score,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<GeoTraffic {self.id} {self.ip_address} [{self.country_code}]>"
