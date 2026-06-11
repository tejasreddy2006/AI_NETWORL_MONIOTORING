"""NetGuard AI — Network Health Score model.

Periodically computed composite health score built from multiple
sub-metrics (traffic stability, device availability, alert frequency,
bandwidth usage, packet loss).
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any, Dict

from app.extensions import db


class NetworkStatus(enum.Enum):
    """Overall network status classification."""

    EXCELLENT = "EXCELLENT"
    GOOD = "GOOD"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class HealthScore(db.Model):  # type: ignore[name-defined]
    """A point-in-time network health snapshot."""

    __tablename__ = "health_scores"

    id: int = db.Column(db.Integer, primary_key=True, autoincrement=True)
    overall_score: float = db.Column(db.Float, nullable=False)
    traffic_stability: float = db.Column(db.Float, nullable=False)
    device_availability: float = db.Column(db.Float, nullable=False)
    alert_frequency: float = db.Column(db.Float, nullable=False)
    bandwidth_usage: float = db.Column(db.Float, nullable=False)
    packet_loss: float = db.Column(db.Float, nullable=False)
    status: str = db.Column(db.Enum(NetworkStatus), nullable=False)
    created_at: datetime = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # ── Serialisation ─────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dictionary."""
        return {
            "id": self.id,
            "overall_score": self.overall_score,
            "traffic_stability": self.traffic_stability,
            "device_availability": self.device_availability,
            "alert_frequency": self.alert_frequency,
            "bandwidth_usage": self.bandwidth_usage,
            "packet_loss": self.packet_loss,
            "status": (
                self.status.value if isinstance(self.status, NetworkStatus) else self.status
            ),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<HealthScore {self.id} score={self.overall_score:.1f} [{self.status}]>"
