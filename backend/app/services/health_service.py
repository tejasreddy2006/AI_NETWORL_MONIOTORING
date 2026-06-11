"""
NetGuard AI — Health Service.

Provides business logic for network health scoring,
historical health data retrieval, and detailed metric breakdowns.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from app.extensions import db
from app.models.health import HealthScore, NetworkStatus
from app.models.device import Device
from app.models.alert import Alert
from app.utils.validators import validate_time_range


def get_current_health() -> dict[str, Any]:
    """Return the latest network health score and summary.

    Returns
    -------
    dict
        ``{"score": float, "status": str, "components": dict, "timestamp": str}``
    """
    latest = HealthScore.query.order_by(HealthScore.created_at.desc()).first()

    if not latest:
        return {
            "score": 100.0,
            "status": "EXCELLENT",
            "components": {
                "traffic_stability": 100.0,
                "device_availability": 100.0,
                "alert_frequency": 100.0,
                "bandwidth_usage": 0.0,
                "packet_loss": 0.0,
            },
            "timestamp": datetime.utcnow().isoformat(),
        }

    return {
        "score": latest.overall_score,
        "status": (
            latest.status.value
            if isinstance(latest.status, NetworkStatus)
            else str(latest.status)
        ),
        "components": {
            "traffic_stability": latest.traffic_stability,
            "device_availability": latest.device_availability,
            "alert_frequency": latest.alert_frequency,
            "bandwidth_usage": latest.bandwidth_usage,
            "packet_loss": latest.packet_loss,
        },
        "timestamp": latest.created_at.isoformat(),
    }


def get_health_history(time_range: str = "24h") -> list[dict[str, Any]]:
    """Return historical health scores over the specified window.

    Parameters
    ----------
    time_range : str
        Duration string, e.g. ``'24h'``, ``'7d'``.

    Returns
    -------
    list[dict]
        Time-series of health score snapshots.
    """
    try:
        start_time = validate_time_range(time_range)
    except ValueError:
        start_time = datetime.utcnow() - timedelta(hours=24)

    scores = (
        HealthScore.query.filter(HealthScore.created_at >= start_time)
        .order_by(HealthScore.created_at.asc())
        .all()
    )
    return [s.to_dict() for s in scores]


def get_health_metrics() -> dict[str, Any]:
    """Return a detailed breakdown of individual health metrics.

    Returns
    -------
    dict
        Metric names mapped to their current values and statuses.
    """
    latest = HealthScore.query.order_by(HealthScore.created_at.desc()).first()

    devices_count = Device.query.count()
    active_alerts = Alert.query.filter(Alert.is_resolved == False).count()

    healthy_count = Device.query.filter(Device.health_status == "HEALTHY").count()
    warning_count = Device.query.filter(Device.health_status == "WARNING").count()
    critical_count = Device.query.filter(Device.health_status == "CRITICAL").count()

    critical_alerts = Alert.query.filter(
        Alert.is_resolved == False, Alert.severity == "CRITICAL"
    ).count()
    high_alerts = Alert.query.filter(
        Alert.is_resolved == False, Alert.severity == "HIGH"
    ).count()

    return {
        "overall": latest.overall_score if latest else 100.0,
        "status": (
            latest.status.value
            if latest and isinstance(latest.status, NetworkStatus)
            else "EXCELLENT"
        ),
        "metrics": {
            "device_status": {
                "total_devices": devices_count,
                "healthy_devices": healthy_count,
                "warning_devices": warning_count,
                "critical_devices": critical_count,
            },
            "alerts": {
                "active_alerts": active_alerts,
                "critical_alerts": critical_alerts,
                "high_alerts": high_alerts,
            },
            "performance": {
                "traffic_stability": latest.traffic_stability if latest else 100.0,
                "bandwidth_usage_pct": latest.bandwidth_usage if latest else 10.0,
                "packet_loss_pct": latest.packet_loss if latest else 0.0,
            },
        },
    }
