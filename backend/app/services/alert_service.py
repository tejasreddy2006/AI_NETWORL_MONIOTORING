"""
NetGuard AI — Alert Service.

Provides business logic for security alert retrieval, creation,
resolution, and statistics aggregation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import func

from app.extensions import db
from app.models.alert import Alert, SeverityLevel
from app.utils.validators import validate_pagination
from app.utils.formatters import paginate_response


def get_alerts(
    page: int = 1,
    per_page: int = 50,
    filters: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Return a paginated list of alerts.

    Parameters
    ----------
    page : int
        Page number (1-indexed).
    per_page : int
        Items per page.
    filters : dict, optional
        Filter criteria (severity, threat_type, is_resolved, etc.).

    Returns
    -------
    dict
        ``{"items": [...], "total": int, "page": int, "per_page": int, "pages": int}``
    """
    page, per_page = validate_pagination(page, per_page)
    query = Alert.query.order_by(Alert.timestamp.desc())

    if filters:
        if filters.get("severity"):
            try:
                sev = SeverityLevel[filters["severity"].upper()]
                query = query.filter(Alert.severity == sev)
            except KeyError:
                pass
        if filters.get("threat_type"):
            query = query.filter(Alert.threat_type == filters["threat_type"])
        if filters.get("is_resolved") is not None:
            is_res = str(filters["is_resolved"]).lower() == "true"
            query = query.filter(Alert.is_resolved == is_res)
        if filters.get("source_ip"):
            query = query.filter(Alert.source_ip == filters["source_ip"])
        if filters.get("destination_ip"):
            query = query.filter(Alert.destination_ip == filters["destination_ip"])

    return paginate_response(query, page, per_page)


def get_alert_by_id(alert_id: int) -> dict[str, Any]:
    """Fetch a single alert by its primary key.

    Parameters
    ----------
    alert_id : int
        Primary key of the alert.

    Returns
    -------
    dict
        Serialised alert data.

    Raises
    ------
    ValueError
        If no alert with the given ID exists.
    """
    alert = Alert.query.get(alert_id)
    if not alert:
        raise ValueError(f"Alert with ID {alert_id} not found.")
    return alert.to_dict()


def create_alert(data: dict[str, Any]) -> Alert:
    """Create and persist a new alert record.

    Parameters
    ----------
    data : dict
        Alert attributes (severity, threat_type, description, etc.).

    Returns
    -------
    Alert
        The newly created Alert model instance.
    """
    sev_str = data.get("severity", "LOW").upper()
    try:
        severity = SeverityLevel[sev_str]
    except KeyError:
        severity = SeverityLevel.LOW

    ts = data.get("timestamp")
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts)
        except ValueError:
            ts = datetime.utcnow()
    elif not ts:
        ts = datetime.utcnow()

    alert = Alert(
        timestamp=ts,
        threat_type=data.get("threat_type", "Unknown Anomaly"),
        severity=severity,
        source_ip=data.get("source_ip", "0.0.0.0"),
        destination_ip=data.get("destination_ip", "0.0.0.0"),
        description=data.get("description", ""),
        raw_evidence=data.get("raw_evidence"),
        recommended_action=data.get("recommended_action", "Investigate connection."),
        is_resolved=False,
    )
    db.session.add(alert)
    db.session.commit()
    return alert


def resolve_alert(alert_id: int, resolved_by: str = "system") -> Alert:
    """Mark an existing alert as resolved.

    Parameters
    ----------
    alert_id : int
        Primary key of the alert to resolve.
    resolved_by : str
        Identifier of the user or system resolving the alert.

    Returns
    -------
    Alert
        The updated Alert model instance.

    Raises
    ------
    ValueError
        If the alert does not exist or is already resolved.
    """
    alert = Alert.query.get(alert_id)
    if not alert:
        raise ValueError(f"Alert with ID {alert_id} not found.")
    if alert.is_resolved:
        raise ValueError(f"Alert with ID {alert_id} is already resolved.")

    alert.is_resolved = True
    alert.resolved_at = datetime.utcnow()
    alert.resolved_by = resolved_by
    db.session.commit()
    return alert


def get_alert_stats() -> dict[str, Any]:
    """Return aggregate alert statistics.

    Returns
    -------
    dict
        Counts keyed by severity, threat type, and resolution status.
        ``{"by_severity": {...}, "by_type": {...}, "open": int, "resolved": int, "total": int}``
    """
    # Group by severity
    severity_stats = db.session.query(
        Alert.severity, func.count(Alert.id)
    ).group_by(Alert.severity).all()
    by_severity = {getattr(sev, "name", str(sev)): count for sev, count in severity_stats}

    # Group by threat type
    type_stats = db.session.query(
        Alert.threat_type, func.count(Alert.id)
    ).group_by(Alert.threat_type).all()
    by_type = {threat_type: count for threat_type, count in type_stats}

    # Resolution splits
    resolved_count = Alert.query.filter(Alert.is_resolved == True).count()
    open_count = Alert.query.filter(Alert.is_resolved == False).count()
    total_count = Alert.query.count()

    return {
        "by_severity": by_severity,
        "by_type": by_type,
        "open": open_count,
        "resolved": resolved_count,
        "total": total_count,
    }
