"""NetGuard AI — Health Score Engine.

Computes a composite network health score from multiple sub-metrics
and persists the result as a ``HealthScore`` snapshot.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from flask import Flask


class HealthScoreEngine:
    """Computes and records periodic network health scores.

    Parameters
    ----------
    app:
        Optional Flask application.
    """

    def __init__(self, app: Optional[Flask] = None) -> None:
        self._app: Optional[Flask] = None

        if app is not None:
            self.init_app(app)

    # ── Flask integration ─────────────────────────────────────────────

    def init_app(self, app: Flask) -> None:
        """Bind the engine to a Flask application.

        Parameters
        ----------
        app:
            The Flask application instance.
        """
        self._app = app
        app.extensions["health_score"] = self

    # ── Public API ────────────────────────────────────────────────────

    def calculate(self) -> Dict[str, Any]:
        """Compute the overall health score and all sub-metrics.

        Returns
        -------
        dict
            ``{"overall_score": float, "traffic_stability": float, …,
            "status": str}``
        """
        raise NotImplementedError

    # ── Sub-metric calculators ────────────────────────────────────────

    def _calc_traffic_stability(self) -> float:
        """Evaluate traffic stability (0.0 – 100.0)."""
        raise NotImplementedError

    def _calc_device_availability(self) -> float:
        """Evaluate device availability (0.0 – 100.0)."""
        raise NotImplementedError

    def _calc_alert_frequency(self) -> float:
        """Evaluate alert frequency score (0.0 – 100.0, higher = fewer alerts)."""
        raise NotImplementedError

    def _calc_bandwidth_usage(self) -> float:
        """Evaluate bandwidth usage score (0.0 – 100.0)."""
        raise NotImplementedError

    def _calc_packet_loss(self) -> float:
        """Evaluate packet loss score (0.0 – 100.0, higher = less loss)."""
        raise NotImplementedError

    def _determine_status(self, score: float) -> str:
        """Map a numeric score to a ``NetworkStatus`` label.

        Parameters
        ----------
        score:
            Overall score (0.0 – 100.0).

        Returns
        -------
        str
            One of ``EXCELLENT``, ``GOOD``, ``WARNING``, ``CRITICAL``.
        """
        raise NotImplementedError
