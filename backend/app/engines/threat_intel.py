"""NetGuard AI — Threat Intelligence Engine.

Provides geographic IP look-ups (MaxMind GeoIP2), reputation scoring,
and aggregated country-level traffic statistics for the globe / map
view on the front-end.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from flask import Flask


class ThreatIntelEngine:
    """GeoIP and threat-intelligence look-up engine.

    Parameters
    ----------
    app:
        Optional Flask application.
    """

    def __init__(self, app: Optional[Flask] = None) -> None:
        self._geoip_reader: Optional[Any] = None
        self._app: Optional[Flask] = None

        if app is not None:
            self.init_app(app)

    # ── Flask integration ─────────────────────────────────────────────

    def init_app(self, app: Flask) -> None:
        """Bind the engine to a Flask application and open the GeoIP DB.

        Parameters
        ----------
        app:
            The Flask application instance.
        """
        self._app = app
        app.extensions["threat_intel"] = self

    # ── Public API ────────────────────────────────────────────────────

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Return geographic and reputation data for *ip*.

        Parameters
        ----------
        ip:
            The IP address to look up.

        Returns
        -------
        dict
            ``{"country_code": …, "city": …, "latitude": …, …}``
        """
        raise NotImplementedError

    def get_country_stats(self) -> List[Dict[str, Any]]:
        """Aggregate traffic statistics grouped by country.

        Returns
        -------
        list[dict]
            List of per-country stat dicts.
        """
        raise NotImplementedError

    def get_suspicious_ips(self) -> List[Dict[str, Any]]:
        """Return IPs with low reputation scores.

        Returns
        -------
        list[dict]
            List of suspicious-IP dicts.
        """
        raise NotImplementedError

    def get_map_data(self) -> List[Dict[str, Any]]:
        """Produce the dataset for the interactive globe / map.

        Returns
        -------
        list[dict]
            List of geo-point dicts with traffic volume and reputation.
        """
        raise NotImplementedError

    # ── Internal helpers ──────────────────────────────────────────────

    def _geoip_lookup(self, ip: str) -> Dict[str, Any]:
        """Query the MaxMind GeoIP2 database.

        Parameters
        ----------
        ip:
            The IP address.

        Returns
        -------
        dict
            Raw geo fields (country, city, lat, lon).
        """
        raise NotImplementedError

    def _calculate_reputation(self, ip: str) -> float:
        """Compute a reputation score for *ip* (0.0 = malicious, 100.0 = clean).

        Parameters
        ----------
        ip:
            The IP address.

        Returns
        -------
        float
            Reputation score.
        """
        raise NotImplementedError
