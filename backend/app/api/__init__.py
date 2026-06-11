"""
NetGuard AI — API Blueprints Package.

Centralises blueprint registration for all versioned API endpoints.
"""

from __future__ import annotations

from flask import Flask


def register_blueprints(app: Flask) -> None:
    """Import and register every API blueprint on the Flask application.

    All blueprints are registered under the ``/api/v1`` URL prefix.

    Parameters
    ----------
    app : Flask
        The Flask application instance.
    """
    from app.api.ai import ai_bp
    from app.api.alerts import alerts_bp
    from app.api.health import health_bp
    from app.api.ml import ml_bp
    from app.api.packets import packets_bp
    from app.api.simulation import simulation_bp
    from app.api.system import system_bp
    from app.api.threat_intel import threat_intel_bp
    from app.api.topology import topology_bp

    app.register_blueprint(packets_bp, url_prefix="/api/v1/packets")
    app.register_blueprint(alerts_bp, url_prefix="/api/v1/alerts")
    app.register_blueprint(topology_bp, url_prefix="/api/v1/topology")
    app.register_blueprint(ml_bp, url_prefix="/api/v1/ml")
    app.register_blueprint(health_bp, url_prefix="/api/v1/health")
    app.register_blueprint(threat_intel_bp, url_prefix="/api/v1/threatintel")
    app.register_blueprint(simulation_bp, url_prefix="/api/v1/simulation")
    app.register_blueprint(ai_bp, url_prefix="/api/v1/ai")
    app.register_blueprint(system_bp, url_prefix="/api/v1/system")
