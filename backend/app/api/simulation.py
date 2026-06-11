"""
NetGuard AI — Simulation API Blueprint.

Exposes REST endpoints for running network simulations,
listing scenarios, and retrieving results.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.services import simulation_service

bp = simulation_bp = Blueprint("simulation", __name__)


@bp.route("/run", methods=["POST"])
def run_simulation():
    """Run a network simulation.

    JSON Body
    ---------
    scenario_type : str
        The simulation scenario identifier.
    config : dict, optional
        Additional scenario-specific configuration.
    """
    try:
        data: dict = request.get_json(force=True)
        scenario_type: str = data.get("scenario_type", "")
        config: dict | None = data.get("config")

        if not scenario_type:
            return jsonify({"error": "scenario_type is required"}), 400

        result = simulation_service.run_simulation(scenario_type=scenario_type, config=config)
        return jsonify(result), 202
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/scenarios", methods=["GET"])
def list_scenarios():
    """List all available simulation scenarios."""
    try:
        result = simulation_service.get_scenarios()
        return jsonify(result), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/results/<int:result_id>", methods=["GET"])
def get_result(result_id: int):
    """Fetch a single simulation result.

    Parameters
    ----------
    result_id : int
        Result primary key (URL path parameter).
    """
    try:
        result = simulation_service.get_simulation_result(result_id)
        return jsonify(result), 200
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
