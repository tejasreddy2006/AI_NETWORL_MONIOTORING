"""
NetGuard AI — Simulation Service.

Provides business logic for running network attack/defence simulations,
listing available scenarios, and retrieving results.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Optional

from app.extensions import db
from app.models.simulation import SimulationResult


def run_simulation(
    scenario_type: str,
    config: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Execute a network simulation for the given scenario.

    Parameters
    ----------
    scenario_type : str
        Identifier for the scenario (e.g. ``'ddos'``, ``'port_scan'``).
    config : dict, optional
        Additional scenario-specific configuration.

    Returns
    -------
    dict
        ``{"result_id": int, "status": str, "summary": str}``
    """
    from app.engines.attack_simulation import AttackSimulationEngine

    engine = AttackSimulationEngine()
    try:
        # Run simulation engine
        sim_data = engine.run_simulation(scenario_type, config)
        duration = sim_data.get("duration", 5)

        # Record simulation run
        db_result = SimulationResult(
            scenario_type=scenario_type,
            configuration=config or {},
            results=sim_data.get("results", {}),
            alerts_generated=sim_data.get("alerts_generated", []),
            duration_seconds=duration,
            started_at=datetime.utcnow() - timedelta(seconds=duration),
            completed_at=datetime.utcnow(),
        )

        db.session.add(db_result)
        db.session.commit()

        return {
            "result_id": db_result.id,
            "status": "success",
            "summary": f"Simulation of {scenario_type} completed successfully.",
        }
    except Exception as exc:
        return {
            "status": "failed",
            "summary": f"Simulation failed: {str(exc)}",
        }


def get_scenarios() -> list[dict[str, Any]]:
    """List all available simulation scenarios.

    Returns
    -------
    list[dict]
        Each element: ``{"id": str, "name": str, "description": str}``
    """
    from app.engines.attack_simulation import AttackSimulationEngine

    engine = AttackSimulationEngine()
    return engine.get_scenarios()


def get_simulation_result(result_id: int) -> dict[str, Any]:
    """Fetch a single simulation result by ID.

    Parameters
    ----------
    result_id : int
        Primary key of the simulation result.

    Returns
    -------
    dict
        Full simulation result payload.

    Raises
    ------
    ValueError
        If no result with the given ID exists.
    """
    res = SimulationResult.query.get(result_id)
    if not res:
        raise ValueError(f"Simulation result with ID {result_id} not found.")
    return res.to_dict()


def get_simulation_history() -> list[dict[str, Any]]:
    """Return all past simulation results in reverse chronological order.

    Returns
    -------
    list[dict]
        Serialised simulation result records.
    """
    history = SimulationResult.query.order_by(SimulationResult.completed_at.desc()).all()
    return [h.to_dict() for h in history]
