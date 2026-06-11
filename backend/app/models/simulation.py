"""NetGuard AI — Simulation Result model.

Stores the configuration, output and alerts of attack-simulation
scenarios run by the attack-simulation engine.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from app.extensions import db


class SimulationResult(db.Model):  # type: ignore[name-defined]
    """Records a completed attack-simulation run."""

    __tablename__ = "simulation_results"

    id: int = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scenario_type: str = db.Column(db.String(50), nullable=False, index=True)
    configuration: Dict[str, Any] = db.Column(db.JSON, nullable=False)
    results: Dict[str, Any] = db.Column(db.JSON, nullable=False)
    alerts_generated: List[Dict[str, Any]] = db.Column(db.JSON, nullable=False)
    duration_seconds: int = db.Column(db.Integer, nullable=False)
    started_at: datetime = db.Column(db.DateTime, nullable=False)
    completed_at: datetime = db.Column(db.DateTime, nullable=False)

    # ── Serialisation ─────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dictionary."""
        return {
            "id": self.id,
            "scenario_type": self.scenario_type,
            "configuration": self.configuration,
            "results": self.results,
            "alerts_generated": self.alerts_generated,
            "duration_seconds": self.duration_seconds,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }

    def __repr__(self) -> str:
        return f"<SimulationResult {self.id} {self.scenario_type} ({self.duration_seconds}s)>"
