"""NetGuard AI — ML Prediction models.

Stores ML model metadata and their predictions (bandwidth forecasts,
congestion likelihood, spike detection, outage risk).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from app.extensions import db


class MLPrediction(db.Model):  # type: ignore[name-defined]
    """Stores an individual prediction emitted by an ML model."""

    __tablename__ = "ml_predictions"

    id: int = db.Column(db.Integer, primary_key=True, autoincrement=True)
    model_name: str = db.Column(db.String(100), nullable=False, index=True)
    prediction_type: str = db.Column(db.String(50), nullable=False, index=True)
    prediction_data: Dict[str, Any] = db.Column(db.JSON, nullable=False)
    confidence: float = db.Column(db.Float, nullable=False)
    prediction_for: datetime = db.Column(db.DateTime, nullable=False)
    created_at: datetime = db.Column(db.DateTime, default=datetime.utcnow)

    # ── Serialisation ─────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dictionary."""
        return {
            "id": self.id,
            "model_name": self.model_name,
            "prediction_type": self.prediction_type,
            "prediction_data": self.prediction_data,
            "confidence": self.confidence,
            "prediction_for": self.prediction_for.isoformat() if self.prediction_for else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<MLPrediction {self.id} {self.model_name} conf={self.confidence:.2f}>"


class MLModel(db.Model):  # type: ignore[name-defined]
    """Registry of trained ML models and their metadata."""

    __tablename__ = "ml_models"

    id: int = db.Column(db.Integer, primary_key=True, autoincrement=True)
    model_name: str = db.Column(db.String(100), unique=True, nullable=False)
    algorithm: str = db.Column(db.String(100), nullable=False)
    metrics: Optional[Dict[str, Any]] = db.Column(db.JSON, nullable=True)
    model_path: str = db.Column(db.String(500), nullable=False)
    trained_at: datetime = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    training_samples: int = db.Column(db.Integer, nullable=False, default=0)

    # ── Serialisation ─────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dictionary."""
        return {
            "id": self.id,
            "model_name": self.model_name,
            "algorithm": self.algorithm,
            "metrics": self.metrics,
            "model_path": self.model_path,
            "trained_at": self.trained_at.isoformat() if self.trained_at else None,
            "training_samples": self.training_samples,
        }

    def __repr__(self) -> str:
        return f"<MLModel {self.id} {self.model_name} ({self.algorithm})>"
