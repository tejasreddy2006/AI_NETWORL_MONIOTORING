"""
NetGuard AI — ML Service.

Provides business logic for machine-learning predictions,
model management, and on-demand training triggers.
"""

from __future__ import annotations

from typing import Any, Optional

from flask import current_app

from app.extensions import db
from app.models.prediction import MLModel, MLPrediction


def get_predictions(
    prediction_type: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Return ML predictions, optionally filtered by type.

    Parameters
    ----------
    prediction_type : str, optional
        Filter by prediction category (e.g. ``'traffic_forecast'``).

    Returns
    -------
    list[dict]
        Serialised prediction records.
    """
    query = MLPrediction.query.order_by(MLPrediction.created_at.desc())
    if prediction_type:
        query = query.filter(MLPrediction.prediction_type == prediction_type)
    results = query.all()

    # Self-healing fallback: run dynamic predictions if none exist
    if not results:
        engine = current_app.extensions.get("ml_prediction")
        if engine:
            try:
                engine.predict()
                # Query again after generating predictions
                results = query.all()
            except Exception as e:
                current_app.logger.error(f"Dynamic prediction generation failed: {e}")

    return [p.to_dict() for p in results]


def get_models() -> list[dict[str, Any]]:
    """Return metadata for all registered ML models.

    Returns
    -------
    list[dict]
        Each element contains model name, algorithm, metrics, path, etc.
    """
    return [m.to_dict() for m in MLModel.query.all()]


def trigger_training() -> dict[str, Any]:
    """Kick off a model (re-)training job.

    Returns
    -------
    dict
        ``{"status": str, "message": str}``
    """
    engine = current_app.extensions.get("ml_prediction")
    if not engine:
        return {
            "status": "failed",
            "message": "ML Prediction Engine not registered.",
        }

    try:
        results = engine.train_models()
        if "error" in results:
            return {
                "status": "failed",
                "message": f"Training failed: {results['error']}",
            }
        return {
            "status": "success",
            "message": "Models trained successfully.",
            "metrics": results,
        }
    except Exception as exc:
        return {
            "status": "failed",
            "message": f"Training failed: {str(exc)}",
        }


def get_latest_predictions() -> dict[str, Any]:
    """Return the most recent prediction results across all models.

    Returns
    -------
    dict
        Keyed by model/type with their latest prediction payloads.
    """
    preds = MLPrediction.query.order_by(MLPrediction.created_at.desc()).all()

    # Self-healing fallback: run dynamic predictions if none exist
    if not preds:
        engine = current_app.extensions.get("ml_prediction")
        if engine:
            try:
                engine.predict()
                preds = MLPrediction.query.order_by(MLPrediction.created_at.desc()).all()
            except Exception as e:
                current_app.logger.error(f"Dynamic prediction generation failed: {e}")

    latest: dict[str, Any] = {}
    for p in preds:
        if p.prediction_type not in latest:
            latest[p.prediction_type] = p.to_dict()
    return latest

