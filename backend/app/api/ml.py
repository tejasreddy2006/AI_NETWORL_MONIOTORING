"""
NetGuard AI — ML API Blueprint.

Exposes REST endpoints for ML predictions, model listing,
and training trigger.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.services import ml_service

bp = ml_bp = Blueprint("ml", __name__)


@bp.route("/predictions", methods=["GET"])
def get_predictions():
    """Return ML predictions, optionally filtered by type.

    Query Parameters
    ----------------
    prediction_type : str
    """
    try:
        prediction_type: str | None = request.args.get("prediction_type")
        result = ml_service.get_predictions(prediction_type=prediction_type)
        return jsonify(result), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/train", methods=["POST"])
def trigger_training():
    """Trigger an asynchronous model (re-)training job."""
    try:
        result = ml_service.trigger_training()
        return jsonify(result), 202
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/models", methods=["GET"])
def list_models():
    """Return metadata for all registered ML models."""
    try:
        result = ml_service.get_models()
        return jsonify(result), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
