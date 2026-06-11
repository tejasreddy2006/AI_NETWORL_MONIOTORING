"""NetGuard AI — ML Prediction Engine Tests.

Tests feature extraction, training logic, model persistence, and prediction generation.
"""

import os
import pytest
from datetime import datetime
from app import create_app
from app.extensions import db
from app.models.prediction import MLModel, MLPrediction
from app.engines.ml_prediction import MLPredictionEngine


@pytest.fixture
def app():
    """Create Flask application configured for testing."""
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        # Set a temporary ML models directory inside the app instance folder
        app.config["ML_MODELS_DIR"] = os.path.join(app.instance_path, "ml_models_test")
        yield app
        db.session.remove()
        db.drop_all()
        # Clean up created model directory
        if os.path.exists(app.config["ML_MODELS_DIR"]):
            import shutil
            shutil.rmtree(app.config["ML_MODELS_DIR"])


@pytest.fixture
def engine(app):
    """Create a MLPredictionEngine instance."""
    return MLPredictionEngine(app)


def test_feature_extraction(app, engine):
    """Test that feature extraction generates a valid DataFrame with all columns."""
    with app.app_context():
        df = engine._extract_features()
        
        # Checking dataframe properties
        assert df is not None
        assert not df.empty
        assert len(df) == 144  # Default 24 hours of 10-minute intervals
        
        expected_cols = {
            "timestamp", "total_bytes", "packet_count", "tcp_ratio", 
            "udp_ratio", "alert_count", "critical_alert_count", "avg_health_score"
        }
        assert expected_cols.issubset(set(df.columns))


def test_model_training_and_registry(app, engine):
    """Test that model training runs, persists models to disk, and updates DB registry."""
    with app.app_context():
        results = engine.train_models()
        
        # Verify result structure
        assert "error" not in results
        assert "bandwidth_model" in results
        assert "congestion_model" in results
        assert "spike_model" in results
        assert "outage_model" in results
        
        assert results["bandwidth_model"]["success"] is True
        assert results["congestion_model"]["success"] is True
        assert results["spike_model"]["success"] is True
        assert results["outage_model"]["success"] is True
        
        # Verify persistence on disk
        models_dir = app.config["ML_MODELS_DIR"]
        assert os.path.exists(models_dir)
        assert os.path.exists(os.path.join(models_dir, "bandwidth.joblib"))
        assert os.path.exists(os.path.join(models_dir, "congestion.joblib"))
        assert os.path.exists(os.path.join(models_dir, "spike.joblib"))
        assert os.path.exists(os.path.join(models_dir, "outage.joblib"))

        # Verify DB registry entry
        db_models = MLModel.query.all()
        assert len(db_models) == 4
        model_names = [m.model_name for m in db_models]
        assert "bandwidth_model" in model_names
        assert "congestion_model" in model_names
        assert "spike_model" in model_names
        assert "outage_model" in model_names


def test_prediction_generation(app, engine):
    """Test that predict() generates, logs, and returns prediction dicts."""
    with app.app_context():
        # First train the models so they exist
        engine.train_models()
        
        # Now run predictions
        preds = engine.predict()
        
        # Verify output dict
        assert "bandwidth" in preds
        assert "congestion" in preds
        assert "anomaly" in preds
        assert "outage" in preds
        
        assert "predicted_bytes" in preds["bandwidth"]
        assert "congestion_probability" in preds["congestion"]
        assert "is_spike" in preds["anomaly"]
        assert "outage_probability" in preds["outage"]
        
        # Verify database logs
        db_preds = MLPrediction.query.all()
        assert len(db_preds) == 4
        types = [p.prediction_type for p in db_preds]
        assert "bandwidth" in types
        assert "congestion" in types
        assert "anomaly" in types
        assert "outage" in types
