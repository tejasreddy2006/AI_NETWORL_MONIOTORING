#!/usr/bin/env python3
"""
Train ML models for NetGuard AI threat detection.

This script triggers training of all ML models:
  - Anomaly detection (Isolation Forest)
  - Traffic classification (Random Forest)
  - DDoS prediction model

Usage:
    python scripts/train_models.py
"""

import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app import create_app
from app.engines.ml_prediction import MLPredictionEngine


def train():
    """Train all ML models."""
    app = create_app()

    with app.app_context():
        print("=" * 60)
        print("[ROBOT] NetGuard AI - ML Model Training")
        print("=" * 60)
        print()

        engine = MLPredictionEngine(app)

        print("[DATA] Fetching training data from database...")
        print()

        results = engine.train_models()

        print()
        print("=" * 60)
        print("[SUMMARY] Training Results:")
        print("=" * 60)

        for model_name, result in results.items():
            status = "[OK]" if result.get('success') else "[FAIL]"
            print(f"  {status} {model_name}:")
            if result.get('accuracy'):
                print(f"      Accuracy:  {result['accuracy']:.4f}")
            if result.get('f1_score'):
                print(f"      F1 Score:  {result['f1_score']:.4f}")
            if result.get('samples'):
                print(f"      Samples:   {result['samples']}")
            if result.get('error'):
                print(f"      Error:     {result['error']}")
            print()

        print("=" * 60)
        print("[OK] Training complete! Models saved to ml_models/")
        print("=" * 60)


if __name__ == '__main__':
    train()
