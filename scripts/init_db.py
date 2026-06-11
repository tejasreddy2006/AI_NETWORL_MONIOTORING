#!/usr/bin/env python3
"""
Initialize the NetGuard AI database.
Creates all tables defined in the SQLAlchemy models.

Usage:
    python scripts/init_db.py
"""

import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app import create_app, db


def init_database():
    """Create all database tables."""
    app = create_app()

    with app.app_context():
        # Import all models to ensure they are registered
        from app.models import (
            Packet, Alert, Device, DeviceLink,
            HealthScore, GeoTraffic, MLPrediction, MLModel,
            SimulationResult, AIConversation
        )

        # Create all tables
        db.create_all()

        print("=" * 50)
        print("[OK] Database initialized successfully!")
        print("=" * 50)
        print(f"  Database: {app.config.get('SQLALCHEMY_DATABASE_URI', 'N/A')}")
        print(f"  Tables created for all models")
        print("=" * 50)


if __name__ == '__main__':
    init_database()
