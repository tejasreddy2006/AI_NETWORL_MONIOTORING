"""NetGuard AI — Flask extension instances.

All extensions are instantiated here *without* an app so they can be
imported freely.  The ``init_extensions`` function binds them to a
concrete Flask app during the factory phase.
"""

from __future__ import annotations

from typing import Optional

from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy

# ── Extension singletons ─────────────────────────────────────────────
db: SQLAlchemy = SQLAlchemy()
migrate: Migrate = Migrate()
socketio: SocketIO = SocketIO(cors_allowed_origins="*", async_mode="eventlet")
cors: CORS = CORS()
limiter: Limiter = Limiter(key_func=get_remote_address)

# Redis client — initialised lazily inside ``init_extensions``.
redis_client: Optional[object] = None


def init_extensions(app: Flask) -> None:
    """Bind every extension to *app*.

    Parameters
    ----------
    app:
        The Flask application created by the factory.
    """
    global redis_client  # noqa: PLW0603

    db.init_app(app)
    migrate.init_app(app, db)
    socketio.init_app(app)
    cors.init_app(app, resources={r"/api/*": {"origins": app.config.get("CORS_ORIGINS", "*")}})
    limiter.init_app(app)

    # Attempt to connect to Redis; fall back to None on failure.
    try:
        import redis

        redis_client = redis.Redis.from_url(
            app.config.get("REDIS_URL", "redis://localhost:6379/0"),
            decode_responses=True,
        )
        redis_client.ping()
        app.logger.info("Redis connection established.")
    except Exception:  # noqa: BLE001
        redis_client = None
        app.logger.warning("Redis unavailable — falling back to in-memory caching.")
