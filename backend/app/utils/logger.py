"""
NetGuard AI — Logging Configuration.

Provides ``setup_logger`` to configure application-wide logging
and ``get_logger`` as a convenience factory for named loggers.
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from typing import Optional

from flask import Flask


def setup_logger(app: Flask) -> logging.Logger:
    """Configure the root application logger.

    * Sets the log level from ``app.config['LOG_LEVEL']`` (default ``INFO``).
    * Adds a ``RotatingFileHandler`` writing to ``logs/netguard.log``.
    * Adds a ``StreamHandler`` for console output.
    * Uses a structured format: ``[%(asctime)s] %(levelname)s in %(module)s: %(message)s``.

    Parameters
    ----------
    app : Flask
        The Flask application instance (used to read config).

    Returns
    -------
    logging.Logger
        The configured root logger.
    """
    log_level: str = app.config.get("LOG_LEVEL", "INFO")
    log_format: str = "[%(asctime)s] %(levelname)s in %(module)s: %(message)s"
    formatter: logging.Formatter = logging.Formatter(log_format)

    logger: logging.Logger = logging.getLogger("netguard")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # --- File handler ---
    log_dir: str = os.path.join(app.root_path, "..", "logs")
    os.makedirs(log_dir, exist_ok=True)

    file_handler: RotatingFileHandler = RotatingFileHandler(
        os.path.join(log_dir, "netguard.log"),
        maxBytes=10_485_760,  # 10 MB
        backupCount=5,
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # --- Console handler ---
    console_handler: logging.StreamHandler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the ``netguard`` namespace.

    Parameters
    ----------
    name : str
        Logger name, typically ``__name__`` of the calling module.

    Returns
    -------
    logging.Logger
    """
    return logging.getLogger(f"netguard.{name}")
