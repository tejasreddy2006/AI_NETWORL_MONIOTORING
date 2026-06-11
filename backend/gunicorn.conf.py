"""Gunicorn configuration for production deployment."""
import os

bind = f"0.0.0.0:{os.environ.get('PORT', '5000')}"
workers = 1  # Single worker for SocketIO
worker_class = 'eventlet'
timeout = 120
keepalive = 5
errorlog = '-'
accesslog = '-'
loglevel = 'info'
