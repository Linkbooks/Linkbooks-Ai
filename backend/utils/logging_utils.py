import logging
from flask import request
from config import Config
import os


# ------------------ Logging Setup ------------------- #

# ✅ Set log level based on environment variable
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def setup_logging():
    """Initializes logging settings for the application."""
    logging.info(f"Running in {os.getenv('FLASK_ENV', 'unknown')} mode.")


# ----------- Log Requests to Backend Helper ----------- #

def log_request_info():
    """Logs each incoming request to the backend with IP address and request details."""
    logging.info(f"📩 {request.remote_addr} - {request.method} {request.path}")


def register_request_logging(app):
    """Attaches the request logging function to the Flask app."""
    if Config.DEBUG:  # ✅ Only log in development mode
        app.before_request(log_request_info)