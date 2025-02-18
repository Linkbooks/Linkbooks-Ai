import logging
from flask import request, jsonify
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
        
        
# ----------------- Debug Load Environment Variables ----------------- #
def get_debug_env():
    """
    Retrieves and logs environment variables safely.
    ⚠️ Only allowed in development mode!
    """
    if not os.getenv("FLASK_ENV") == "development":
        return jsonify({"error": "Not authorized."}), 403

    variables = {
        "SUPABASE_URL": os.getenv('SUPABASE_URL'),
        "SUPABASE_KEY": os.getenv('SUPABASE_KEY'),
        "QB_SANDBOX_CLIENT_ID": os.getenv('QB_SANDBOX_CLIENT_ID'),
        "QB_SANDBOX_CLIENT_SECRET": os.getenv('QB_SANDBOX_CLIENT_SECRET'),
        "QB_PROD_CLIENT_ID": os.getenv('QB_PROD_CLIENT_ID'),
        "QB_PROD_CLIENT_SECRET": os.getenv('QB_PROD_CLIENT_SECRET'),
        "FLASK_SECRET_KEY": os.getenv('FLASK_SECRET_KEY'),
        "OPENAI_API_KEY": os.getenv('OPENAI_API_KEY'),
    }

    logging.info(f"Environment variables: {variables}")

    return jsonify({
        key: ("*****" if "KEY" in key or "SECRET" in key else value)
        for key, value in variables.items()
    }), 200