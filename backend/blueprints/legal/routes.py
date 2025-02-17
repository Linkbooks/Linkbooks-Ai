import logging
import os
from flask import Blueprint, render_template, request, jsonify

legal_bp = Blueprint('legal', __name__, url_prefix='/legal')

# ------------------------------------------
# 📜 Legal Routes: EULA, Privacy Policy, Debug
# ------------------------------------------

@legal_bp.route('/eula', methods=['GET'])
def eula():
    """Serves the End User License Agreement (EULA) page."""
    return render_template('eula.html')

@legal_bp.route('/privacy-policy', methods=['GET'])
def privacy_policy():
    """Serves the Privacy Policy page."""
    return render_template('privacy_policy.html')

@legal_bp.route('/debug-env', methods=['GET'])
def debug_env():
    """
    Debugging route to check environment variables.
    ⚠️ **Only allowed in development mode!**
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

    return {
        key: ("*****" if "KEY" in key or "SECRET" in key else value)
        for key, value in variables.items()
    }, 200


@legal_bp.before_request
def log_request_info():
    """Logs all incoming requests to this blueprint."""
    logging.info(f"📩 Incoming request: {request.method} {request.path}")
