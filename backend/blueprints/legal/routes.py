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