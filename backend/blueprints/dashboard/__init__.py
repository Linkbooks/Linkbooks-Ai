from flask import Blueprint

dashboard_bp = Blueprint("dashboard", __name__)

from . import routes  # Import routes AFTER Blueprint is created
