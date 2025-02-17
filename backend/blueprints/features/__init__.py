from flask import Blueprint

features_bp = Blueprint("features", __name__)

from . import routes  # Import routes AFTER Blueprint is created
