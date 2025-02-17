from flask import Blueprint

legal_bp = Blueprint("legal", __name__)

from . import routes  # Import routes AFTER Blueprint is created
