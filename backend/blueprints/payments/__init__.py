from flask import Blueprint

payments_bp = Blueprint("payments", __name__)

# Import routes AFTER blueprint is defined to prevent circular imports
from . import routes
