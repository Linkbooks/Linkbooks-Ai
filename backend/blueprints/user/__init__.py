from flask import Blueprint

user_bp = Blueprint("user", __name__)

from . import routes  # Import routes AFTER Blueprint is created
