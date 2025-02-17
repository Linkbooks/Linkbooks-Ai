from flask import Blueprint

openai_bp = Blueprint("openai", __name__)

from . import routes  # Import routes AFTER Blueprint is created
