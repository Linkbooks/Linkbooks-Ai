from flask import Blueprint

quickbooks_bp = Blueprint("quickbooks", __name__)

from . import routes  # Import routes AFTER Blueprint is created
