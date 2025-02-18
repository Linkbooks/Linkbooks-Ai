from flask import Blueprint
import logging

logging.warning("🔍 Loading auth blueprint __init__...")

auth_bp = Blueprint("auth", __name__)

logging.warning("🔍 Created auth_bp, now importing routes...")

from . import routes  # Import routes AFTER Blueprint is created

logging.warning("🔍 Done importing auth routes.")