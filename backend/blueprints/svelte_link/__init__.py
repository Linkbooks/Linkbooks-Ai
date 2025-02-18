from flask import Blueprint

svelte_link_bp = Blueprint("svelte_link", __name__)

from . import routes  # Import routes AFTER Blueprint is created