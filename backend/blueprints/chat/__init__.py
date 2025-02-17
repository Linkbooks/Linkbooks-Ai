from flask import Blueprint

chat_bp = Blueprint('chat', __name__, url_prefix='/chat')

from . import routes  # Import routes AFTER Blueprint is created
