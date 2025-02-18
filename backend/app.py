from flask import Flask, render_template, redirect, request, Response, stream_with_context, make_response, url_for, jsonify, session, send_from_directory, abort
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from config import Config
from extensions import limiter, socketio, cors
from blueprints.auth import auth_bp
from blueprints.quickbooks import quickbooks_bp
from blueprints.chat import chat_bp
from blueprints.payments import payments_bp
from blueprints.legal import legal_bp
from blueprints.openai import openai_bp
from blueprints.dashboard import dashboard_bp
from blueprints.svelte_link import svelte_link_bp
from utils.logging_utils import log_request_info
from utils.logging_utils import setup_logging
from utils.security_utils import verify_token
from utils.logging_utils import register_request_logging
from utils.scheduler_utils import start_scheduler
from utils.filters import datetimeformat
from utils.email_utils import init_mail



def create_app():
    """Factory function to create Flask app"""
    app = Flask(
        __name__,
        static_folder="../frontend/.svelte-kit/output/client",  # ✅ Svelte static files
        static_url_path="/",  
        template_folder="templates"
    )
    
    # ✅ Load Config
    app.config.from_object(Config)
    
    # ✅ Raise an error if SECRET_KEY is missing
    if not app.config["SECRET_KEY"]:
        raise RuntimeError("Missing FLASK_SECRET_KEY environment variable.")
    
    # ✅ Initialize logging
    setup_logging()
    
    # ✅ Serve Flask's static files separately
    app.static_folder = "static"  # ✅ Ensures Flask still serves /backend/static
    
    # ✅ Register logging only in development mode
    register_request_logging(app)
    
    # ✅ Initialize the Scheduler
    start_scheduler()  # Ensure scheduled jobs start when app runs

    # Initialize Extensions
    cors.init_app(app, origins=Config.ALLOWED_CORS_ORIGINS, allow_headers=["Content-Type", "Authorization"])
    jwt = JWTManager(app)
    limiter.init_app(app)
    socketio.init_app(app)
    
    # Initialize Utils
    app.jinja_env.filters['datetimeformat'] = datetimeformat
    init_mail(app)

    # Register Blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(quickbooks_bp, url_prefix='/quickbooks')
    app.register_blueprint(chat_bp, url_prefix='/chat')
    app.register_blueprint(payments_bp, url_prefix='/payments')
    app.register_blueprint(openai_bp, url_prefix="/chatgpt")
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
    app.register_blueprint(legal_bp, url_prefix='/legal')
    app.register_blueprint(svelte_link_bp, url_prefix='/legal')
    





    return app


if __name__ == "__main__":
    app = create_app()
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
