from flask import Flask, render_template, redirect, request, Response, stream_with_context, make_response, url_for, jsonify, Flask, session, send_from_directory, abort
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from config import Config
from extensions import db, limiter, socketio
from blueprints.auth import auth_bp
from blueprints.quickbooks import quickbooks_bp
from blueprints.chat import chat_bp
from blueprints.payments import payments_bp
from blueprints.reports import reports_bp
from blueprints.openai.routes import openai_bp
from blueprints.dashboard.routes import dashboard_bp


def create_app():
    """Factory function to create Flask app"""
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize Extensions
    CORS(app, supports_credentials=True)
    db.init_app(app)
    jwt = JWTManager(app)
    limiter.init_app(app)
    socketio.init_app(app)

    # Register Blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(quickbooks_bp, url_prefix='/quickbooks')
    app.register_blueprint(chat_bp, url_prefix='/chat')
    app.register_blueprint(payments_bp, url_prefix='/payments')
    app.register_blueprint(reports_bp, url_prefix='/reports')
    app.register_blueprint(chatgpt_bp, url_prefix="/chatgpt")
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')

    return app




# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

# --------------------- Svelte API ------------------------ #

# ✅ Serve Static Assets for Svelte
@app.route('/assets/<path:path>')
def serve_static_assets(path):
    return send_from_directory(os.path.join(app.static_folder, "assets"), path)

# ✅ Serve Svelte frontend files
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_svelte_frontend(path):
    # ✅ If the request is for an API, don’t interfere
    if path.startswith("api/"):
        abort(404)  # Stops Flask from hijacking API calls

    # ✅ If the request is for a Flask template, return the Flask page
    flask_pages = ["login", "dashboard"]
    if path in flask_pages:
        return render_template(f"{path}.html")

    # ✅ Otherwise, serve the Svelte frontend
    return send_from_directory(app.static_folder, "index.html")




if __name__ == "__main__":
    app = create_app()
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
