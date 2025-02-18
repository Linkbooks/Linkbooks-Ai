# 📌 blueprints/general/routes.py
from flask import Blueprint, render_template, send_from_directory, abort

# Create Blueprint
svelte_link_bp = Blueprint('svelte_link', __name__, url_prefix='/svelte_link')

# --------------------- Svelte API ------------------------ #

# ✅ Serve Static Assets for Svelte
@svelte_link_bp.route('/assets/<path:path>')
def serve_static_assets(path):
    return send_from_directory("static/assets", path)

# ✅ Serve Svelte frontend files
@svelte_link_bp.route("/", defaults={"path": ""})
@svelte_link_bp.route("/<path:path>")
def serve_svelte_frontend(path):
    if path.startswith("api/"):
        abort(404)  # Stops Flask from hijacking API calls

    flask_pages = ["login", "dashboard"]
    if path in flask_pages:
        return render_template(f"{path}.html")

    return send_from_directory("static", "index.html")