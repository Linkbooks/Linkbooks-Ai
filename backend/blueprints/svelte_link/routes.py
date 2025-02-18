# 📌 blueprints/svelte_link/routes.py
from . import svelte_link_bp
from flask import Blueprint, render_template, send_from_directory, abort



# --------------------- Svelte API ------------------------ #

# ✅ Serve Static Assets for Svelte
@svelte_link_bp.route('/assets/<path:path>')
def serve_static_assets(path):
    return send_from_directory("static/assets", path)

# ✅ Serve Svelte frontend files
@svelte_link_bp.route("/", defaults={"path": ""})
@svelte_link_bp.route("/<path:path>")
def serve_svelte_frontend(path):
    # If the path starts with any known blueprint prefix, skip serving Svelte
    blueprint_prefixes = ["auth", "quickbooks", "chat", "payments", "chatgpt", "legal"]
    if any(path.startswith(prefix) for prefix in blueprint_prefixes):
        abort(404)  # Let the correct blueprint handle it

    flask_pages = ["login", "dashboard"]
    if path in flask_pages:
        return render_template(f"{path}.html")

    return send_from_directory("static", "index.html")