import logging
from flask import Blueprint, request, jsonify, session, render_template
from extensions import supabase
from utils.security_utils import token_required


user_bp = Blueprint('user', __name__, url_prefix='/user')

# Import routes AFTER blueprint is defined to prevent circular imports

# ------------------------------------------------------------------------------
# User Profile and Settings Routes
# ------------------------------------------------------------------------------
# ------------------------------------------
# User Profile API Route (Now Returns JSON)
# ------------------------------------------
@user_bp.route('/user_profile', methods=['GET'])
@token_required  # ✅ Ensures authentication
def user_profile():
    try:
        user_id = request.user_id  # ✅ Get user_id from token_required decorator
        
        # ✅ Fetch user data from Supabase
        user_data = supabase.table("user_profiles").select("*").eq("id", user_id).execute()

        if not user_data.data:
            return jsonify({"error": "User not found"}), 404

        return jsonify(user_data.data[0])  # ✅ Send JSON response instead of rendering HTML

    except Exception as e:
        logging.error(f"Error in user_profile: {e}")
        return jsonify({"error": "Failed to load user profile"}), 500


@user_bp.route('/settings')
@token_required  # Add authentication check
def settings():
    try:
        settings_type = request.args.get('type', 'general')  # Get settings type from URL
        return render_template('settings.html', settings_type=settings_type)
    except Exception as e:
        logging.error(f"Error in settings: {e}")
        return render_template('error.html', error="Failed to load settings"), 500
