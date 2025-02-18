from . import dashboard_bp
import logging
from datetime import datetime
from flask import Blueprint, request, jsonify, redirect, send_from_directory, current_app
import jwt
import uuid
from jwt import DecodeError, ExpiredSignatureError
from extensions import supabase
from config import Config


# ------------------------------------------
# Dashboard
# ------------------------------------------
@dashboard_bp.route('/dashboard', methods=['GET'])
def dashboard():
    """
    Dashboard now serves the Svelte frontend.
    Actual data (QuickBooks status & ChatGPT sessions) is fetched via API.
    """
    token = request.cookies.get('session_token')
    if not token:
        return redirect('/login')

    return send_from_directory(current_app.static_folder, "index.html")

@dashboard_bp.route('/api/dashboard-data', methods=['GET'])
def get_dashboard_data():
    """
    API endpoint for fetching dashboard-related data.
    Includes QuickBooks connection status & ChatGPT sessions.
    """
    try:
        # Get session token
        token = request.cookies.get('session_token')
        if not token:
            return jsonify({"error": "User not authenticated"}), 401

        try:
            decoded = jwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])
            user_id = decoded.get("user_id")
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return jsonify({"error": "Invalid or expired token"}), 401

        # ✅ QuickBooks Status Check
        quickbooks_login_needed = True
        response = supabase.table("quickbooks_tokens").select("access_token", "token_expiry").eq("user_id", user_id).execute()
        if response.data and response.data[0].get("access_token"):
            expiry = response.data[0].get("token_expiry")
            if expiry and datetime.utcnow() < datetime.fromisoformat(expiry):
                quickbooks_login_needed = False  # ✅ QuickBooks is connected

        # ✅ Fetch active ChatGPT sessions
        chatgpt_sessions = []
        session_response = supabase.table("chatgpt_oauth_states") \
            .select("chat_session_id, expiry, created_at") \
            .eq("user_id", user_id) \
            .execute()
        
        if session_response.data:
            chatgpt_sessions = [
                {
                    "chatSessionId": str(session["chat_session_id"]) if isinstance(session["chat_session_id"], uuid.UUID) else session["chat_session_id"],
                    "expiry": session["expiry"],
                    "createdAt": session.get("created_at")
                }
                for session in session_response.data
                if session.get("chat_session_id")
            ]

        # ✅ Return data as JSON
        return jsonify({
            "success": True,
            "quickbooks_login_needed": quickbooks_login_needed,
            "chatSessionId": request.args.get('chatSessionId', ""),  # Pass chatSessionId from URL
            "chatgpt_sessions": chatgpt_sessions
        }), 200

    except Exception as e:
        logging.error(f"Error in /api/dashboard-data: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


# --------------------------------------------
#        ChatGPT Session Status Route
# --------------------------------------------
@dashboard_bp.route('/session/status', methods=['GET'])
def get_session_status():
    """
    Checks if a ChatGPT session is active by looking for tokens in chatgpt_tokens.
    """
    try:
        chat_session_id = request.args.get('chatSessionId')
        if not chat_session_id:
            return jsonify({"authenticated": False, "message": "chatSessionId is required"}), 400

        response = supabase.table("chatgpt_tokens").select("*").eq("chat_session_id", chat_session_id).execute()
        if not response.data:
            logging.warning(f"No tokens found for chatSessionId {chat_session_id}.")
            return jsonify({"authenticated": False, "message": "No tokens found. Please log in."}), 401

        tokens = response.data[0]
        expiry = datetime.fromisoformat(tokens['expiry'])
        if datetime.utcnow() > expiry:
            logging.info(f"Access token for chatSessionId {chat_session_id} expired.")
            return jsonify({"authenticated": False, "message": "Session expired. Please reauthenticate."}), 401

        logging.info(f"Session {chat_session_id} is active and authenticated.")
        return jsonify({"authenticated": True, "message": "Session is active."}), 200

    except Exception as e:
        logging.error(f"Error in /session/status: {e}", exc_info=True)
        return jsonify({"authenticated": False, "message": "An unexpected error occurred. Try again later."}), 500
