from . import auth_bp
import logging
import jwt
from flask import Blueprint, request, jsonify, render_template, redirect, url_for, session, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
from supabase import create_client, AuthApiError
from bcrypt import checkpw
from config import get_config, Config
from extensions import limiter, supabase
from urllib.parse import quote
from .helpers import generate_session_token
from blueprints.quickbooks.helpers import revoke_quickbooks_tokens, refresh_access_token
from utils.security_utils import token_required


# Load Supabase client
config = get_config()
supabase = create_client(config.SUPABASE_URL, config.SUPABASE_KEY)

# ---------- Config Variables ---------- #



# Load Brevo ENV variables
BREVO_API_KEY = Config.BREVO_API_KEY
BREVO_SEND_EMAIL_URL = Config.BREVO_SEND_EMAIL_URL


# ------------------------------------------
# Login Route
# ------------------------------------------
@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", error_message="Too many login attempts. Please try again in a minute.")
def login():
    if request.method == 'GET':
        chat_session_id = request.args.get('chatSessionId')
        return render_template('login.html', chatSessionId=chat_session_id)

    try:
        data = request.form
        email = data.get('email', '').strip().lower()
        password = data.get('password')
        chat_session_id = data.get('chatSessionId')

        if not email or not password:
            return render_template('login.html', error_message="Email and password are required.", chatSessionId=chat_session_id), 400

        response = supabase.table("users").select("id").eq("email", email).execute()
        if not response.data:
            logging.warning(f"Login failed: No account found for email {email}.")
            return render_template('login.html', error_message="No account found with that email.", chatSessionId=chat_session_id), 401

        user_id = response.data[0]["id"]

        try:
            auth_response = supabase.auth.sign_in_with_password({"email": email, "password": password})
            logging.info(f"Auth response: {auth_response}")
        except AuthApiError as e:
            error_msg = str(e).lower()
            if 'invalid login credentials' in error_msg or 'invalid password' in error_msg:
                return render_template('login.html', error_message="Invalid email or password.", chatSessionId=chat_session_id), 401
            elif 'too many requests' in error_msg or 'rate limit' in error_msg:
                return render_template('login.html', error_message="Too many login attempts. Please try again later.", chatSessionId=chat_session_id), 401
            elif 'jwt expired' in error_msg:
                return render_template('login.html', error_message="Session expired. Please log in again.", chatSessionId=chat_session_id), 401
            else:
                return render_template('login.html', error_message="An error occurred during login. Please try again.", chatSessionId=chat_session_id), 401

        token = generate_session_token(user_id, email)
        logging.info(f"Generated session token for user ID: {user_id}")

        session['user_id'] = user_id
        session['email'] = email

        if chat_session_id:
            try:
                link_response = supabase.table("user_profiles").update({"chat_session_id": chat_session_id}).eq("id", user_id).execute()
                if not link_response.data:
                    logging.warning(f"Failed to link chatSessionId for user {user_id}.")
                else:
                    logging.info(f"Successfully linked chatSessionId {chat_session_id} to user {user_id}.")
            except Exception as e:
                logging.error(f"Error linking chatSessionId for user {user_id}: {e}")

        resp = make_response(redirect(url_for('dashboard') if not chat_session_id else url_for('auth.link_chat_session', chatSessionId=chat_session_id)))
        resp.set_cookie("session_token", token, httponly=True, secure=True, samesite="None", domain=".linkbooksai.com")
        logging.info(f"Session token set for user ID: {user_id}")

        return resp

    except Exception as e:
        logging.error(f"Error during login: {e}", exc_info=True)
        return render_template('login.html', error_message="An unexpected error occurred during login. Please try again."), 500


# ------------------------------------------
# Logout Route
# ------------------------------------------
@auth_bp.route('/logout')
def logout():
    """
    Logs the user out by revoking QuickBooks tokens and deleting relevant tokens from Supabase.
    """
    try:
        session_token = request.cookies.get("session_token") or request.cookies.get("session")
        if not session_token:
            logging.warning("No session token found during logout.")
            return render_template("logout.html", message="You have been logged out successfully.")

        decoded = jwt.decode(session_token, Config.SECRET_KEY, algorithms=["HS256"])
        user_id = decoded.get("user_id")

        if not user_id:
            logging.warning("No user_id found in session token during logout.")
            return render_template("logout.html", message="You have been logged out successfully.")

        # ✅ Revoke QuickBooks tokens
        qb_response = supabase.table("quickbooks_tokens").select("refresh_token").eq("user_id", user_id).execute()
        if qb_response.data:
            refresh_token = qb_response.data[0]["refresh_token"]
            revoke_quickbooks_tokens(refresh_token)

        # ✅ Delete QuickBooks tokens
        supabase.table("quickbooks_tokens").delete().eq("user_id", user_id).execute()

        # ✅ Expire both session tokens
        resp = make_response(render_template("logout.html", message="You have been logged out successfully."))
        resp.set_cookie("session_token", "", expires=0, path="/")
        resp.set_cookie("session", "", expires=0, path="/")

        logging.info("✅ Both session tokens deleted successfully.")
        return resp

    except Exception as e:
        logging.error(f"❌ Error during logout: {e}")
        return render_template("logout.html", message="An error occurred during logout. Please try again."), 500


# ------------------------------------------
# Check Auth Status
# ------------------------------------------
@auth_bp.route("/status", methods=["GET"])
def check_auth_status():
    session_token = request.cookies.get("session_token")
    
    if not session_token:
        return jsonify({"logged_in": False, "message": "No session token found"}), 401

    return jsonify({"logged_in": True, "session_token": session_token})


# ------------------------------------------
# Create Account Route
# ------------------------------------------
@auth_bp.route('/create-account', methods=['GET', 'POST'])
def create_account():
    if request.method == 'GET':
        chat_session_id = request.args.get('chatSessionId', None)
        return render_template('create_account.html', chat_session_id=chat_session_id)

    elif request.method == 'POST':
        data = request.form
        chat_session_id = data.get('chat_session_id', None)
        name = data.get('name', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        phone = data.get('phone', '').strip()
        address = data.get('address', '').strip()

        if not email or not password or not confirm_password:
            return jsonify({"success": False, "error_message": "Email and passwords are required."}), 400

        if password != confirm_password:
            return jsonify({"success": False, "error_message": "Passwords do not match."}), 400

        if len(password) < 6:
            return jsonify({"success": False, "error_message": "Password must be at least 6 characters long."}), 400

        try:
            response = supabase.table("users").select("id").eq("email", email).execute()
            if response.data:
                return jsonify({"success": False, "error_message": "An account with this email already exists."}), 400
        except Exception as e:
            logging.error(f"Error checking for existing account: {e}, chat_session_id: {chat_session_id}")
            return jsonify({"success": False, "error_message": "Failed to check for an existing account."}), 500

        try:
            auth_response = supabase.auth.sign_up({"email": email, "password": password})
            user_id = auth_response.user.id if auth_response.user else None
            if not user_id:
                raise Exception("Failed to create user in Supabase Auth.")
        except Exception as e:
            logging.error(f"Auth creation failed: {e}, chat_session_id: {chat_session_id}")
            return jsonify({"success": False, "error_message": "Error creating account."}), 500

        try:
            user_profile = {
                "id": user_id,
                "name": name,
                "phone": phone,
                "address": address,
                'subscription_status': 'inactive',
                "gpt_config": {"default_behavior": "friendly"},
                "is_verified": False,
            }
            supabase.table("user_profiles").insert(user_profile).execute()
        except Exception as e:
            logging.error(f"Error inserting user profile: {e}, chat_session_id: {chat_session_id}")
            try:
                supabase.auth.api.delete_user(user_id)
                logging.info(f"Deleted user {user_id} due to profile creation failure.")
            except Exception as delete_error:
                logging.error(f"Error deleting user {user_id}: {delete_error}")
            return jsonify({"success": False, "error_message": "Failed to save user profile."}), 500

        session['user_id'] = user_id
        session['email'] = email
        if chat_session_id:
            session['chat_session_id'] = chat_session_id

        return redirect(url_for('subscriptions'))



# ------------------------------------------
# Protected Example: fetch-user-data
# ------------------------------------------
@auth_bp.route('/fetch-user-data', methods=['GET'])
@token_required  # ✅ Protects route
def fetch_user_data():
    """
    Example of a protected route using the @token_required decorator.
    """
    try:
        user_id = request.user_id  # ✅ Extracted from token_required
        return jsonify({"message": f"Fetched user data for user_id = {user_id} successfully"}), 200
    except Exception as e:
        logging.error(f"Error in /fetch-user-data: {e}")
        return jsonify({"error": str(e)}), 500
    
    

    
logging.warning("🔍 Auth routes.py loaded...")

@auth_bp.route("/testdebug", methods=["GET"])
def test_debug():
    logging.warning("🔍 Auth test_debug route is being called!")
    return "OK"