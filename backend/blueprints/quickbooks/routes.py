import logging
import jwt
import requests
import os
from flask import Blueprint, request, jsonify, redirect
from datetime import datetime, timedelta
from extensions import supabase
from config import Config
from utils.oauth_utils import validate_state
from utils.security_utils import generate_random_state
from utils.scheduler_utils import cleanup_expired_states


# Create Blueprint
quickbooks_bp = Blueprint('quickbooks', __name__, url_prefix='/quickbooks')

#---------------------------------------------------------#
#------------------- Config Variables --------------------#
#---------------------------------------------------------#

CLIENT_ID = Config.QB_CLIENT_ID
CLIENT_SECRET = Config.QB_CLIENT_SECRET
REDIRECT_URI = Config.QB_REDIRECT_URI
AUTHORIZATION_BASE_URL = Config.AUTHORIZATION_BASE_URL
SCOPE = Config.SCOPE
SECRET_KEY = Config.SECRET_KEY

# --------------------------------------------------------#
#    ✅ QuickBooks Login for App & ChatGPT Sessions
# --------------------------------------------------------#
@quickbooks_bp.route('/quickbooks-login', methods=['GET'])
def quickbooks_login():
    """
    Initiates QuickBooks OAuth, ensuring linkage between user and tokens.
    ✅ Only updates existing states—NO new rows.
    ✅ Applies changes to all active chat sessions for the user.
    """
    try:
        # 1) Extract and decode session token
        session_token = request.cookies.get('session_token')
        if not session_token:
            return jsonify({"error": "User not authenticated. Please log in first."}), 401

        try:
            decoded = jwt.decode(session_token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Session token expired. Please log in again."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid session token. Please log in again."}), 401

        user_id = decoded.get("user_id")
        if not user_id:
            return jsonify({"error": "User ID missing from session token."}), 401

        # 2) Generate a fresh OAuth state & expiry
        state = generate_random_state()
        expiry = datetime.utcnow() + timedelta(minutes=30)

        # ✅ Only UPDATE existing chat sessions for this user, don't insert new ones
        response = supabase.table("chatgpt_oauth_states").update({
            "state": state,
            "expiry": expiry.isoformat(),
            "is_authenticated": False  # Reset authentication until OAuth completes
        }).eq("user_id", user_id).execute()

        # ✅ Handle missing sessions: Insert new one if needed
        if not response.data:  
            logging.warning(f"No existing OAuth state found for user {user_id}. Inserting a new record...")
            insert_response = supabase.table("chatgpt_oauth_states").insert({
                "user_id": user_id,
                "state": state,
                "expiry": expiry.isoformat(),
                "is_authenticated": False
            }).execute()

            if not insert_response.data:
                logging.error(f"Failed to insert new OAuth state for user {user_id}")
                return jsonify({"error": "Failed to initialize OAuth state."}), 500

        logging.info(f"Updated OAuth state {state} for user {user_id}")

        # 3) Construct the QuickBooks OAuth URL with the stored 'state'
        auth_url = (
            f"{AUTHORIZATION_BASE_URL}?"
            f"client_id={CLIENT_ID}&"
            f"response_type=code&"
            f"scope={SCOPE}&"
            f"redirect_uri={REDIRECT_URI}&"
            f"state={state}"
        )
        logging.info(f"Redirecting to QuickBooks login: {auth_url}")

        # 4) Redirect the user to QuickBooks authorization page
        return redirect(auth_url)

    except Exception as e:
        logging.error(f"Error in /quickbooks-login: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


# ------------------------------------------
# QuickBooks OAuth Callback
# ------------------------------------------
@quickbooks_bp.route('/callback', methods=['GET'])
def callback():
    """
    Handles QuickBooks OAuth callback and stores tokens in Supabase.
    Now stores tokens **by user_id**, not chatSessionId.
    """
    try:
        # Cleanup expired states first
        cleanup_expired_states()

        code = request.args.get('code')
        realm_id = request.args.get('realmId')
        state = request.args.get('state')

        if not code or not realm_id or not state:
            logging.error("❌ Missing required parameters (code, realmId, or state).")
            return jsonify({"error": "Missing required parameters (code, realmId, or state)."}), 400

        # 1️⃣ Validate State & Get user_id
        logging.info(f"🔍 Validating state: {state}")
        response_state = supabase.table("chatgpt_oauth_states").select("*").eq("state", state).execute()

        if not response_state.data:
            logging.error(f"❌ Invalid or expired state parameter: {state}")
            return jsonify({"error": "Invalid or expired state parameter."}), 400

        stored_state = response_state.data[0]
        user_id = stored_state.get("user_id")

        if not user_id:
            logging.error("❌ No user_id found for this OAuth state.")
            return jsonify({"error": "User ID missing from OAuth flow."}), 400

        # 2️⃣ Exchange authorization code for QuickBooks tokens
        auth_header = requests.auth.HTTPBasicAuth(os.getenv("CLIENT_ID"), os.getenv("CLIENT_SECRET"))
        payload = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': os.getenv("REDIRECT_URI")
        }
        headers = {'Accept': 'application/json'}
        token_response = requests.post(os.getenv("TOKEN_URL"), auth=auth_header, data=payload, headers=headers)

        if token_response.status_code != 200:
            logging.error(f"❌ Token exchange failed: {token_response.text}")
            return jsonify({"error": f"Failed to retrieve tokens: {token_response.text}"}), 400

        tokens = token_response.json()
        access_token = tokens['access_token']
        refresh_token = tokens.get('refresh_token')
        expires_in = tokens['expires_in']
        expiry_str = (datetime.utcnow() + timedelta(seconds=expires_in)).isoformat()

        # 3️⃣ Store tokens **by user_id**
        try:
            supabase.table("quickbooks_tokens").upsert({
                "user_id": user_id,  # Store tokens per user
                "realm_id": realm_id,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_expiry": expiry_str
            }).execute()

            # ✅ Mark ALL chat sessions for this user as authenticated
            supabase.table("chatgpt_oauth_states").update({
                "is_authenticated": True
            }).eq("user_id", user_id).execute()

            logging.info(f"✅ QuickBooks authorization successful for user {user_id}")

            # ✅ Redirect URL based on environment
            redirect_url = (
                "http://localhost:5173/dashboard?quickbooks_login_success=true"
                if os.getenv("FLASK_ENV") == "development"
                else "https://linkbooksai.com/dashboard?quickbooks_login_success=true"
            )

            return redirect(redirect_url)

        except Exception as e:
            logging.error(f"❌ Failed to store QuickBooks tokens for user {user_id}: {e}")
            return jsonify({"error": "Failed to store QuickBooks tokens."}), 500

    except Exception as e:
        logging.error(f"❌ Error in /callback: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    

