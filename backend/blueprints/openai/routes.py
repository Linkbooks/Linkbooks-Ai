import logging
import uuid
import jwt
import openai
from datetime import datetime, timedelta
from urllib.parse import quote
from flask import Blueprint, request, jsonify, redirect, url_for, jsonify
from extensions import supabase, openai_client
from .helpers import refresh_access_token_for_chatgpt, store_tokens_for_chatgpt_session  # Ensure this is in a helpers file
from utils.security_utils import generate_random_state
from config import Config

# ------ Config Variables ------#

CLIENT_ID = Config.QB_CLIENT_ID
CLIENT_SECRET = Config.QB_CLIENT_SECRET
AUTHORIZATION_BASE_URL = Config.AUTHORIZATION_BASE_URL
SCOPE = Config.SCOPE
REDIRECT_URI = Config.QB_REDIRECT_URI

# Create Blueprint
openai_bp = Blueprint('openai', __name__, url_prefix='/openai')

# ------------------------------------------
# ChatGPT OAuth Start
# ------------------------------------------
@openai_bp.route('/oauth/start-for-chatgpt', methods=['GET'])
def start_oauth_for_chatgpt():
    """
    Ensures ChatGPT users have a linked user account and returns an OAuth login URL.
    If no chatSessionId is provided, generates one.
    """
    try:
        chat_session_id = request.args.get('chatSessionId')
        if not chat_session_id:
            chat_session_id = str(uuid.uuid4())  # Generate a unique session ID
            logging.info(f"Generated new chatSessionId: {chat_session_id}")

        logging.info(f"Using chatSessionId: {chat_session_id}")

        # Check if a user is linked to this session
        user_check = supabase.table("user_profiles").select("id").eq("chat_session_id", chat_session_id).execute()

        if not user_check.data:
            # 🛑 No user linked → Prompt login first
            encoded_session_id = quote(chat_session_id, safe="")
            middleware_login_url = f"https://linkbooksai.com/login?chatSessionId={encoded_session_id}"
            return jsonify({
                "loginUrl": middleware_login_url,
                "chatSessionId": chat_session_id
            }), 200
        
        # ✅ A user exists, extract user_id
        user_id = user_check.data[0]["id"]

        # ✅ Check if the user is already authenticated with QuickBooks
        auth_check = supabase.table("chatgpt_oauth_states") \
            .select("is_authenticated") \
            .eq("user_id", user_id) \
            .eq("is_authenticated", True) \
            .execute()

        is_already_authenticated = bool(auth_check.data)  # True if previously authenticated

        # ✅ Store new chat session, BUT DO NOT TOUCH is_authenticated
        state = generate_random_state()
        expiry = (datetime.utcnow() + timedelta(minutes=30)).isoformat()

        supabase.table("chatgpt_oauth_states").upsert({
            "chat_session_id": chat_session_id,
            "user_id": user_id,
            "state": state,
            "expiry": expiry
        }, on_conflict=["chat_session_id"]).execute()

        # ✅ If already authenticated, return success immediately
        if is_already_authenticated:
            return jsonify({
                "authenticated": True,
                "chatSessionId": chat_session_id
            }), 200

        # ✅ Otherwise, generate OAuth login link
        quickbooks_oauth_url = (
            f"{AUTHORIZATION_BASE_URL}?"
            f"client_id={CLIENT_ID}&"
            f"response_type=code&"
            f"scope={SCOPE}&"
            f"redirect_uri={REDIRECT_URI}&"
            f"state={state}"
        )

        return jsonify({
            "loginUrl": quickbooks_oauth_url,
            "chatSessionId": chat_session_id
        }), 200

    except Exception as e:
        logging.error(f"Error in start_oauth_for_chatgpt: {e}", exc_info=True)
        return jsonify({"error": "An error occurred. Please try again."}), 500


# ------------------------------------------
# Link Chat Session
# ------------------------------------------
@openai_bp.route('/link-chat-session', methods=['GET'])
def link_chat_session():
    """
    Links a ChatGPT chatSessionId to the currently logged-in user via session_token.
    """
    try:
        chat_session_id = request.args.get('chatSessionId')
        session_token = request.cookies.get('session_token')

        if not chat_session_id or not isinstance(chat_session_id, str) or not chat_session_id.strip():
            logging.error("Invalid or missing chat_session_id.")
            return jsonify({"error": "chatSessionId is required and must be a valid string."}), 400

        if not session_token:
            return jsonify({"error": "User not authenticated. Please log in first."}), 401

        try:
            decoded = jwt.decode(session_token, Config.SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Session token has expired. Please log in again."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid session token. Please log in again."}), 401

        user_id = decoded.get("user_id")
        if not user_id:
            return jsonify({"error": "Invalid session token: user_id not found."}), 401

        state = "initiated"
        is_authenticated = False
        expiry = (datetime.utcnow() + timedelta(minutes=30)).isoformat()

        # Check if an entry already exists
        existing_entry = supabase.table("chatgpt_oauth_states") \
            .select("chat_session_id") \
            .eq("chat_session_id", chat_session_id) \
            .eq("user_id", user_id) \
            .execute()

        if existing_entry.data:
            # Update the existing entry
            logging.info(f"Updating existing chatgpt_oauth_states entry for chatSessionId {chat_session_id}")
            oauth_states_response = supabase.table("chatgpt_oauth_states") \
                .update({
                    "state": state,
                    "expiry": expiry,
                    "is_authenticated": is_authenticated
                }) \
                .eq("chat_session_id", chat_session_id) \
                .eq("user_id", user_id) \
                .execute()
        else:
            # Insert new entry
            logging.info(f"Inserting new chatgpt_oauth_states entry for chatSessionId {chat_session_id}")
            oauth_states_response = supabase.table("chatgpt_oauth_states") \
                .insert({
                    "chat_session_id": chat_session_id,
                    "user_id": user_id,
                    "state": state,
                    "expiry": expiry,
                    "is_authenticated": is_authenticated,
                }) \
                .execute()

        if not oauth_states_response.data:
            logging.error(f"Failed to update/insert chatgpt_oauth_states for user {user_id}: {oauth_states_response}")
            return jsonify({"error": "Failed to link chatSessionId to user"}), 500

        logging.info(f"Successfully linked chatSessionId {chat_session_id} for user {user_id}.")

        # Update user profile with chatSessionId
        profile_update_payload = {
            "chat_session_id": chat_session_id,
            "updated_at": datetime.utcnow().isoformat(),
        }
        logging.info(f"Updating user_profiles: {profile_update_payload}")

        profile_update_response = supabase.table("user_profiles") \
            .update(profile_update_payload) \
            .eq("id", user_id) \
            .execute()

        if not profile_update_response.data:
            logging.error(f"Failed to update user_profiles for user {user_id}: {profile_update_response}")
            return jsonify({"error": "Failed to update user profile with chatSessionId"}), 500

        logging.info(f"chatSessionId {chat_session_id} successfully linked for user {user_id}.")

        # ✅ Redirect to dashboard with chatSessionId in the URL
        dashboard_url = url_for('dashboard', chatSessionId=chat_session_id)
        logging.info(f"Redirecting to dashboard: {dashboard_url}")
        return redirect(dashboard_url)

    except Exception as e:
        logging.error(f"Error in /link-chat-session: {e}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred. Please try again later."}), 500


# ------------------------------------------
# Preferences - Fetch
# ------------------------------------------
@openai_bp.route('/preferences', methods=['GET'])
def fetch_preferences():
    """
    Fetches the personalization note from user_profiles for a given ChatGPT session ID.
    """
    try:
        chat_session_id = request.args.get('chatSessionId')
        if not chat_session_id:
            return jsonify({"error": "chatSessionId is required"}), 400

        response = supabase.table("user_profiles").select("personalization_note").eq("chat_session_id", chat_session_id).execute()
        if not response.data or not response.data[0].get('personalization_note'):
            return jsonify({
                "personalizationNote": "",
                "message": "No personalization note found. Please add one."
            }), 200

        personalization_note = response.data[0]['personalization_note']
        return jsonify({
            "personalizationNote": personalization_note,
            "message": "Personalization preferences retrieved successfully."
        }), 200

    except Exception as e:
        logging.error(f"❌ Error in /preferences: {e}")
        return jsonify({"error": str(e)}), 500


# ------------------------------------------
# Preferences - Update
# ------------------------------------------
@openai_bp.route('/preferences/update', methods=['POST'])
def update_preferences():
    """
    Updates the personalization note for a given ChatGPT session ID.
    """
    try:
        data = request.json
        chat_session_id = data.get('chatSessionId')
        personalization_note = data.get('personalizationNote')

        if not chat_session_id:
            return jsonify({"error": "chatSessionId is required"}), 400
        if not personalization_note:
            return jsonify({"error": "personalizationNote is required"}), 400
        if len(personalization_note) > 240:
            return jsonify({"error": "personalizationNote exceeds 240 characters"}), 400

        response = supabase.table("user_profiles").update({
            "personalization_note": personalization_note
        }).eq("chat_session_id", chat_session_id).execute()

        if not response.data:
            return jsonify({"error": "Failed to update personalization note. Invalid chatSessionId?"}), 400

        return jsonify({"message": "Personalization note updated successfully."}), 200

    except Exception as e:
        logging.error(f"❌ Error in /preferences/update: {e}")
        return jsonify({"error": str(e)}), 500
    
    
# ------------------------------------------
# Testing OpenAI Endpoints
# ------------------------------------------
@openai_bp.route('/test-openai', methods=['GET'])
def test_openai():
    try:
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Hello, can you confirm this is working?"}
            ],
            max_tokens=50
        )
        return {"message": response.choices[0].message.content}, 200
    except Exception as e:
        logging.error(f"Error in /test-openai: {e}")
        return {"error": f"OpenAI error: {str(e)}"}, 500

@openai_bp.route('/test-openai-key', methods=['GET'])
def test_openai_key():
    try:
        if not openai_client.api_key:
            raise ValueError("OpenAI API key not loaded")
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "Test API key"}],
            max_tokens=10
        )
        return {"response": response['choices'][0]['message']['content']}, 200
    except Exception as e:
        return {"error": str(e)}, 500