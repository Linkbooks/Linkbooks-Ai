import os
import logging
import requests
import secrets
import random, string
import bcrypt
import time
from flask import render_template, redirect, request, make_response, url_for, jsonify, Flask
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from supabase import create_client, Client
from supabase.lib.client_options import ClientOptions
from gotrue.errors import AuthApiError  # Correct import for error handling
from bcrypt import checkpw
from openai import OpenAI
import jwt
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.events import EVENT_JOB_ERROR

# ------------------------------------------------------------------------------
# Scheduler initialization
# ------------------------------------------------------------------------------
scheduler = BackgroundScheduler()

def cleanup_expired_states():
    """
    Deletes any entries in chatgpt_oauth_states whose 'expiry' is in the past.
    """
    try:
        now = datetime.utcnow().isoformat()
        supabase.table("chatgpt_oauth_states").delete().lt("expiry", now).execute()
        logging.info("Expired state tokens cleaned up.")
    except Exception as e:
        logging.error(f"Error cleaning up expired states: {e}")

scheduler.add_job(cleanup_expired_states, 'interval', hours=1)

def log_scheduler_error(event):
    """
    Logs errors from the scheduler.
    """
    if event.exception:
        logging.error(f"Scheduler job failed: {event.job_id}, Exception: {event.exception}")

scheduler.add_listener(log_scheduler_error, EVENT_JOB_ERROR)
scheduler.start()

# ------------------------------------------------------------------------------
# Flask app initialization
# ------------------------------------------------------------------------------
app = Flask(__name__)

@app.before_request
def initialize_scheduler():
    """
    Ensures the scheduler is running before handling requests.
    """
    if not scheduler.running:
        scheduler.add_job(cleanup_expired_states, 'interval', hours=1)
        scheduler.start()


# ------------------------------------------------------------------------------
# Environment variables
# ------------------------------------------------------------------------------
if os.getenv("FLASK_ENV") == "development":
    load_dotenv()

DEV_MODE = os.getenv("FLASK_ENV", "production") == "development"

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY environment variable is missing.")

# Logging Configuration
log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logging.info(f"Running in {os.getenv('FLASK_ENV', 'unknown')} mode.")

required_env_vars = ['SUPABASE_URL', 'SUPABASE_KEY', 'FLASK_SECRET_KEY']
if DEV_MODE:
    required_env_vars.extend(['QB_SANDBOX_CLIENT_ID', 'QB_SANDBOX_CLIENT_SECRET', 'SANDBOX_REDIRECT_URI'])
else:
    required_env_vars.extend(['QB_PROD_CLIENT_ID', 'QB_PROD_CLIENT_SECRET', 'PROD_REDIRECT_URI'])

missing_vars = [var for var in required_env_vars if not os.getenv(var)]
if missing_vars:
    raise RuntimeError(f"Missing required environment variables: {', '.join(missing_vars)}")

print("Loaded Environment Variables:")
for key, value in os.environ.items():
    if key in required_env_vars:
        # Mask out secrets
        print(f"{key}: {'*****' if 'KEY' in key or 'SECRET' in key else value}")

app.secret_key = os.getenv('FLASK_SECRET_KEY')
if not app.secret_key:
    raise RuntimeError("Missing FLASK_SECRET_KEY environment variable.")

# ------------------------------------------------------------------------------
# Limiter
# ------------------------------------------------------------------------------
limiter = Limiter(
    key_func=get_remote_address
)
limiter.init_app(app)

# ------------------------------------------------------------------------------
# Supabase Initialization
# ------------------------------------------------------------------------------
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')

try:
    client_options = ClientOptions(postgrest_client_timeout=30)
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY, options=client_options)
    logging.info("Supabase client initialized successfully.")
except Exception as e:
    logging.error(f"Error initializing Supabase client: {e}")
    supabase = None

# ------------------------------------------------------------------------------
# QuickBooks OAuth config
# ------------------------------------------------------------------------------
if DEV_MODE:
    CLIENT_ID = os.getenv('QB_SANDBOX_CLIENT_ID')
    CLIENT_SECRET = os.getenv('QB_SANDBOX_CLIENT_SECRET')
    REDIRECT_URI = os.getenv('SANDBOX_REDIRECT_URI')
    QUICKBOOKS_API_BASE_URL = "https://sandbox-quickbooks.api.intuit.com/v3/company/"
    REVOKE_TOKEN_URL = "https://developer.api.intuit.com/v2/oauth2/tokens/revoke"
    LOGGING_LEVEL = 'DEBUG'
    logging.info("Using Sandbox QuickBooks credentials.")
else:
    CLIENT_ID = os.getenv('QB_PROD_CLIENT_ID')
    CLIENT_SECRET = os.getenv('QB_PROD_CLIENT_SECRET')
    REDIRECT_URI = os.getenv('PROD_REDIRECT_URI')
    QUICKBOOKS_API_BASE_URL = "https://quickbooks.api.intuit.com/v3/company/"
    REVOKE_TOKEN_URL = "https://developer.api.intuit.com/v2/oauth2/tokens/revoke"
    LOGGING_LEVEL = 'INFO'
    logging.info("Using Production QuickBooks credentials.")

AUTHORIZATION_BASE_URL = "https://appcenter.intuit.com/connect/oauth2"
TOKEN_URL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
SCOPE = "com.intuit.quickbooks.accounting"

logging.info(f"Using REDIRECT_URI: {REDIRECT_URI}")
assert REDIRECT_URI in [
    "http://localhost:5000/callback",
    "https://quickbooks-gpt-app.onrender.com/callback",
], f"Mismatch in REDIRECT_URI configuration. Current: {REDIRECT_URI}"

# ------------------------------------------------------------------------------
# OpenAI client
# ------------------------------------------------------------------------------
openai_client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'

# ------------------------------------------------------------------------------
# Helper Functions
# ------------------------------------------------------------------------------
def create_user_with_email(user_data):
    """
    Creates a user in Supabase Auth and user_profiles.
    """
    email = user_data.get("email")
    password = user_data.get("password")
    name = user_data.get("name")
    phone = user_data.get("phone")
    address = user_data.get("address")

    # Step 1: Create the user in Supabase Auth
    try:
        auth_response = supabase.auth.sign_up({"email": email, "password": password})
        if auth_response.get('user'):
            user_id = auth_response['user']['id']
            logging.info(f"User {name} created successfully in Supabase Auth with ID: {user_id}")
        else:
            logging.error(f"Error creating user in Supabase Auth: {auth_response}")
            return {"error": "Failed to create user in Supabase Auth."}, 500
    except Exception as e:
        logging.error(f"Error creating user in Supabase Auth: {e}")
        return {"error": "Failed to create user."}, 500

    # Step 2: Insert additional user data
    try:
        profile_response = supabase.table('user_profiles').insert({
            'id': user_id,
            'name': name,
            'email': email,
            'phone': phone,
            'address': address
        }).execute()

        if profile_response.data:
            logging.info(f"User profile created successfully for {name}.")
        else:
            logging.error(f"Error creating user profile: {profile_response}")
            return {"error": "Failed to create user profile."}, 500
    except Exception as e:
        logging.error(f"Error creating user profile: {e}")
        return {"error": "Failed to create user profile."}, 500

def generate_session_token(user_id, email):
    """
    Generates a JWT token with 24-hour expiry.
    """
    token = jwt.encode(
        {
            "user_id": user_id,
            "email": email,
            "exp": datetime.now(timezone.utc) + timedelta(hours=24)
        },
        SECRET_KEY,
        algorithm="HS256"
    )
    return token

def token_required(f):
    """
    Decorator requiring a valid token from the session_token cookie.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("session_token")
        if not token:
            return {"error": "No Authorization token provided"}, 401
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user_id = decoded.get("user_id")
            if not request.user_id:
                raise Exception("No user_id found in the token.")
        except jwt.ExpiredSignatureError:
            return {"error": "Token has expired"}, 401
        except jwt.InvalidTokenError:
            return {"error": "Invalid token"}, 401
        except Exception:
            return {"error": "Unauthorized access. Please log in again."}, 401

        return f(*args, **kwargs)
    return decorated

def get_quickbooks_tokens(user_id):
    """
    Retrieve QuickBooks tokens for a given user ID from quickbooks_tokens table.
    """
    try:
        response = supabase.table("quickbooks_tokens").select("*").eq("id", user_id).execute()
        if not response.data:
            raise Exception("No QuickBooks tokens found for the user.")
        return response.data[0]
    except Exception as e:
        logging.error(f"Error fetching QuickBooks tokens: {e}")
        raise Exception("Failed to fetch QuickBooks tokens.")

def save_quickbooks_tokens(user_id, realm_id, access_token, refresh_token, token_expiry):
    """
    Upsert QuickBooks tokens.
    """
    try:
        supabase.table("quickbooks_tokens").upsert({
            "id": user_id,
            "realm_id": realm_id,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_expiry": token_expiry,
            "last_updated": datetime.utcnow().isoformat()
        }).execute()
        logging.info("QuickBooks tokens saved successfully.")
    except Exception as e:
        logging.error(f"Error saving QuickBooks tokens: {e}")
        raise Exception("Failed to save QuickBooks tokens.")

def refresh_access_token(user_id):
    """
    Refreshes the QuickBooks access token for an app-based user.
    """
    quickbooks_data = get_quickbooks_tokens(user_id)
    if not quickbooks_data:
        raise Exception("No QuickBooks tokens found for this user.")

    refresh_token = quickbooks_data['refresh_token']
    auth_header = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    payload = {'grant_type': 'refresh_token', 'refresh_token': refresh_token}
    headers = {'Accept': 'application/json'}

    response = requests.post(TOKEN_URL, auth=auth_header, data=payload, headers=headers)
    if response.status_code == 200:
        tokens = response.json()
        new_access_token = tokens['access_token']
        new_refresh_token = tokens.get('refresh_token', refresh_token)
        new_expiry = (datetime.utcnow() + timedelta(seconds=tokens['expires_in'])).isoformat()

        save_quickbooks_tokens(
            user_id=user_id,
            realm_id=quickbooks_data['realm_id'],
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            token_expiry=new_expiry
        )
        logging.info(f"Access token refreshed for user {user_id}.")
    else:
        logging.error(f"Failed to refresh access token for user_id {user_id}: {response.text}")
        raise Exception(response.text)

def get_company_info(user_id):
    """
    Fetches the QuickBooks company info for the specified user_id.
    Automatically refreshes if tokens are expired.
    """
    try:
        tokens = get_quickbooks_tokens(user_id)
        access_token = tokens.get('access_token')
        realm_id = tokens.get('realm_id')
        expiry = tokens.get('token_expiry')

        if not access_token:
            raise Exception("No access token found. QuickBooks disconnected.")

        # Check for expiry
        if expiry and datetime.utcnow() > datetime.fromisoformat(expiry):
            logging.info("Access token expired. Refreshing...")
            refresh_access_token(user_id)
            tokens = get_quickbooks_tokens(user_id)
            access_token = tokens.get('access_token')
            realm_id = tokens.get('realm_id')

        # Make request to QBO
        headers = {
            'Authorization': f"Bearer {access_token}",
            'Accept': 'application/json'
        }
        api_url = f"{QUICKBOOKS_API_BASE_URL}{realm_id}/companyinfo/{realm_id}"
        response = requests.get(api_url, headers=headers)

        if response.status_code == 401:
            logging.info("Got 401 fetching company info. Trying refresh again...")
            refresh_access_token(user_id)
            tokens = get_quickbooks_tokens(user_id)
            access_token = tokens.get('access_token')
            headers['Authorization'] = f"Bearer {access_token}"
            response = requests.get(api_url, headers=headers)

        if response.status_code == 200:
            return response.json().get("CompanyInfo", {})
        else:
            logging.error(f"QuickBooks API Error: {response.status_code} - {response.text}")
            raise Exception(f"Failed to fetch company info: {response.status_code} {response.text}")
    except Exception as e:
        logging.error(f"Error in get_company_info: {e}")
        raise

def store_tokens_for_chatgpt_session(chat_session_id, realm_id, access_token, refresh_token, expiry):
    """
    Stores QuickBooks tokens associated with a ChatGPT session ID into 'chatgpt_tokens'.
    """
    try:
        # Retrieve user_id from user_profiles
        user_profile = supabase.table("user_profiles").select("id").eq("chat_session_id", chat_session_id).execute()
        if not user_profile.data:
            logging.error(f"No user found for chatSessionId: {chat_session_id}")
            raise ValueError("User not found for given chatSessionId")

        user_id = user_profile.data[0]["id"]

        payload = {
            "chat_session_id": chat_session_id,
            "user_id": user_id,
            "realm_id": realm_id,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expiry": expiry
        }
        logging.info(f"Payload for chatgpt_tokens upsert: {payload}")

        token_response = supabase.table("chatgpt_tokens").upsert(payload).execute()
        if token_response.error:
            logging.error(f"Failed to store tokens: {token_response.error}")
            raise ValueError("Failed to store tokens")

        logging.info(f"Tokens stored successfully for chatSessionId: {chat_session_id}")
    except Exception as e:
        logging.error(f"Error storing tokens for ChatGPT session {chat_session_id}: {e}")
        raise

def generate_random_state(length=16):
    """
    Generates a random `state` string for OAuth (CSRF protection).
    """
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def revoke_quickbooks_tokens(refresh_token):
    """
    Revokes the given refresh token with QuickBooks.
    """
    try:
        auth_header = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
        payload = {'token': refresh_token}
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = requests.post(REVOKE_TOKEN_URL, auth=auth_header, data=payload, headers=headers)
        if response.status_code != 200:
            raise Exception(f"Failed to revoke tokens: {response.text}")
        logging.info("QuickBooks tokens revoked successfully.")
    except Exception as e:
        logging.error(f"Error revoking tokens: {e}")
        raise

# ------------------------------------------------------------------------------
# Optional store_state() - if used anywhere, ensure it supplies a non-null 'state'
# ------------------------------------------------------------------------------
"""
def store_state(chat_session_id, state):
    expiry = datetime.utcnow() + timedelta(minutes=30)
    try:
        supabase.table("chatgpt_oauth_states").upsert({
            "state": state,
            "chat_session_id": chat_session_id,
            "expiry": expiry.isoformat()
        }).execute()
        logging.info(f"Stored state: {state} with expiry: {expiry}")
    except Exception as e:
        logging.error(f"Failed to store state: {state}, Error: {e}")
        raise
"""

def validate_state(state):
    """
    Validates the incoming state against chatgpt_oauth_states (CSRF protection).
    """
    response = supabase.table("chatgpt_oauth_states").select("*").eq("state", state).execute()
    if not response.data:
        logging.error(f"State not found in database: {state}")
        raise ValueError("Invalid or expired state parameter.")

    stored_state = response.data[0]
    expiry = datetime.fromisoformat(stored_state["expiry"])
    if datetime.utcnow() > expiry:
        logging.error(f"State expired. Generated: {stored_state['expiry']} Current: {datetime.utcnow()}")
        raise ValueError("State token expired.")
    return stored_state

def generate_new_state(chat_session_id):
    """
    Generates a new state for OAuth and stores it in 'chatgpt_oauth_states'.
    """
    try:
        state = f"{chat_session_id}-{secrets.token_hex(8)}"
        expiry = (datetime.utcnow() + timedelta(minutes=15)).isoformat()

        supabase.table("chatgpt_oauth_states").upsert({
            "chat_session_id": chat_session_id,
            "state": state,
            "expiry": expiry
        }).execute()

        logging.info(f"Stored new state for chatSessionId {chat_session_id}: {state}")
        return state
    except Exception as e:
        logging.error(f"Error generating new state for chatSessionId {chat_session_id}: {e}", exc_info=True)
        raise Exception("Failed to generate and store OAuth state.")

# ------------------------------------------------------------------------------
# Flask Routes
# ------------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

# ------------------------------------------
# Login Route
# ------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
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
            error_message = "Email and password are required."
            return render_template('login.html', error_message=error_message, chatSessionId=chat_session_id), 400

        # Check user in 'users' table
        response = supabase.table("users").select("id").eq("email", email).execute()
        if not response.data or len(response.data) == 0:
            error_message = "No account found with that email."
            logging.warning(f"Login failed: No account found for email {email}.")
            return render_template('login.html', error_message=error_message, chatSessionId=chat_session_id), 401

        user_id = response.data[0]["id"]

        # Attempt sign_in with supabase.auth
        try:
            auth_response = supabase.auth.sign_in_with_password({"email": email, "password": password})
            logging.info(f"Auth response: {auth_response}")
        except AuthApiError as e:
            error_msg = str(e).lower()
            if 'invalid login credentials' in error_msg or 'invalid password' in error_msg:
                error_message = "Invalid email or password."
            elif 'too many requests' in error_msg or 'rate limit' in error_msg:
                error_message = "Too many login attempts. Please try again later."
            elif 'jwt expired' in error_msg:
                error_message = "Session expired. Please log in again."
            else:
                error_message = "An error occurred during login. Please try again."
            return render_template('login.html', error_message=error_message, chatSessionId=chat_session_id), 401

        # Generate session token
        token = generate_session_token(user_id, email)
        logging.info(f"Generated session token for user ID: {user_id}")

        # Link ChatGPT session ID if provided
        if chat_session_id:
            try:
                link_response = supabase.table("user_profiles").update({
                    "chat_session_id": chat_session_id
                }).eq("id", user_id).execute()
                if link_response.error:
                    logging.warning(f"Failed to link chatSessionId for user {user_id}. Response: {link_response}")
                else:
                    logging.info(f"Successfully linked chatSessionId {chat_session_id} to user {user_id}.")
            except Exception as e:
                logging.error(f"Error linking chatSessionId for user {user_id}: {e}")

        resp = make_response(
            redirect(
                url_for('dashboard') if not chat_session_id
                else url_for('link_chat_session', chatSessionId=chat_session_id)
            )
        )
        secure_cookie = app.config.get("ENV") == "production"
        resp.set_cookie(
            "session_token",
            token,
            httponly=True,
            secure=secure_cookie,
            samesite='Lax',
        )
        logging.info(f"Session token set for user ID: {user_id}")
        return resp

    except Exception as e:
        logging.error(f"Error during login: {e}", exc_info=True)
        error_message = "An unexpected error occurred during login. Please try again."
        return render_template('login.html', error_message=error_message), 500


# ------------------------------------------
# Create Account Routes
# ------------------------------------------
@app.route('/create-account', methods=['GET'])
def create_account_form():
    return render_template('create_account.html')

@app.route('/create-account', methods=['POST'])
def create_account():
    data = request.form
    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password')
    confirm_password = data.get('confirm_password')
    phone = data.get('phone', '').strip()
    address = data.get('address', '').strip()

    if not email or not password or not confirm_password:
        error_message = "Email and passwords are required."
        return jsonify({"success": False, "error_message": error_message}), 400

    if password != confirm_password:
        error_message = "Passwords do not match."
        return jsonify({"success": False, "error_message": error_message}), 400

    if len(password) < 6:
        error_message = "Password must be at least 6 characters long."
        return jsonify({"success": False, "error_message": error_message}), 400

    # Check if user already exists
    try:
        response = supabase.table("users").select("id").eq("email", email).execute()
        if response.data:
            error_message = "An account with this email already exists."
            return jsonify({"success": False, "error_message": error_message}), 400
    except Exception as e:
        logging.error(f"Error checking for existing account: {e}")
        error_message = "Failed to check for an existing account."
        return jsonify({"success": False, "error_message": error_message}), 500

    # Create user in Supabase Auth
    try:
        auth_response = supabase.auth.sign_up({"email": email, "password": password})
        logging.info(f"Auth response: {auth_response}")

        if hasattr(auth_response, 'user') and auth_response.user:
            user_id = auth_response.user.id
            logging.info(f"User created in Supabase Auth with ID: {user_id}")
        else:
            error_message = "Failed to create user in authentication system."
            return jsonify({"success": False, "error_message": error_message}), 400
    except AuthApiError as e:
        logging.error(f"AuthApiError during sign_up: {e}", exc_info=True)
        error_msg = str(e).lower()
        if 'password should be at least 6 characters' in error_msg:
            error_message = "Password must be at least 6 characters long."
        elif 'user already registered' in error_msg:
            error_message = "An account with that email already exists."
        elif 'rate limit' in error_msg:
            error_message = "You have reached the maximum number of sign-up attempts. Please try again later."
            return jsonify({"success": False, "error_message": error_message}), 429
        else:
            error_message = "An error occurred during account creation."
        return jsonify({"success": False, "error_message": error_message}), 400
    except Exception as e:
        logging.error(f"Exception during sign_up: {e}", exc_info=True)
        error_message = "An unexpected error occurred during account creation."
        return jsonify({"success": False, "error_message": error_message}), 500

    # Insert user profile
    try:
        user_profile = {
            "id": user_id,
            "name": name,
            "phone": phone,
            "address": address,
            "gpt_config": {"default_behavior": "friendly"},
            "is_verified": False
        }
        supabase.table("user_profiles").insert(user_profile).execute()
        logging.info(f"User profile created for ID: {user_id}")
    except Exception as e:
        logging.error(f"Error inserting user profile: {e}")
        error_message = "Failed to save user profile."
        return jsonify({"success": False, "error_message": error_message}), 500

    success_message = "Account created successfully! A verification email has been sent."
    return jsonify({"success": True, "success_message": success_message}), 200

@app.route('/confirmation')
def confirmation():
    return render_template('confirmation.html')

# ------------------------------------------
# Protected Example: fetch-user-data
# ------------------------------------------
@app.route('/fetch-user-data', methods=['GET'])
@token_required
def fetch_user_data():
    """
    Example of a protected route using the @token_required decorator.
    """
    try:
        user_email = request.user_id  # not necessarily the email, depending on your token payload
        return {"message": f"Fetched user data for user_id = {user_email} successfully"}, 200
    except Exception as e:
        logging.error(f"Error in /fetch-user-data: {e}")
        return {"error": str(e)}, 500


# ------------------------------------------
# QuickBooks Login for app-based or ChatGPT sessions
# ------------------------------------------
@app.route('/quickbooks-login', methods=['GET'])
def quickbooks_login():
    """
    Initiates QuickBooks OAuth by inserting a row in chatgpt_oauth_states with a random state.
    """
    try:
        session_token = request.cookies.get('session_token')
        if not session_token:
            return jsonify({"error": "User not authenticated. Please log in first."}), 401

        # Decode session_token
        try:
            decoded = jwt.decode(session_token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Session token expired. Please log in again."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid session token. Please log in again."}), 401

        user_id = decoded.get("user_id")
        if not user_id:
            return jsonify({"error": "User ID missing in session token. Please log in again."}), 401

        chat_session_id = request.args.get("chatSessionId")
        if chat_session_id:
            logging.info(f"ChatGPT session detected: {chat_session_id}")
        else:
            logging.info(f"App-based session detected for user: {user_id}")

        # Generate a dynamic state
        state = generate_random_state()
        expiry = datetime.utcnow() + timedelta(minutes=30)

        supabase.table("chatgpt_oauth_states").insert({
            "state": state,
            "user_id": user_id,
            "chat_session_id": chat_session_id,  # Can be None for app-based
            "expiry": expiry.isoformat()
        }).execute()

        # Construct the QuickBooks OAuth URL
        auth_url = (
            f"{AUTHORIZATION_BASE_URL}?"
            f"client_id={CLIENT_ID}&"
            f"response_type=code&"
            f"scope={SCOPE}&"
            f"redirect_uri={REDIRECT_URI}&"
            f"state={state}"
        )
        logging.info(f"Redirecting to QuickBooks login: {auth_url}")
        return redirect(auth_url)
    except Exception as e:
        logging.error(f"Error in /quickbooks-login: {e}")
        return jsonify({"error": str(e)}), 500

# ------------------------------------------
# Logout Route
# ------------------------------------------
@app.route('/logout')
def logout():
    """
    Logs the user out by revoking QuickBooks tokens and deleting relevant tokens from Supabase.
    """
    try:
        session_token = request.cookies.get('session_token')
        if not session_token:
            raise Exception("No session token found.")

        decoded = jwt.decode(session_token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded.get("user_id")
        if not user_id:
            raise Exception("No user_id found in session token.")

        # Revoke QuickBooks tokens
        qb_response = supabase.table("quickbooks_tokens").select("refresh_token").eq("id", user_id).execute()
        if qb_response.data:
            refresh_token = qb_response.data[0]["refresh_token"]
            revoke_quickbooks_tokens(refresh_token)

        # Delete QuickBooks tokens
        supabase.table("quickbooks_tokens").delete().eq("id", user_id).execute()

        # Delete ChatGPT tokens
        chat_response = supabase.table("chatgpt_tokens").select("chat_session_id").eq("realm_id", user_id).execute()
        if chat_response.data:
            chat_session_id = chat_response.data[0]["chat_session_id"]
            supabase.table("chatgpt_tokens").delete().eq("chat_session_id", chat_session_id).execute()

        logging.info("User logged out successfully.")
        return render_template("logout.html", message="You have been logged out successfully.")
    except Exception as e:
        logging.error(f"Error during logout: {e}")
        return render_template("logout.html", message="An error occurred during logout. Please try again.")


# ------------------------------------------
# ChatGPT-specific routes
# ------------------------------------------
@app.route('/oauth/start-for-chatgpt', methods=['GET'])
def start_oauth_for_chatgpt():
    """
    Ensures ChatGPT users have a linked middleware user, then returns a QuickBooks OAuth URL.
    """
    try:
        chat_session_id = request.args.get('chatSessionId')
        if not chat_session_id:
            return jsonify({"error": "chatSessionId is required"}), 400

        logging.info(f"Received chatSessionId: {chat_session_id}")

        user_check = supabase.table("user_profiles").select("id").eq("chat_session_id", chat_session_id).execute()
        if not user_check.data:
            # Not linked? Redirect them to /login
            middleware_login_url = f"https://quickbooks-gpt-app.onrender.com/login?chatSessionId={chat_session_id}"
            logging.info(f"ChatGPT session not linked. Redirecting to login: {middleware_login_url}")
            return jsonify({"loginUrl": middleware_login_url}), 200

        # Check if we already have a valid state
        state_query = supabase.table("chatgpt_oauth_states").select("*").eq("chat_session_id", chat_session_id).execute()
        if state_query.data:
            stored_state = state_query.data[0]
            expiry = datetime.fromisoformat(stored_state["expiry"])
            if datetime.utcnow() < expiry:
                state = stored_state["state"]
                logging.info(f"Reusing valid state for chatSessionId {chat_session_id}: {state}")
            else:
                # State expired, generate new
                state = generate_new_state(chat_session_id)
                logging.info(f"Generated new state for expired session {chat_session_id}: {state}")
        else:
            # No row yet, generate new
            state = generate_new_state(chat_session_id)
            logging.info(f"Generated new state for new session {chat_session_id}: {state}")

        quickbooks_oauth_url = (
            f"{AUTHORIZATION_BASE_URL}?"
            f"client_id={CLIENT_ID}&"
            f"response_type=code&"
            f"scope={SCOPE}&"
            f"redirect_uri={REDIRECT_URI}&"
            f"state={state}"
        )

        logging.info(f"Generated QuickBooks OAuth URL for chatSessionId {chat_session_id}: {quickbooks_oauth_url}")
        return jsonify({"loginUrl": quickbooks_oauth_url}), 200

    except Exception as e:
        logging.error(f"Error in start_oauth_for_chatgpt: {e}", exc_info=True)
        return jsonify({"error": "An error occurred while processing the OAuth flow. Please try again later."}), 500


@app.route('/link-chat-session', methods=['GET'])
def link_chat_session():
    """
    Links a ChatGPT chatSessionId to the currently logged-in user via session_token.
    """
    try:
        chat_session_id = request.args.get('chatSessionId')
        session_token = request.cookies.get('session_token')

        if not chat_session_id:
            return jsonify({"error": "chatSessionId is required"}), 400

        if not session_token:
            return jsonify({"error": "User not authenticated. Please log in first."}), 401

        try:
            decoded = jwt.decode(session_token, SECRET_KEY, algorithms=["HS256"])
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

        oauth_states_payload = {
            "chat_session_id": chat_session_id,
            "user_id": user_id,
            "state": state,
            "expiry": expiry,
            "is_authenticated": is_authenticated,
        }
        logging.info(f"Payload for chatgpt_oauth_states upsert: {oauth_states_payload}")

        oauth_states_response = supabase.table("chatgpt_oauth_states").upsert(oauth_states_payload).execute()
        if not oauth_states_response.data:
            logging.error(f"Failed to upsert chatgpt_oauth_states for user {user_id}: {oauth_states_response}")
            return jsonify({"error": "Failed to link chatSessionId to user"}), 500

        profile_update_payload = {
            "chat_session_id": chat_session_id,
            "updated_at": datetime.utcnow().isoformat(),
        }
        logging.info(f"Payload for user_profiles update: {profile_update_payload}")

        profile_update_response = (
            supabase.table("user_profiles")
            .update(profile_update_payload)
            .eq("id", user_id)
            .execute()
        )

        if not profile_update_response.data:
            logging.error(f"Failed to update user_profiles for user {user_id}: {profile_update_response}")
            return jsonify({"error": "Failed to update user profile with chatSessionId"}), 500

        logging.info(f"chatSessionId {chat_session_id} successfully linked for user {user_id}.")
        return jsonify({"success": True, "message": "chatSessionId linked successfully", "state": state}), 200

    except Exception as e:
        logging.error(f"Error in /link-chat-session: {e}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred. Please try again later."}), 500


@app.route('/session/status', methods=['GET'])
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
        logging.error(f"Error in /session/status: {e}")
        return jsonify({"authenticated": False, "message": "An unexpected error occurred. Try again later."}), 500

def refresh_access_token_for_chatgpt(chat_session_id, refresh_token):
    """
    Refreshes the QuickBooks access token for a ChatGPT session using Supabase.
    """
    auth_header = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    payload = {'grant_type': 'refresh_token', 'refresh_token': refresh_token}
    headers = {'Accept': 'application/json'}

    response = requests.post(TOKEN_URL, auth=auth_header, data=payload, headers=headers)
    if response.status_code == 200:
        tokens = response.json()
        access_token = tokens['access_token']
        new_refresh_token = tokens.get('refresh_token', refresh_token)
        expiry = (datetime.utcnow() + timedelta(seconds=tokens['expires_in'])).isoformat()

        try:
            update_resp = supabase.table("chatgpt_tokens").update({
                "access_token": access_token,
                "refresh_token": new_refresh_token,
                "expiry": expiry
            }).eq("chat_session_id", chat_session_id).execute()

            if not update_resp.data:
                raise Exception("Failed to update tokens in Supabase")

            logging.info(f"Access token refreshed for ChatGPT session {chat_session_id}")
            return {
                "access_token": access_token,
                "refresh_token": new_refresh_token,
                "expiry": expiry
            }
        except Exception as e:
            logging.error(f"Failed to store refreshed tokens for ChatGPT session {chat_session_id}: {e}")
            raise
    else:
        logging.error(f"Failed to refresh access token for chatSessionId {chat_session_id}: {response.text}")
        raise Exception(response.text)

# ------------------------------------------
# Preferences
# ------------------------------------------
@app.route('/preferences', methods=['GET'])
def fetch_preferences():
    """
    Fetches the personalization note from user_profiles for a given ChatGPT session ID.
    """
    try:
        chat_session_id = request.args.get('chatSessionId')
        if not chat_session_id:
            return jsonify({"error": "chatSessionId is required"}), 400

        # If your DB schema stores this in 'chat_session_id':
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
        logging.error(f"Error in /preferences: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/preferences/update', methods=['POST'])
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
        logging.error(f"Error in /preferences/update: {e}")
        return jsonify({"error": str(e)}), 500

# ------------------------------------------
# QuickBooks OAuth Callback
# ------------------------------------------
@app.route('/callback', methods=['GET'])
def callback():
    """
    Handles QuickBooks OAuth callback and stores tokens in Supabase.
    """
    try:
        # Cleanup expired states
        cleanup_expired_states()

        code = request.args.get('code')
        realm_id = request.args.get('realmId')
        state = request.args.get('state')

        if not code or not realm_id or not state:
            logging.error("Missing required parameters (code, realmId, or state).")
            return jsonify({"error": "Missing required parameters (code, realmId, or state)."}), 400

        # Validate state
        logging.info(f"Validating state: {state}")
        response_state = supabase.table("chatgpt_oauth_states").select("*").eq("state", state).execute()
        if not response_state.data:
            logging.error(f"Invalid or expired state parameter: {state}")
            return jsonify({"error": "Invalid or expired state parameter."}), 400

        stored_state = response_state.data[0]
        chat_session_id = stored_state.get("chat_session_id")
        expiry = datetime.fromisoformat(stored_state["expiry"])
        if datetime.utcnow() > expiry:
            logging.error(f"State expired for session {chat_session_id}: {state}")
            return jsonify({"error": "State token expired."}), 400

        # Exchange authorization code for tokens
        auth_header = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
        payload = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI
        }
        headers = {'Accept': 'application/json'}
        token_response = requests.post(TOKEN_URL, auth=auth_header, data=payload, headers=headers)

        if token_response.status_code != 200:
            logging.error(f"Token exchange failed: {token_response.text}")
            return jsonify({"error": f"Failed to retrieve tokens: {token_response.text}"}), 400

        tokens = token_response.json()
        access_token = tokens['access_token']
        refresh_token = tokens.get('refresh_token')
        expiry_dt = datetime.utcnow() + timedelta(seconds=tokens['expires_in'])
        expiry_str = expiry_dt.isoformat()

        # ChatGPT session
        if chat_session_id:
            try:
                logging.info(f"Storing tokens for ChatGPT session {chat_session_id} with realm ID {realm_id}")
                user_profile = supabase.table("user_profiles").select("id").eq("chat_session_id", chat_session_id).execute()
                if not user_profile.data:
                    logging.error(f"No user linked to chatSessionId {chat_session_id}.")
                    return jsonify({"error": "No user linked to this ChatGPT session ID."}), 400

                user_id = user_profile.data[0]["id"]

                # Store tokens in chatgpt_tokens
                store_tokens_for_chatgpt_session(
                    chat_session_id=chat_session_id,
                    realm_id=realm_id,
                    access_token=access_token,
                    refresh_token=refresh_token,
                    expiry=expiry_str
                )

                # Mark chatgpt_oauth_states as completed
                supabase.table("chatgpt_oauth_states").update({
                    "state": "completed",
                    "is_authenticated": True,
                    "user_id": user_id
                }).eq("chat_session_id", chat_session_id).execute()

                logging.info(f"QuickBooks authorization successful for ChatGPT session {chat_session_id}")
                return jsonify({"success": True, "message": "QuickBooks tokens stored for ChatGPT session."}), 200

            except Exception as e:
                logging.error(f"Failed to store tokens for ChatGPT session {chat_session_id}: {e}")
                return jsonify({"error": "Failed to store tokens for ChatGPT session."}), 500

        # App-based session
        session_token = request.cookies.get('session_token')
        if not session_token:
            logging.error("No session token provided.")
            return jsonify({"error": "No session token provided."}), 400

        try:
            decoded = jwt.decode(session_token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            logging.error("Session token expired.")
            return jsonify({"error": "Session token expired. Please log in again."}), 401
        except jwt.InvalidTokenError:
            logging.error("Invalid session token.")
            return jsonify({"error": "Invalid session token. Please log in again."}), 401

        user_id = decoded.get("user_id")
        if not user_id:
            logging.error("User ID missing from session token.")
            return jsonify({"error": "User ID missing from session token."}), 400

        # Store tokens for app-based user
        try:
            logging.info(f"Storing tokens for user {user_id} with realm ID {realm_id}")
            supabase.table("quickbooks_tokens").upsert({
                "id": user_id,
                "realm_id": realm_id,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_expiry": expiry_str
            }).execute()
            logging.info(f"QuickBooks authorization successful for user {user_id}")
            return redirect(url_for('dashboard') + "?quickbooks_login_success=true")
        except Exception as e:
            logging.error(f"Failed to store tokens for user {user_id}: {e}")
            return jsonify({"error": "Failed to store tokens for user."}), 500

    except Exception as e:
        logging.error(f"Error in /callback: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

# ------------------------------------------
# Dashboard
# ------------------------------------------
@app.route('/dashboard')
def dashboard():
    """
    Example dashboard route that attempts to show QuickBooks data for a logged-in user.
    """
    try:
        success_message = request.args.get('quickbooks_login_success')
        token = request.cookies.get('session_token')
        if not token:
            logging.info("No session_token found. QuickBooks disconnected.")
            return render_template('dashboard.html', success_message=success_message, quickbooks_login_needed=True)

        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            user_id = decoded.get("user_id")
            if not user_id:
                logging.warning("No user_id in token. QuickBooks disconnected.")
                return render_template('dashboard.html', success_message=success_message, quickbooks_login_needed=True)
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            logging.warning("Token invalid or expired. QuickBooks disconnected.")
            return render_template('dashboard.html', success_message=success_message, quickbooks_login_needed=True)

        # Try fetching QuickBooks data
        try:
            company_info = get_company_info(user_id)
            return render_template('dashboard.html', data=company_info, success_message=success_message, quickbooks_login_needed=False)
        except Exception as e:
            logging.warning(f"Error fetching QuickBooks data: {e}")
            return render_template('dashboard.html', success_message=success_message, quickbooks_login_needed=True)

    except Exception as e:
        logging.error(f"Error in /dashboard: {e}", exc_info=True)
        return {"error": str(e)}, 500

# ------------------------------------------
# Fetch Reports for ChatGPT sessions
# ------------------------------------------
@app.route('/fetch-reports', methods=['GET'])
def fetch_reports_route():
    """
    Fetches a QuickBooks report for a given chatSessionId.
    """
    try:
        chat_session_id = request.args.get('chatSessionId')
        report_type = request.args.get('reportType')
        start_date = request.args.get('startDate')
        end_date = request.args.get('endDate')

        if not chat_session_id:
            logging.error("Missing chatSessionId.")
            return jsonify({"error": "chatSessionId is required"}), 400

        if not report_type:
            logging.error("Missing reportType.")
            return jsonify({"error": "reportType is required"}), 400

        resp = supabase.table("chatgpt_tokens").select("*").eq("chat_session_id", chat_session_id).execute()
        if not resp.data:
            logging.error(f"Invalid or expired chatSessionId: {chat_session_id}")
            return jsonify({"error": "Invalid or expired chatSessionId. Please log in again."}), 401

        tokens = resp.data[0]
        access_token = tokens['access_token']
        refresh_token = tokens.get('refresh_token')
        realm_id = tokens['realm_id']
        expiry = tokens['expiry']

        if expiry and datetime.utcnow() > datetime.fromisoformat(expiry):
            logging.info(f"Access token expired for chatSessionId {chat_session_id}. Attempting refresh...")
            try:
                refreshed_tokens = refresh_access_token_for_chatgpt(chat_session_id, refresh_token)
                access_token = refreshed_tokens['access_token']
                # realm_id remains unchanged if not returned
            except Exception as e:
                logging.error(f"Failed to refresh tokens for chatSessionId {chat_session_id}: {e}")
                return jsonify({"error": "Failed to refresh tokens. Please log in again."}), 401

        # Fetch the report
        report_data = fetch_report(
            user_id=realm_id,  # passing realm_id as user_id in the fetch_report function
            report_type=report_type,
            start_date=start_date,
            end_date=end_date
        )

        return jsonify({
            "reportType": report_type,
            "data": report_data,
        }), 200

    except Exception as e:
        logging.error(f"Error in /fetch-reports: {e}")
        return jsonify({"error": str(e)}), 500

def fetch_report(user_id, report_type, start_date=None, end_date=None):
    """
    Fetches a QuickBooks report by calling /reports/<report_type>.
    (Note: here user_id is actually the realm_id.)
    """
    try:
        # Attempt to treat user_id as realm_id for the request
        tokens = get_quickbooks_tokens(user_id)  # This might need customizing if your schema differs
        access_token = tokens.get('access_token')
        expiry = tokens.get('token_expiry')

        if not access_token:
            raise Exception("No access token or realm_id found.")

        if expiry and datetime.utcnow() > datetime.fromisoformat(expiry):
            # If you wanted to auto-refresh in the app-based flow, call refresh_access_token(user_id)
            pass

        headers = {
            'Authorization': f"Bearer {access_token}",
            'Accept': 'application/json'
        }
        url = f"{QUICKBOOKS_API_BASE_URL}{user_id}/reports/{report_type}"

        params = {}
        if start_date:
            params['start_date'] = start_date
        if end_date:
            params['end_date'] = end_date

        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 401:
            # Possibly refresh again or handle error
            pass

        if response.status_code != 200:
            raise Exception(f"Report request failed: {response.status_code} {response.text}")

        return response.json()
    except Exception as e:
        logging.error(f"Error in fetch_report: {e}")
        raise

# ------------------------------------------
# Business Info
# ------------------------------------------
@app.route('/business-info', methods=['GET'])
def business_info():
    """
    Retrieves the user's company information from QuickBooks if they have a valid session.
    """
    try:
        session_token = request.cookies.get('session_token')
        if not session_token:
            logging.error("No session token provided.")
            return {"error": "Session expired. Please log in again."}, 401

        try:
            decoded = jwt.decode(session_token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            logging.error("Session token expired.")
            return {"error": "Session token expired. Please log in again."}, 401
        except jwt.InvalidTokenError:
            logging.error("Invalid session token.")
            return {"error": "Invalid session token. Please log in again."}, 401

        user_id = decoded.get("user_id")
        if not user_id:
            logging.error("User ID missing from session token.")
            return {"error": "Session invalid. Please log in again."}, 401

        tokens = get_quickbooks_tokens(user_id)
        access_token = tokens.get('access_token')
        realm_id = tokens.get('realm_id')
        expiry = tokens.get('token_expiry')

        if not access_token or not realm_id:
            logging.error("QuickBooks not connected.")
            return {"error": "QuickBooks not connected. Please log in again."}, 400

        if expiry and datetime.utcnow() > datetime.fromisoformat(expiry):
            logging.info("Access token expired. Attempting refresh...")
            try:
                refresh_access_token(user_id)
                tokens = get_quickbooks_tokens(user_id)
                access_token = tokens.get('access_token')
            except Exception as e:
                logging.error(f"Failed to refresh tokens for user {user_id}: {e}")
                return {"error": "Could not refresh tokens. Please log in again."}, 401

        company_info = get_company_info(user_id)
        return {
            "companyName": company_info.get("CompanyName"),
            "legalName": company_info.get("LegalName"),
            "address": company_info.get("CompanyAddr", {}).get("Line1"),
            "phone": company_info.get("PrimaryPhone", {}).get("FreeFormNumber"),
            "email": company_info.get("Email", {}).get("Address"),
        }, 200

    except Exception as e:
        logging.error(f"Error in /business-info: {e}")
        return {"error": str(e)}, 500

# ------------------------------------------
# Analyze
# ------------------------------------------
@app.route('/analyze', methods=['GET'])
def analyze():
    """
    Example endpoint showing how you might call OpenAI with the company's data.
    """
    try:
        # For demonstration, let's just hardcode some data
        company_info = {"CompanyName": "Demo Co", "LegalName": "Demo Co Inc."}

        prompt = (
            "Analyze the following business details...\n"
            f"Company Info:\n{company_info}"
        )
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300,
            temperature=0.7
        )
        analysis = response.choices[0].message.content
        return render_template('analysis.html', analysis=analysis, data=company_info)
    except Exception as e:
        logging.error(f"Error in /analyze: {e}")
        return {"error": str(e)}, 500

# ------------------------------------------
# get_reports: Returns a list of supported QuickBooks reports
# ------------------------------------------
def get_reports():
    """
    Returns a list of supported QuickBooks reports.
    """
    return [
        # Financial Reports
        "ProfitAndLoss",
        "ProfitAndLossDetail",
        "BalanceSheet",
        "BalanceSheetDetail",
        "CashFlow",
        "TrialBalance",
        "GeneralLedger",

        # Sales Reports
        "SalesByCustomerSummary",
        "SalesByCustomerDetail",
        "SalesByProductServiceSummary",
        "SalesByProductServiceDetail",
        "SalesByLocation",
        "EstimatesByCustomer",

        # Expense and Vendor Reports
        "ExpensesByVendorSummary",
        "ExpensesByVendorDetail",
        "AgedPayablesSummary",
        "AgedPayablesDetail",
        "UnpaidBills",

        # Customer Reports
        "AgedReceivablesSummary",
        "AgedReceivablesDetail",
        "CustomerBalanceSummary",
        "CustomerBalanceDetail",
        "InvoiceList",

        # Employee Reports
        "PayrollSummary",
        "PayrollDetails",
        "EmployeeDetails",
        "TimeActivitiesByEmployeeDetail",

        # Product and Inventory Reports
        "InventoryValuationSummary",
        "InventoryValuationDetail",
        "PhysicalInventoryWorksheet",
        "ProductServiceList",

        # Budget and Forecast Reports
        "BudgetOverview",
        "BudgetVsActual",
        "ProfitAndLossBudgetPerformance",

        # Tax and VAT Reports
        "VATSummary",
        "VATDetailReport",
        "SalesTaxLiabilityReport",

        # Custom Reports
        "CustomSummaryReport",
        "CustomTransactionDetailReport",

        # Other Reports
        "TransactionListByDate",
        "AuditLog",
        "BusinessSnapshot",
        "MissingChecks",
        "ReconciliationReports"
    ]

@app.route('/list-reports', methods=['GET'])
def list_reports():
    """
    Returns a list of supported QuickBooks reports.
    """
    try:
        available_reports = get_reports()
        return {
            "availableReports": available_reports,
            "message": "Use the /fetch-reports endpoint with ?reportType=<one of these>."
        }, 200
    except Exception as e:
        logging.error(f"Error listing reports: {e}")
        return {"error": str(e)}, 500

# ------------------------------------------
# analyze-reports
# ------------------------------------------
@app.route('/analyze-reports', methods=['POST'])
def analyze_reports():
    """
    Sends retrieved report data to OpenAI for an example analysis.
    """
    try:
        reports = request.json
        if not reports or not isinstance(reports, dict):
            return {"error": "Invalid or missing report data. Expected a JSON object."}, 400

        prompt = f"Analyze the following financial data:\n{reports}"
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300
        )
        analysis = response.choices[0].message.content
        return {"analysis": analysis, "originalData": reports}, 200
    except Exception as e:
        logging.error(f"Error analyzing reports: {e}")
        return {"error": str(e)}, 500

# ------------------------------------------
# Testing OpenAI Endpoints
# ------------------------------------------
@app.route('/test-openai', methods=['GET'])
def test_openai():
    try:
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
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

@app.route('/test-openai-key', methods=['GET'])
def test_openai_key():
    try:
        if not openai_client.api_key:
            raise ValueError("OpenAI API key not loaded")
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": "Test API key"}],
            max_tokens=10
        )
        return {"response": response['choices'][0]['message']['content']}, 200
    except Exception as e:
        return {"error": str(e)}, 500

# ------------------------------------------
# Misc: EULA, Privacy, Debug
# ------------------------------------------
@app.route('/eula', methods=['GET'])
def eula():
    return render_template('eula.html')

@app.route('/privacy-policy', methods=['GET'])
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/debug-env', methods=['GET'])
def debug_env():
    """
    Be careful not to expose real secrets in production logs/responses.
    """
    variables = {
        "SUPABASE_URL": os.getenv('SUPABASE_URL'),
        "SUPABASE_KEY": os.getenv('SUPABASE_KEY'),
        "QB_SANDBOX_CLIENT_ID": os.getenv('QB_SANDBOX_CLIENT_ID'),
        "QB_SANDBOX_CLIENT_SECRET": os.getenv('QB_SANDBOX_CLIENT_SECRET'),
        "QB_PROD_CLIENT_ID": os.getenv('QB_PROD_CLIENT_ID'),
        "QB_PROD_CLIENT_SECRET": os.getenv('QB_PROD_CLIENT_SECRET'),
        "FLASK_SECRET_KEY": os.getenv('FLASK_SECRET_KEY'),
        "OPENAI_API_KEY": os.getenv('OPENAI_API_KEY'),
    }
    logging.info(f"Environment variables: {variables}")
    return {
        key: ("*****" if "KEY" in key or "SECRET" in key else value)
        for key, value in variables.items()
    }, 200

print(f"OpenAI API Key Loaded: {bool(openai_client.api_key)}")

@app.before_request
def log_request_info():
    logging.info(f"Headers: {request.headers}")
    logging.info(f"Body: {request.get_data()}")
    logging.info(f"Args: {request.args}")

if __name__ == '__main__':
    app.run(debug=debug_mode)

if os.getenv("FLASK_ENV") == "production":
    app.debug = False
