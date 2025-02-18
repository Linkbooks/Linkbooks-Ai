import eventlet
eventlet.monkey_patch()

import os
import logging
import requests
import secrets
import random
import re, sys, threading
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
import string
import bcrypt
import time
import atexit
import eventlet
from flask import render_template, redirect, request, Response, stream_with_context, make_response, url_for, jsonify, Flask, session, send_from_directory, abort
from flask_mail import Mail, Message
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from supabase import create_client, Client
from supabase.lib.client_options import ClientOptions
from gotrue.errors import AuthApiError  # Correct import for error handling
from bcrypt import checkpw
from openai import OpenAI, AssistantEventHandler
import stripe
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.events import EVENT_JOB_ERROR
from urllib.parse import quote
import uuid  # Added for chat_session_id generation
from utils.logging_utils import log_request_info

#------------------- Open AI Assistant ID -------------------#
ASSISTANT_ID = "asst_0w2HuDpG8cgKC3liBnHtUWSO"

# ✅ Store user threads in memory (for now)
user_threads = {}
#------------------------------------------------------------#

# ------------------------------------------------------------------------------
# Environment variables
# ------------------------------------------------------------------------------

# Load environment variables from .env file in development mode
if os.getenv("FLASK_ENV") == "development":
    load_dotenv()

DEV_MODE = os.getenv("FLASK_ENV", "production") == "development"

# Validate JWT_SECRET_KEY
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY environment variable is missing.")

# Define required environment variables
required_env_vars = ['SUPABASE_URL', 'SUPABASE_KEY', 'FLASK_SECRET_KEY']
if DEV_MODE:
    required_env_vars.extend(['QB_SANDBOX_CLIENT_ID', 'QB_SANDBOX_CLIENT_SECRET', 'SANDBOX_REDIRECT_URI'])
else:
    required_env_vars.extend(['QB_PROD_CLIENT_ID', 'QB_PROD_CLIENT_SECRET', 'PROD_REDIRECT_URI'])

# Check for missing environment variables
missing_vars = [var for var in required_env_vars if not os.getenv(var)]
if missing_vars:
    raise RuntimeError(f"Missing required environment variables: {', '.join(missing_vars)}")

# Print loaded environment variables (masking sensitive ones)
print("Loaded Environment Variables:")
for key in required_env_vars:
    value = os.getenv(key)
    # Mask out secrets
    print(f"{key}: {'*****' if 'KEY' in key or 'SECRET' in key else value}")

# ------------------------------------------------------------------------------
# Logging Configuration
# ------------------------------------------------------------------------------

log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logging.info(f"Running in {os.getenv('FLASK_ENV', 'unknown')} mode.")

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
    raise e  # It's critical to have Supabase initialized

# ------------------------------------------------------------------------------
# Scheduler initialization
# ------------------------------------------------------------------------------

scheduler = BackgroundScheduler()

def cleanup_expired_states():
    """
    Deletes expired entries in 'chatgpt_oauth_states'.
    """
    try:
        now = datetime.utcnow().isoformat()
        supabase.table("chatgpt_oauth_states").delete().lt("expiry", now).execute()
        logging.info("Expired state tokens cleaned up.")
    except Exception as e:
        logging.error(f"Error cleaning up expired states: {e}")

def cleanup_expired_verifications():
    """
    Deletes expired email verifications from 'email_verifications'.
    """
    try:
        now = datetime.utcnow().isoformat()
        supabase.table("email_verifications").delete().lt("expires_at", now).execute()
        logging.info("Expired email verifications cleaned up.")
    except Exception as e:
        logging.error(f"Error cleaning up expired email verifications: {e}")

def cleanup_expired_verifications_and_pending_users():
    """
    Deletes expired email verifications and pending users.
    """
    try:
        now = datetime.utcnow().isoformat()

        # Delete expired email verifications
        supabase.table("email_verifications").delete().lt("expires_at", now).execute()
        logging.info("Expired email verifications cleaned up.")

        # Delete users with 'pending' subscription status and expired verifications
        expired_cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
        expired_users = supabase.table("user_profiles").select("id").eq("subscription_status", "pending").lt("created_at", expired_cutoff).execute()

        for user in expired_users.data:
            user_id = user['id']
            supabase.auth.api.delete_user(user_id)
            supabase.table("user_profiles").delete().eq("id", user_id).execute()
            logging.info(f"Deleted pending user {user_id} due to expired verification.")
    except Exception as e:
        logging.error(f"Error during cleanup: {e}")


def cleanup_inactive_users():
    """
    Deletes inactive user accounts created over 24 hours ago.
    """
    try:
        cutoff_time = (datetime.utcnow() - timedelta(hours=24)).isoformat()
        supabase.table("user_profiles").delete().lt("created_at", cutoff_time).eq("subscription_status", "inactive").execute()
        logging.info("Inactive user accounts cleaned up.")
    except Exception as e:
        logging.error(f"Error cleaning up inactive user accounts: {e}")

def log_scheduler_error(event):
    """
    Logs errors occurring in scheduled jobs.
    """
    if event.exception:
        logging.error(f"Scheduler job failed: {event.job_id}, Exception: {event.exception}")

# Schedule cleanup jobs
scheduler.add_job(cleanup_expired_states, 'interval', hours=1, id='cleanup_expired_states')
scheduler.add_job(cleanup_expired_verifications, 'cron', hour=0, id='cleanup_expired_verifications')
scheduler.add_job(cleanup_expired_verifications_and_pending_users, 'interval', hours=1, id='cleanup_expired_verifications_and_pending_users')
scheduler.add_job(cleanup_inactive_users, 'cron', hour=1, id='cleanup_inactive_users')

# Register error listener
scheduler.add_listener(log_scheduler_error, EVENT_JOB_ERROR)

# Start the scheduler
scheduler.start()
logging.info("Scheduler started successfully.")

# Register scheduler shutdown
atexit.register(lambda: scheduler.shutdown())

# ------------------------------------------------------------------------------
# Flask app initialization
# ------------------------------------------------------------------------------
# ✅ Initialize Flask app
app = Flask(
    __name__,
    static_folder="../frontend/.svelte-kit/output/client",  # ✅ Svelte static files
    static_url_path="/",  
    template_folder="templates"
)

# ✅ Serve Flask's static files separately
app.static_folder = "static"  # ✅ Ensures Flask still serves /backend/static


# ✅ Set secret key for security (session management, CSRF protection, etc.)
app.secret_key = os.getenv('FLASK_SECRET_KEY')
if not app.secret_key:
    raise RuntimeError("Missing FLASK_SECRET_KEY environment variable.")

# ✅ Add cookie configuration here
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_DOMAIN='.linkbooksai.com',
    SESSION_COOKIE_HTTPONLY=True
)


#------------Websocket Initialization-------------------#

# Enable CORS

# Get the correct CORS origin based on environment
CORS_ORIGIN = os.getenv("CORS_ORIGIN", "https://linkbooksai.com")  # Production URL
CORS_ORIGIN_LOCAL = os.getenv("CORS_ORIGIN_LOCAL", "http://localhost:5173")  # Local Dev URL

# Determine active CORS origin
ACTIVE_CORS_ORIGIN = CORS_ORIGIN_LOCAL if os.getenv("FLASK_ENV") == "development" else CORS_ORIGIN

# ✅ CORS Configurations
ALLOWED_CORS_ORIGINS = [
    "https://linkbooksai.com",
    "https://app.linkbooksai.com"
]

# ✅ Include localhost only in development mode
if os.getenv("FLASK_ENV") == "development":
    ALLOWED_CORS_ORIGINS.append("http://localhost:5173")

print(f"✅ Using CORS Origin: {ACTIVE_CORS_ORIGIN}")  # Debugging log

# ✅ Enable CORS for HTTP Requests  
CORS(
    app,  
    supports_credentials=True,  # ✅ Allow cookies & auth headers  
    origins=ALLOWED_CORS_ORIGINS,  # ✅ Uses correct list dynamically  
    methods=["GET", "POST", "OPTIONS"],  # ✅ Restrict allowed HTTP methods  
    allow_headers=["Content-Type", "Authorization"],  # ✅ Allow required headers  
    expose_headers=["Set-Cookie"],  # ✅ Allows cookies in responses
    credentials=True
)  

print(f"✅ CORS Configured for: {ALLOWED_CORS_ORIGINS}")

# ---------- Initialize the Websocket SocketIO instance ----------#

# ✅ Dynamically Set CORS Allowed Origins
socketio = SocketIO(
    app,
    cors_allowed_origins=ALLOWED_CORS_ORIGINS,  # ✅ Uses same list dynamically 
    transports=["websocket"],  # ✅ Force WebSockets (no polling)
    ping_interval=25,  # ✅ Helps keep connection alive
    ping_timeout=60  # ✅ Prevents WebSocket from closing too soon
)

print(f"✅ WebSockets Configured for: {ALLOWED_CORS_ORIGINS}")

# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
# Limiter
# ------------------------------------------------------------------------------
limiter = Limiter(
    key_func=get_remote_address
)
limiter.init_app(app)

#-------------------------  Custom Jinja Filter  ------------------------------#
@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    if not value:
        return "N/A"
    return datetime.fromisoformat(value).strftime(format)


# ------------------------------------------------------------------------------
# Configure Stripe
# ------------------------------------------------------------------------------

stripe.api_key = os.getenv('STRIPE_SECRET_KEY')


# ------------------------------------------------------------------------------
# Brevo API Key
# ------------------------------------------------------------------------------

BREVO_API_KEY = os.getenv('BREVO_API_KEY')
BREVO_SEND_EMAIL_URL = "https://api.brevo.com/v3/smtp/email"

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
    "https://app.linkbooksai.com/callback",
], f"Mismatch in REDIRECT_URI configuration. Current: {REDIRECT_URI}"

# ------------------------------------------------------------------------------
# OpenAI client
# ------------------------------------------------------------------------------
openai_client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'

# ------------------------------------------------------------------------------
# Helper Functions
# ------------------------------------------------------------------------------

#--------------Brevo-----------------#

# Flask-Mail Configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = (
    os.getenv('MAIL_DEFAULT_SENDER_NAME'),
    os.getenv('MAIL_DEFAULT_SENDER_EMAIL')
)

mail = Mail(app)

def create_user_with_email(user_data):
    """
    Creates a user in Supabase Auth and user_profiles.
    Raises an exception if any step fails.
    Returns the user_id on success.
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
            raise Exception("Failed to create user in Supabase Auth.")
    except Exception as e:
        logging.error(f"Error creating user in Supabase Auth: {e}")
        raise Exception("Failed to create user.")

    # Step 2: Insert additional user data
    try:
        profile_response = supabase.table('user_profiles').insert({
            'id': user_id,
            'name': name,
            'email': email,
            'phone': phone,
            'address': address,
            'subscription_status': 'pending',  # Set to 'pending' initially
        }).execute()

        if profile_response.data:
            logging.info(f"User profile created successfully for {name}.")
        else:
            logging.error(f"Error creating user profile: {profile_response}")
            raise Exception("Failed to create user profile.")
    except Exception as e:
        logging.error(f"Error creating user profile: {e}")
        # Rollback user creation in Supabase Auth
        try:
            supabase.auth.api.delete_user(user_id)
            logging.info(f"Deleted user {user_id} due to profile creation failure.")
        except Exception as delete_error:
            logging.error(f"Error deleting user {user_id}: {delete_error}")
        raise Exception("Failed to create user profile.")

    return user_id

# ✅ Debug Logging Function (Ensure this is before generate())
def log_debug(msg):
    print(f"{datetime.now().isoformat()} - {msg}", flush=True)

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



# -------------- Log Requests to Backend API ---------------------------------#

@app.before_request
def before_request_logging():
    log_request_info()



#---------- Start the Flask Server ----------#

if os.getenv("FLASK_ENV") == "production":
    app.debug = False

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=app.debug)
