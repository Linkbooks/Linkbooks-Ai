import os
import logging
import requests
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, request, url_for
from dotenv import load_dotenv
from supabase import create_client
from openai import OpenAI

# Load .env file in development environment
if os.getenv('FLASK_ENV') == 'development':
    load_dotenv()

# Validate critical environment variables early
required_env_vars = ['SUPABASE_URL', 'SUPABASE_KEY', 'QB_CLIENT_ID', 'QB_CLIENT_SECRET', 'FLASK_SECRET_KEY']
missing_vars = [var for var in required_env_vars if not os.getenv(var)]
if missing_vars:
    raise RuntimeError(f"Missing required environment variables: {', '.join(missing_vars)}")

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')
if not app.secret_key:
    raise RuntimeError("Missing FLASK_SECRET_KEY environment variable.")

# Flask Debug Mode
debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'

# Logging Configuration
log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(level=getattr(logging, log_level, logging.INFO))

# Initialize Supabase
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
supabase = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None
app.logger.info("Supabase initialized successfully.")

# QuickBooks OAuth Configuration
CLIENT_ID = os.getenv('QB_CLIENT_ID')
CLIENT_SECRET = os.getenv('QB_CLIENT_SECRET')
REDIRECT_URI = os.getenv('REDIRECT_URI', "http://localhost:5000/callback")
AUTHORIZATION_BASE_URL = "https://appcenter.intuit.com/connect/oauth2"
TOKEN_URL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
SCOPE = "com.intuit.quickbooks.accounting"

# Initialize OpenAI client
openai_client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

# Helper Functions
def save_tokens_to_db(access_token, refresh_token, realm_id, expiry=None):
    data = {
        "user_id": "default_user",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "realm_id": realm_id,
        "last_updated": datetime.utcnow().isoformat(),
        "token_expiry": expiry
    }
    response = supabase.table("tokens").upsert(data).execute()
    app.logger.info(f"Tokens saved to Supabase: {response}")

def get_tokens_from_db():
    response = supabase.table("tokens").select("*").eq("user_id", "default_user").execute()
    if not response.data:
        app.logger.error("No tokens found for the user in Supabase.")
        return None, None, None, None
    token = response.data[0]
    return token["access_token"], token["refresh_token"], token["realm_id"], token.get("token_expiry")

def ensure_valid_token():
    access_token, _, _, expiry = get_tokens_from_db()
    if expiry and datetime.utcnow().isoformat() > expiry:
        app.logger.info("Token expired. Refreshing...")
        refresh_access_token()

def refresh_access_token():
    _, refresh_token, _, _ = get_tokens_from_db()
    auth_header = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    payload = {'grant_type': 'refresh_token', 'refresh_token': refresh_token}
    headers = {'Accept': 'application/json'}
    response = requests.post(TOKEN_URL, auth=auth_header, data=payload, headers=headers)
    if response.status_code == 200:
        tokens = response.json()
        expiry_time = (datetime.utcnow() + timedelta(seconds=tokens['expires_in'])).isoformat()
        save_tokens_to_db(tokens['access_token'], tokens['refresh_token'], os.getenv('COMPANY_ID'), expiry=expiry_time)
    else:
        raise Exception(response.text)

# Routes
@app.route('/')
def index():
    try:
        access_token, _, _, expiry = get_tokens_from_db()
        if access_token and expiry and datetime.utcnow().isoformat() < expiry:
            return redirect(url_for('dashboard'))
    except Exception as e:
        app.logger.info("No valid token found. Redirecting to login.")
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    try:
        ensure_valid_token()
        company_info = get_company_info()
        return render_template('dashboard.html', data=company_info)
    except Exception as e:
        app.logger.error(f"Error in /dashboard: {e}")
        return render_template('error.html', message="Error loading dashboard."), 500

@app.route('/fetch-reports', methods=['GET'])
def fetch_reports():
    try:
        ensure_valid_token()
        report_type = request.args.get('reportType')
        if not report_type:
            return {"error": "reportType parameter is required"}, 400
        report_data = fetch_report(report_type)
        return {"data": report_data}, 200
    except Exception as e:
        app.logger.error(f"Error fetching report: {e}")
        return {"error": str(e)}, 500

@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(f"An error occurred: {e}")
    return render_template('error.html', message="An unexpected error occurred."), 500

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', message="Page not found."), 404

@app.before_request
def log_request_info():
    app.logger.info(f"Headers: {request.headers}")
    app.logger.info(f"Body: {request.get_data()}")
    app.logger.info(f"Args: {request.args}")

if __name__ == '__main__':
    app.run(debug=debug_mode)
