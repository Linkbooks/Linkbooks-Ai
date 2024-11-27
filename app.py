import os
import logging
import requests
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, request, url_for, send_from_directory
from dotenv import load_dotenv
from supabase import create_client
import openai

# Load .env file in development environment
if os.getenv('FLASK_ENV') == 'development':
    load_dotenv()

# Validate critical environment variables early
required_env_vars = ['SUPABASE_URL', 'SUPABASE_KEY', 'QB_CLIENT_ID', 'QB_CLIENT_SECRET', 'FLASK_SECRET_KEY']
missing_vars = [var for var in required_env_vars if not os.getenv(var)]
if missing_vars:
    raise RuntimeError(f"Missing required environment variables: {', '.join(missing_vars)}")

# Logging Configuration
log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(level=getattr(logging, log_level, logging.INFO))

# Supabase Initialization
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
try:
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    logging.info("Supabase client initialized successfully.")
except Exception as e:
    logging.error(f"Error initializing Supabase client: {e}")
    supabase = None

# QuickBooks OAuth Configuration
CLIENT_ID = os.getenv('QB_CLIENT_ID')
CLIENT_SECRET = os.getenv('QB_CLIENT_SECRET')
REDIRECT_URI = os.getenv('REDIRECT_URI', "http://localhost:5000/callback")
AUTHORIZATION_BASE_URL = "https://appcenter.intuit.com/connect/oauth2"
TOKEN_URL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
SCOPE = "com.intuit.quickbooks.accounting"

# Initialize OpenAI API key
openai.api_key = os.getenv('OPENAI_API_KEY')

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')
if not app.secret_key:
    raise RuntimeError("Missing FLASK_SECRET_KEY environment variable.")

# Flask Debug Mode
debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'

# Helper Functions
def save_tokens_to_db(access_token, refresh_token, realm_id, expiry=None):
    if not supabase:
        logging.error("Supabase client is not initialized.")
        raise Exception("Supabase client is not available.")
    data = {
        "user_id": "default_user",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "realm_id": realm_id,
        "last_updated": datetime.utcnow().isoformat(),
        "token_expiry": expiry
    }
    response = supabase.table("tokens").upsert(data).execute()
    logging.info(f"Supabase response: {response}")
    if not response.data:
        logging.error(f"Failed to save tokens: {response}")
        raise Exception(f"Failed to save tokens: {response}")
    logging.info("Tokens saved to Supabase successfully.")

def get_tokens_from_db():
    if not supabase:
        logging.error("Supabase client is not initialized.")
        raise Exception("Supabase client is not available.")
    response = supabase.table("tokens").select("*").eq("user_id", "default_user").execute()
    if not response.data:
        logging.error("No tokens found for the user in Supabase.")
        return None, None, None, None
    token = response.data[0]
    return token["access_token"], token["refresh_token"], token["realm_id"], token.get("token_expiry")

def refresh_access_token():
    _, refresh_token, _, _ = get_tokens_from_db()
    auth_header = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    payload = {'grant_type': 'refresh_token', 'refresh_token': refresh_token}
    headers = {'Accept': 'application/json'}
    logging.info("Attempting to refresh access token...")
    response = requests.post(TOKEN_URL, auth=auth_header, data=payload, headers=headers)
    if response.status_code == 200:
        tokens = response.json()
        expiry_time = (datetime.utcnow() + timedelta(seconds=tokens['expires_in'])).isoformat()
        save_tokens_to_db(tokens['access_token'], tokens['refresh_token'], os.getenv('COMPANY_ID'), expiry=expiry_time)
        logging.info("Access token refreshed successfully.")
    else:
        logging.error(f"Failed to refresh access token: {response.text}")
        raise Exception(response.text)

def get_company_info():
    access_token, _, realm_id, expiry = get_tokens_from_db()
    if expiry and datetime.utcnow().isoformat() > expiry:
        logging.info("Token expired. Refreshing...")
        refresh_access_token()
        access_token, _, _, _ = get_tokens_from_db()

    headers = {
        'Authorization': f"Bearer {access_token}",
        'Accept': 'application/json'
    }
    query = "SELECT * FROM CompanyInfo"
    api_url = f"https://sandbox-quickbooks.api.intuit.com/v3/company/{realm_id}/query?query={query}&minorversion=14"
    response = requests.get(api_url, headers=headers)
    if response.status_code == 401:
        logging.info("Access token expired. Attempting refresh...")
        refresh_access_token()
        access_token, _, _, _ = get_tokens_from_db()
        headers['Authorization'] = f"Bearer {access_token}"
        response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        return response.json().get("QueryResponse", {}).get("CompanyInfo", [])[0]
    else:
        raise Exception(response.text)

# Flask Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    auth_url = f"{AUTHORIZATION_BASE_URL}?client_id={CLIENT_ID}&response_type=code&scope={SCOPE}&redirect_uri={REDIRECT_URI}&state=RandomStateString"
    logging.info(f"Redirecting to QuickBooks login: {auth_url}")
    return redirect(auth_url)

@app.route('/logout')
def logout():
    return redirect(url_for('index'))


@app.route('/callback')
def callback():
    try:
        logging.info(f"Callback request args: {request.args}")
        error = request.args.get('error')
        if error:
            return f"Error during OAuth2: {error}", 400
        code = request.args.get('code')
        realm_id = request.args.get('realmId')
        auth_header = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
        payload = {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': REDIRECT_URI}
        headers = {'Accept': 'application/json'}
        response = requests.post(TOKEN_URL, auth=auth_header, data=payload, headers=headers)
        if response.status_code != 200:
            raise Exception(response.text)
        tokens = response.json()
        expiry_time = (datetime.utcnow() + timedelta(seconds=tokens['expires_in'])).isoformat()
        save_tokens_to_db(tokens['access_token'], tokens['refresh_token'], realm_id, expiry=expiry_time)
        return redirect(url_for('dashboard'))
    except Exception as e:
        logging.error(f"Error in /callback: {e}")
        return {"error": str(e)}, 500

@app.route('/dashboard')
def dashboard():
    try:
        company_info = get_company_info()
        return render_template('dashboard.html', data=company_info)
    except Exception as e:
        logging.error(f"Error in /dashboard: {e}")
        return {"error": str(e)}, 500

@app.route('/business-info', methods=['GET'])
def business_info():
    try:
        company_info = get_company_info()
        return {
            "companyName": company_info.get("CompanyName"),
            "legalName": company_info.get("LegalName"),
            "address": company_info.get("CompanyAddr", {}).get("Line1"),
            "phone": company_info.get("PrimaryPhone", {}).get("FreeFormNumber"),
            "email": company_info.get("Email", {}).get("Address")
        }, 200
    except Exception as e:
        logging.error(f"Error in /business-info: {e}")
        return {"error": str(e)}, 500

if __name__ == '__main__':
    app.run(debug=debug_mode)
