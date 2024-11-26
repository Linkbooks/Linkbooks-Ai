from flask import Flask, render_template, redirect, request, url_for
from dotenv import load_dotenv
import os
import requests
import logging
from datetime import datetime
from supabase import create_client
import openai

# Load environment variables from .env
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO)

# Supabase Configuration
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

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
app.secret_key = 'be8ca2b4f7c5380136cd8cd6088dd3e1'


# Helper Functions
def save_tokens_to_db(access_token, refresh_token, realm_id):
    """Save or update tokens in the Supabase database."""
    data = {
        "user_id": "default_user",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "realm_id": realm_id,
        "last_updated": datetime.utcnow().isoformat()
    }
    response = supabase.table("tokens").upsert(data).execute()
    if response.status_code != 200:
        raise Exception(f"Failed to save tokens: {response.error}")
    logging.info("Tokens saved to Supabase successfully.")

def get_tokens_from_db():
    """Retrieve tokens from the Supabase database."""
    response = supabase.table("tokens").select("*").eq("user_id", "default_user").execute()
    if response.status_code != 200 or not response.data:
        raise Exception(f"Failed to fetch tokens: {response.error}")
    token = response.data[0]
    return token["access_token"], token["refresh_token"], token["realm_id"]

def refresh_access_token():
    """Refresh the access token using the refresh token."""
    _, refresh_token, _ = get_tokens_from_db()
    auth_header = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    payload = {'grant_type': 'refresh_token', 'refresh_token': refresh_token}
    headers = {'Accept': 'application/json'}
    logging.info("Attempting to refresh access token...")
    response = requests.post(TOKEN_URL, auth=auth_header, data=payload, headers=headers)

    if response.status_code == 200:
        tokens = response.json()
        save_tokens_to_db(tokens['access_token'], tokens['refresh_token'], os.getenv('COMPANY_ID'))
        logging.info("Access token refreshed successfully.")
    else:
        error_msg = f"Failed to refresh access token: {response.text}"
        logging.error(error_msg)
        raise Exception(error_msg)

def get_company_info():
    """Fetch company info from QuickBooks."""
    access_token, _, realm_id = get_tokens_from_db()
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
        access_token, _, _ = get_tokens_from_db()
        headers['Authorization'] = f"Bearer {access_token}"
        response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        return data.get("QueryResponse", {}).get("CompanyInfo", [])[0]
    else:
        raise Exception(f"Failed to fetch company info: {response.text}")


# Flask Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    auth_url = (
        f"{AUTHORIZATION_BASE_URL}?client_id={CLIENT_ID}"
        f"&response_type=code&scope={SCOPE}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&state=RandomStateString"
    )
    logging.info(f"Redirecting to QuickBooks login: {auth_url}")
    return redirect(auth_url)

@app.route('/callback')
def callback():
    error = request.args.get('error')
    if error:
        logging.error(f"OAuth2 error: {error}")
        return f"Error during OAuth2: {error}", 400

    code = request.args.get('code')
    realm_id = request.args.get('realmId')
    if not code or not realm_id:
        logging.error("Missing code or realmId in callback.")
        return "Missing code or realmId in callback.", 400

    auth_header = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    payload = {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': REDIRECT_URI}
    headers = {'Accept': 'application/json'}
    response = requests.post(TOKEN_URL, auth=auth_header, data=payload, headers=headers)

    if response.status_code == 200:
        tokens = response.json()
        save_tokens_to_db(tokens['access_token'], tokens['refresh_token'], realm_id)
        logging.info("OAuth flow completed successfully and tokens saved to Supabase.")
        return redirect(url_for('dashboard'))
    else:
        logging.error(f"Failed to obtain tokens: {response.text}")
        return f"Failed to obtain tokens: {response.text}", 400

@app.route('/dashboard')
def dashboard():
    try:
        company_info = get_company_info()
        return render_template('dashboard.html', data=company_info)
    except Exception as e:
        logging.error(f"Error fetching company info: {e}")
        return str(e), 500

@app.route('/business-info', methods=['GET'])
def business_info():
    try:
        company_info = get_company_info()
        simplified_info = {
            "companyName": company_info.get("CompanyName"),
            "legalName": company_info.get("LegalName"),
            "address": company_info.get("CompanyAddr", {}).get("Line1"),
            "phone": company_info.get("PrimaryPhone", {}).get("FreeFormNumber"),
            "email": company_info.get("Email", {}).get("Address"),
        }
        return simplified_info
    except Exception as e:
        logging.error(f"Error fetching business info: {e}")
        return {"error": str(e)}, 500

@app.route('/analyze', methods=['GET'])
def analyze():
    try:
        company_info = get_company_info()
        prompt = f"Summarize this company information in a professional tone: {company_info}"
        openai_response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a professional assistant summarizing company information."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=200
        )
        analysis = openai_response.choices[0].message['content']
        return {"analysis": analysis, "companyInfo": company_info}
    except Exception as e:
        logging.error(f"Error analyzing company info: {e}")
        return {"error": str(e)}, 500

@app.route('/logout')
def logout():
    logging.info("User logged out.")
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
