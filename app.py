import os
import logging
import requests
import secrets
import bcrypt
import time
from flask import render_template, redirect, request, make_response, url_for, send_from_directory, jsonify, Flask
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


# Loading Env File for Running app locally On/Off
if os.getenv("FLASK_ENV") == "development":
    load_dotenv()

# Determine if in development mode
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

# Validate critical environment variables early
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
        print(f"{key}: {'*****' if 'KEY' in key or 'SECRET' in key else value}")



# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')
if not app.secret_key:
    raise RuntimeError("Missing FLASK_SECRET_KEY environment variable.")

# Initialize Limiter (for newer versions)
limiter = Limiter(
    key_func=get_remote_address  # Determine how the rate limit key should be assigned (e.g., by IP address)
)
limiter.init_app(app)  # Attach the limiter to the Flask app


# Supabase Initialization
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
try:
    client_options = ClientOptions(postgrest_client_timeout=30)  # Timeout in seconds
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY, options=client_options)
    logging.info("Supabase client initialized successfully.")
except Exception as e:
    logging.error(f"Error initializing Supabase client: {e}")
    supabase = None


# QuickBooks OAuth Configuration
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


# Initialize OpenAI client
openai_client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

# Flask Debug Mode
debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'

# Helper Functions
def save_tokens_to_db(access_token, refresh_token, realm_id, expiry=None, email=None):
    if not supabase:
        logging.error("Supabase client is not initialized.")
        raise Exception("Supabase client is not available.")
    
    data = {
        "email": email,  # Link tokens to the user's email
        "access_token": access_token,
        "refresh_token": refresh_token,
        "realm_id": realm_id,
        "last_updated": datetime.utcnow().isoformat(),
        "token_expiry": expiry
    }

    response = supabase.table("users").upsert(data).execute()
    if not response.data:
        logging.error(f"Failed to save tokens: {response}")
        raise Exception(f"Failed to save tokens: {response}")
    logging.info("Tokens saved to Supabase successfully.")


def create_user_with_email(user_data):
    # Assuming 'user_data' is a dictionary with user fields (e.g., name, phone, address, email, password)
    email = user_data.get("email")
    password = user_data.get("password")  # Expecting password to come with user data
    name = user_data.get("name")
    phone = user_data.get("phone")
    address = user_data.get("address")
    
    # Step 1: Create the user in Supabase Auth with the password
    try:
        auth_response = supabase.auth.sign_up({
            "email": email,
            "password": password  # Supabase will handle the password securely and send verification email
        })
        
        if auth_response.get('user'):
            user_id = auth_response['user']['id']
            logging.info(f"User {name} created successfully in Supabase Auth with ID: {user_id}")
        else:
            logging.error(f"Error creating user in Supabase Auth: {auth_response}")
            return {"error": "Failed to create user in Supabase Auth."}, 500
        
    except Exception as e:
        logging.error(f"Error creating user in Supabase Auth: {e}")
        return {"error": "Failed to create user."}, 500

    # Step 2: Insert the additional user data (name, phone, address) into the user_profiles table
    try:
        profile_response = supabase.table('user_profiles').insert({
            'id': user_id,  # Link the new user to their profile
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

def refresh_access_token(user_id):
    """
    Refreshes the QuickBooks access token for the given user_id.
    """
    quickbooks_data = get_quickbooks_tokens(user_id)  # Retrieve tokens for this user

    if not quickbooks_data:
        logging.error(f"No QuickBooks tokens found for user_id: {user_id}")
        raise Exception("No QuickBooks tokens found for the user.")

    refresh_token = quickbooks_data['refresh_token']
    auth_header = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    payload = {'grant_type': 'refresh_token', 'refresh_token': refresh_token}
    headers = {'Accept': 'application/json'}

    logging.info(f"Attempting to refresh access token for user_id: {user_id}...")
    response = requests.post(TOKEN_URL, auth=auth_header, data=payload, headers=headers)

    if response.status_code == 200:
        tokens = response.json()
        new_access_token = tokens['access_token']
        new_refresh_token = tokens.get('refresh_token', refresh_token)  # Some APIs might not return a new refresh token
        new_expiry = (datetime.utcnow() + timedelta(seconds=tokens['expires_in'])).isoformat()

        # Save updated tokens to the database
        save_quickbooks_tokens(
            user_id=user_id,
            realm_id=quickbooks_data['realm_id'],
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            token_expiry=new_expiry
        )
        logging.info(f"Access token refreshed and saved successfully for user_id: {user_id}.")
    else:
        logging.error(f"Failed to refresh access token for user_id {user_id}: {response.text}")
        raise Exception(response.text)



def save_quickbooks_tokens(user_id, realm_id, access_token, refresh_token, token_expiry):
    """
    Save QuickBooks tokens to the quickbooks_tokens table.
    """
    try:
        # Convert datetime to ISO string format
        token_expiry_str = token_expiry.isoformat() if isinstance(token_expiry, datetime) else token_expiry

        data = {
            "id": user_id,
            "realm_id": realm_id,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_expiry": token_expiry_str,  # Store as ISO string
            "last_updated": datetime.utcnow().isoformat()
        }
        supabase.table("quickbooks_tokens").upsert(data).execute()
        logging.info("QuickBooks tokens saved successfully.")
    except Exception as e:
        logging.error(f"Error saving QuickBooks tokens: {e}")
        raise Exception("Failed to save QuickBooks tokens.")

def get_quickbooks_tokens(user_id):
    """
    Retrieve QuickBooks tokens for a given user.
    """
    try:
        response = supabase.table("quickbooks_tokens").select("*").eq("id", user_id).execute()
        if not response.data:
            raise Exception("No QuickBooks tokens found for the user.")
        return response.data[0]
    except Exception as e:
        logging.error(f"Error fetching QuickBooks tokens: {e}")
        raise Exception("Failed to fetch QuickBooks tokens.")

def generate_session_token(user_id, email):
    """
    Generates a JWT token with a 24-hour expiration time.
    """
    token = jwt.encode(
        {
            "user_id": user_id,  # Include user_id in the payload
            "email": email,      # Include email for context
            "exp": datetime.now(timezone.utc) + timedelta(hours=24)  # Timezone-aware expiration
        },
        SECRET_KEY,
        algorithm="HS256"
    )
    return token

 
def get_authenticated_user_email():
    token = request.headers.get("Authorization")
    if not token:
        raise Exception("No Authorization token provided")
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return decoded["email"]
    except jwt.ExpiredSignatureError:
        raise Exception("Token has expired")
    except jwt.InvalidTokenError:
        raise Exception("Invalid token")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        raise Exception("An unexpected error occurred")

def get_tokens_by_user_id(user_id):
    """
    Fetch QuickBooks tokens from the Supabase table based on the user ID.
    """
    try:
        response = supabase.table("quickbooks_tokens").select("*").eq("id", user_id).execute()
        data = response.data

        if not data:
            logging.warning(f"No QuickBooks tokens found for user ID: {user_id}")
            return None, None, None, None

        token_data = data[0]
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        realm_id = token_data.get("realm_id")
        token_expiry = token_data.get("token_expiry")

        return access_token, refresh_token, realm_id, token_expiry

    except Exception as e:
        logging.error(f"Error fetching QuickBooks tokens: {e}")
        return None, None, None, None

def clean_expired_states():
    """
    Delete expired OAuth states from the chatgpt_oauth_states table.
    """
    try:
        supabase.table("chatgpt_oauth_states").delete().lte("expiry", datetime.utcnow().isoformat()).execute()
        logging.info("Expired OAuth states cleaned up.")
    except Exception as e:
        logging.error(f"Error cleaning expired OAuth states: {e}")

def refresh_quickbooks_tokens(chat_session_id, refresh_token):
    try:
        auth_header = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
        payload = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token
        }
        headers = {'Accept': 'application/json'}

        response = requests.post(TOKEN_URL, auth=auth_header, data=payload, headers=headers)

        if response.status_code != 200:
            raise Exception(f"Failed to refresh tokens: {response.text}")

        tokens = response.json()
        new_access_token = tokens['access_token']
        new_refresh_token = tokens.get('refresh_token', refresh_token)  # Use old refresh_token if new one isn't provided
        new_expiry = datetime.utcnow() + timedelta(seconds=tokens['expires_in'])

        # Update tokens in database
        supabase.table("chatgpt_tokens").update({
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "expiry": new_expiry.isoformat()
        }).eq("chat_session_id", chat_session_id).execute()

        return new_access_token

    except Exception as e:
        logging.error(f"Error refreshing tokens for {chat_session_id}: {e}")
        raise


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




def get_tokens_by_email(email):
    if not supabase:
        logging.error("Supabase client is not initialized.")
        raise Exception("Supabase client is not available.")

    response = supabase.table("users").select("*").eq("email", email).execute()
    if not response.data:
        logging.warning(f"No tokens found for the given email: {email}")
        return None, None, None, None  # Return None values instead of raising an exception

    token_data = response.data[0]
    return (
        token_data["access_token"],
        token_data["refresh_token"],
        token_data["realm_id"],
        token_data.get("token_expiry")
    )


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        """
        Decorator to require and validate JWT tokens for protected routes.
        """
        token = request.cookies.get("session_token")  # Get token from cookies
        if not token:
            return {"error": "No Authorization token provided"}, 401
        
        try:
            # Decode the token and extract user_id
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user_id = decoded.get("user_id")  # Attach the user's user_id to the request
            if not request.user_id:
                raise Exception("No user_id found in the token.")
        except jwt.ExpiredSignatureError:
            return {"error": "Token has expired"}, 401
        except jwt.InvalidTokenError:
            return {"error": "Invalid token"}, 401
        except Exception as e:
            return {"error": "Unauthorized access. Please log in again."}, 401
        
        return f(*args, **kwargs)
    return decorated



def get_company_info(user_id):
    try:
        # Fetch tokens using user_id
        tokens = get_quickbooks_tokens(user_id)
        access_token = tokens.get('access_token')
        refresh_token = tokens.get('refresh_token')
        realm_id = tokens.get('realm_id')
        expiry = tokens.get('token_expiry')

        if not access_token:
            logging.error("Access token missing.")
            raise Exception("No access token found. QuickBooks disconnected.")

        # Validate token expiry
        if expiry and datetime.utcnow() > datetime.fromisoformat(expiry):
            logging.info("Access token expired. Refreshing...")
            refresh_access_token(user_id)
            tokens = get_quickbooks_tokens(user_id)
            access_token = tokens.get('access_token')
            refresh_token = tokens.get('refresh_token')
            realm_id = tokens.get('realm_id')
            expiry = tokens.get('token_expiry')

        # Use the correct API base URL based on environment
        api_base_url = QUICKBOOKS_API_BASE_URL

        # Attempt to fetch company info using the correct endpoint
        headers = {
            'Authorization': f"Bearer {access_token}",
            'Accept': 'application/json'
        }
        api_url = f"{api_base_url}{realm_id}/companyinfo/{realm_id}"
        response = requests.get(api_url, headers=headers)

        logging.debug(f"QuickBooks API Request URL: {api_url}")
        logging.debug(f"QuickBooks API Response Status: {response.status_code}")

        if response.status_code == 401:
            # Token expired during request, try refreshing again
            logging.info("Access token expired during request. Refreshing...")
            refresh_access_token(user_id)
            tokens = get_quickbooks_tokens(user_id)
            access_token = tokens.get('access_token')
            realm_id = tokens.get('realm_id')
            headers['Authorization'] = f"Bearer {access_token}"
            response = requests.get(api_url, headers=headers)

            logging.debug(f"QuickBooks API Retry Response Status: {response.status_code}")

        if response.status_code == 200:
            return response.json().get("CompanyInfo", {})
        else:
            logging.error(f"QuickBooks API Error: {response.status_code} - {response.text}")
            raise Exception(f"Failed to fetch company info: {response.status_code} {response.text}")
    except Exception as e:
        logging.error(f"Error in get_company_info: {e}")
        raise


    

    
def fetch_report(user_id, report_type, start_date=None, end_date=None):
    try:
        # Fetch tokens
        tokens = get_quickbooks_tokens(user_id)
        access_token = tokens.get('access_token')
        refresh_token = tokens.get('refresh_token')
        realm_id = tokens.get('realm_id')
        expiry = tokens.get('token_expiry')

        if not access_token or not realm_id:
            logging.error("Missing access token or realm_id.")
            raise Exception("QuickBooks tokens are incomplete.")

        # Validate token expiry
        if expiry and datetime.utcnow() > datetime.fromisoformat(expiry):
            logging.info("Access token expired. Refreshing...")
            refresh_access_token(user_id)
            tokens = get_quickbooks_tokens(user_id)
            access_token = tokens.get('access_token')
            refresh_token = tokens.get('refresh_token')
            realm_id = tokens.get('realm_id')
            expiry = tokens.get('token_expiry')

        # Use the correct API base URL based on environment
        api_base_url = QUICKBOOKS_API_BASE_URL

        # Construct API request
        headers = {
            'Authorization': f"Bearer {access_token}",
            'Accept': 'application/json'
        }
        base_url = f'{api_base_url}{realm_id}/reports/{report_type}'
        params = {}
        if start_date:
            params['start_date'] = start_date
        if end_date:
            params['end_date'] = end_date

        response = requests.get(base_url, headers=headers, params=params)

        logging.debug(f"QuickBooks Report Request URL: {base_url}")
        logging.debug(f"QuickBooks Report Response Status: {response.status_code}")

        # Handle token expiration during request
        if response.status_code == 401:
            logging.info("Access token expired during report request. Refreshing...")
            refresh_access_token(user_id)
            tokens = get_quickbooks_tokens(user_id)
            access_token = tokens.get('access_token')
            realm_id = tokens.get('realm_id')
            headers['Authorization'] = f"Bearer {access_token}"
            response = requests.get(base_url, headers=headers, params=params)

            logging.debug(f"QuickBooks Report Retry Response Status: {response.status_code}")

        # Check response status
        if response.status_code == 200:
            logging.info(f"Successfully fetched {report_type} report.")
            return response.json()
        else:
            logging.error(f"QuickBooks Report API Error: {response.status_code} - {response.text}")
            raise Exception(f"Failed to fetch report: {response.status_code} {response.text}")
    except Exception as e:
        logging.error(f"Error in fetch_report: {e}")
        raise



def get_reports():
    """
    Returns a list of supported QuickBooks reports.

    :return: List of supported report types.
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



# Flask Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", error_message="Too many login attempts. Please try again in a minute.")
def login():
    if request.method == 'GET':
        return render_template('login.html')

    try:
        data = request.form
        email = data.get('email').strip().lower()
        password = data.get('password')
        chat_session_id = request.args.get('chatSessionId')  # Get ChatGPT session ID if provided

        logging.info(f"Received chatSessionId: {chat_session_id}")  # Log chatSessionId

        # Validation for Missing Fields
        if not email or not password:
            error_message = "Email and password are required."
            return render_template('login.html', error_message=error_message), 400

        # Check if the user exists
        response = supabase.table("users").select("id").eq("email", email).execute()
        if not response.data or len(response.data) == 0:
            error_message = "No account found with that email."
            return render_template('login.html', error_message=error_message), 401

        user_id = response.data[0]["id"]

        # Authenticate user
        try:
            auth_response = supabase.auth.sign_in_with_password({"email": email, "password": password})
        except AuthApiError as e:
            error_message = "Invalid login credentials." if "invalid" in str(e).lower() else "An error occurred during login."
            return render_template('login.html', error_message=error_message), 401

        # Generate session token
        token = generate_session_token(user_id, email)
        logging.info(f"Generated session token for user ID: {user_id}")

        # Set token in cookie
        resp = make_response(
            redirect(
                url_for('link_chat_session', chatSessionId=chat_session_id) if chat_session_id else url_for('dashboard')
            )
        )
        resp.set_cookie(
            "session_token",
            token,
            httponly=True,
            secure=True,
            samesite='Lax'
        )
        logging.info(f"Session token set for user ID: {user_id}")
        return resp

    except Exception as e:
        logging.error(f"Error during login: {e}", exc_info=True)
        error_message = "An unexpected error occurred during login. Please try again."
        return render_template('login.html', error_message=error_message), 500




# Create Account Route

@app.route('/create-account', methods=['GET'])
def create_account_form():
    return render_template('create_account.html')


@app.route('/create-account', methods=['POST'])
def create_account():
    data = request.form
    name = data.get('name').strip()
    email = data.get('email').strip().lower()  # Convert to lowercase
    password = data.get('password')
    confirm_password = data.get('confirm_password')
    phone = data.get('phone').strip()
    address = data.get('address').strip()

    logging.info(f"Attempting to create account for email: {email}")

    # Validate input
    if not email or not password or not confirm_password:
        error_message = "Email and passwords are required."
        logging.warning("Account creation failed: Missing email or passwords.")
        return jsonify({"success": False, "error_message": error_message}), 400

    if password != confirm_password:
        error_message = "Passwords do not match."
        logging.warning("Account creation failed: Passwords do not match.")
        return jsonify({"success": False, "error_message": error_message}), 400

    # Validate password length
    if len(password) < 6:
        error_message = "Password must be at least 6 characters long."
        logging.warning(f"Account creation failed: Password too short for email {email}.")
        return jsonify({"success": False, "error_message": error_message}), 400

    # Check for an existing account in the `users` table
    try:
        response = supabase.table("users").select("id").eq("email", email).execute()
        if response.data:
            logging.info(f"Existing user found with email: {email}")
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
            logging.error(f"Auth error: {error_message}")
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

    # Insert user profile information
    try:
        user_profile = {
            "id": user_id,
            "name": name,
            "phone": phone,
            "address": address,
            "gpt_config": {"default_behavior": "friendly"},  # Example placeholder
            "is_verified": False  # Default verification status
        }
        supabase.table("user_profiles").insert(user_profile).execute()
        logging.info(f"User profile created for ID: {user_id}")
    except Exception as e:
        logging.error(f"Error inserting user profile: {e}")
        error_message = "Failed to save user profile."
        return jsonify({"success": False, "error_message": error_message}), 500

    # All steps succeeded, send success response
    success_message = "Account created successfully! A verification email has been sent to your email address. Please check your inbox to verify your account."
    return jsonify({"success": True, "success_message": success_message}), 200


    
@app.route('/confirmation')
def confirmation():
    return render_template('confirmation.html')  # Create a 'confirmation.html' in your templates folder.


@app.route('/fetch-user-data', methods=['GET'])
@token_required
def fetch_user_data():
    """
    Fetches QuickBooks data for the authenticated user.
    """
    try:
        # Get user's email from JWT
        user_email = get_authenticated_user_email()

        # Fetch QuickBooks tokens
        access_token, _, realm_id, expiry = get_tokens_by_email(user_email)

        # Check if token is expired
        if expiry and datetime.utcnow() > datetime.fromisoformat(expiry):
            logging.info("Token expired. Refreshing...")
            refresh_access_token()
            access_token, _, realm_id, _ = get_tokens_by_email(user_email)

        # Fetch data using access_token
        headers = {
            'Authorization': f"Bearer {access_token}",
            'Accept': 'application/json'
        }
        response = requests.get(f"https://quickbooks.api.intuit.com/v3/company/{realm_id}/some-endpoint", headers=headers)

        if response.status_code == 200:
            return response.json(), 200
        else:
            logging.error(f"Error fetching user data: {response.text}")
            return {"error": f"Failed to fetch data: {response.text}"}, response.status_code
    except Exception as e:
        logging.error(f"Error in /fetch-user-data: {e}")
        return {"error": str(e)}, 500


@app.route('/quickbooks-login')
def quickbooks_login():
    """
    Handles QuickBooks OAuth login.
    """
    auth_url = f"{AUTHORIZATION_BASE_URL}?client_id={CLIENT_ID}&response_type=code&scope={SCOPE}&redirect_uri={REDIRECT_URI}&state=RandomStateString"
    logging.info(f"Redirecting to QuickBooks login: {auth_url}")
    return redirect(auth_url)


@app.route('/logout')
def logout():
    try:
        session_token = request.cookies.get('session_token')
        if not session_token:
            logging.warning("No session token found during logout.")
            return render_template('logout.html', message="You have been successfully logged out.")

        decoded = jwt.decode(session_token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded.get("user_id")

        if not user_id:
            logging.warning("No user ID found in session token during logout.")
            return render_template('logout.html', message="You have been successfully logged out.")

        # Fetch the QuickBooks tokens from the database
        response = supabase.table("quickbooks_tokens").select("refresh_token").eq("id", user_id).execute()
        if response.data and response.data[0].get("refresh_token"):
            revoke_quickbooks_tokens(response.data[0]["refresh_token"])

        # Clear the session data in Supabase
        supabase.table("quickbooks_tokens").delete().eq("id", user_id).execute()
        supabase.table("chatgpt_tokens").delete().eq("user_id", user_id).execute()

        # Clear the session cookie
        response = make_response(render_template('logout.html', message="You have been successfully logged out."))
        response.delete_cookie('session_token')

        logging.info(f"User {user_id} logged out successfully.")
        return response

    except Exception as e:
        logging.error(f"Error during logout: {e}")
        return render_template('logout.html', message="An error occurred during logout. Please try again.")


    
    #------------CHAT GPT LOGIN------------------------------------#

def store_state(chat_session_id, state):
    """
    Store the state value associated with the chatSessionId in the Supabase database.
    """
    try:
        # Insert or update the state in Supabase
        response = supabase.table("chatgpt_oauth_states").upsert({
            "chat_session_id": chat_session_id,
            "state": state,
            "expiry": (datetime.utcnow() + timedelta(minutes=10)).isoformat()  # 10-minute expiry
        }).execute()

        if not response.data:
            raise Exception("Failed to store state in Supabase")
    except Exception as e:
        logging.error(f"Error in store_state: {e}")
        raise


@app.route('/oauth/start-for-chatgpt', methods=['GET'])
def start_oauth_for_chatgpt():
    """
    Handles the login flow for ChatGPT users by ensuring they are authenticated with the middleware app first.
    """
    try:
        # Get the ChatGPT session ID
        chat_session_id = request.args.get('chatSessionId')
        if not chat_session_id:
            return jsonify({"error": "chatSessionId is required"}), 400

        # Check if the session is linked to a middleware user
        user_check = supabase.table("user_profiles").select("id").eq("chat_session_id", chat_session_id).execute()

        if not user_check.data:
            # Redirect to the middleware app login URL
            middleware_login_url = f"https://quickbooks-gpt-app.onrender.com/login?chatSessionId={chat_session_id}"
            return jsonify({"loginUrl": middleware_login_url}), 200

        # Generate a unique state value for CSRF protection
        state = f"{chat_session_id}-{secrets.token_hex(8)}"

        # Store the state in Supabase
        store_state(chat_session_id, state)

        # Construct the QuickBooks OAuth login URL
        quickbooks_oauth_url = (
            f"{AUTHORIZATION_BASE_URL}?"
            f"client_id={CLIENT_ID}&"
            f"response_type=code&"
            f"scope={SCOPE}&"
            f"redirect_uri={REDIRECT_URI}&"
            f"state={state}"
        )

        # Return the QuickBooks login URL
        return jsonify({"loginUrl": quickbooks_oauth_url}), 200

    except Exception as e:
        logging.error(f"Error in start_oauth_for_chatgpt: {e}")
        return jsonify({"error": str(e)}), 500



@app.route('/link-chat-session', methods=['POST'])
def link_chat_session():
    """
    Links a ChatGPT chatSessionId to the logged-in user in Supabase.
    """
    try:
        data = request.json
        chat_session_id = data.get('chatSessionId')
        session_token = request.cookies.get('session_token')

        if not chat_session_id:
            return jsonify({"error": "chatSessionId is required"}), 400

        if not session_token:
            return jsonify({"error": "User not authenticated. Please log in first."}), 401

        # Decode the session token
        decoded = jwt.decode(session_token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded.get("user_id")

        if not user_id:
            return jsonify({"error": "Invalid session token"}), 401

        # Link chatSessionId to the user
        response = supabase.table("user_profiles").update({
            "chat_session_id": chat_session_id
        }).eq("id", user_id).execute()

        if not response.data:
            return jsonify({"error": "Failed to link chatSessionId to user"}), 500

        return jsonify({"success": True, "message": "chatSessionId linked successfully"}), 200

    except Exception as e:
        logging.error(f"Error linking chatSessionId: {e}")
        return jsonify({"error": "An error occurred while linking chatSessionId. Try again later."}), 500


@app.route('/session/status', methods=['GET'])
def get_session_status():
    """
    Checks the authentication status of a ChatGPT session.
    """
    try:
        chat_session_id = request.args.get('chatSessionId')
        if not chat_session_id:
            return jsonify({"authenticated": False, "message": "chatSessionId is required"}), 400

        response = supabase.table("chatgpt_tokens").select("*").eq("chat_session_id", chat_session_id).execute()
        if not response.data:
            return jsonify({"authenticated": False, "message": "No tokens found. Please log in."}), 401

        tokens = response.data[0]
        expiry = datetime.fromisoformat(tokens['expiry'])

        if datetime.utcnow() > expiry:
            logging.info(f"Access token for chatSessionId {chat_session_id} expired.")
            return jsonify({"authenticated": False, "message": "Session expired. Please reauthenticate."}), 401

        return jsonify({"authenticated": True, "message": "Session is active."}), 200

    except Exception as e:
        logging.error(f"Error in /session/status: {e}")
        return jsonify({"authenticated": False, "message": "An error occurred. Try again later."}), 500



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
        new_refresh_token = tokens.get('refresh_token', refresh_token)  # Use existing refresh token if not provided
        expiry = (datetime.utcnow() + timedelta(seconds=tokens['expires_in'])).isoformat()

        # Update tokens in Supabase
        try:
            response = supabase.table("chatgpt_tokens").update({
                "access_token": access_token,
                "refresh_token": new_refresh_token,
                "expiry": expiry
            }).eq("chat_session_id", chat_session_id).execute()

            if not response.data:
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


@app.route('/preferences', methods=['GET'])
def fetch_preferences():
    """
    Fetches the personalization note from the user_profiles table for a given ChatGPT session ID.
    """
    try:
        # Get chatSessionId from query parameters
        chat_session_id = request.args.get('chatSessionId')
        if not chat_session_id:
            return jsonify({"error": "chatSessionId is required"}), 400

        # Fetch the user's profile using the chatSessionId
        response = supabase.table("user_profiles").select("personalization_note").eq("id", chat_session_id).execute()

        if not response.data or not response.data[0].get('personalization_note'):
            return jsonify({
                "personalizationNote": "",
                "message": "No personalization note found. Please add one."
            }), 200

        # Extract personalization note
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
        # Parse input JSON
        data = request.json
        chat_session_id = data.get('chatSessionId')
        personalization_note = data.get('personalizationNote')

        if not chat_session_id:
            return jsonify({"error": "chatSessionId is required"}), 400

        if not personalization_note:
            return jsonify({"error": "personalizationNote is required"}), 400

        if len(personalization_note) > 240:
            return jsonify({"error": "personalizationNote exceeds 240 characters"}), 400

        # Update the personalization note in the user_profiles table
        response = supabase.table("user_profiles").update({
            "personalization_note": personalization_note
        }).eq("id", chat_session_id).execute()

        if not response.data:
            return jsonify({"error": "Failed to update personalization note. Invalid chatSessionId?"}), 400

        return jsonify({
            "message": "Personalization note updated successfully."
        }), 200

    except Exception as e:
        logging.error(f"Error in /preferences/update: {e}")
        return jsonify({"error": str(e)}), 500


#-------------------------------------------------------------#

@app.route('/callback', methods=['GET'])
def callback():
    """
    Handles QuickBooks OAuth callback and stores tokens in Supabase.
    """
    try:
        # Retrieve query parameters
        code = request.args.get('code')
        realm_id = request.args.get('realmId')
        state = request.args.get('state')

        if not code or not realm_id:
            return jsonify({"error": "Missing authorization code or realmId"}), 400

        if not state:
            return jsonify({"error": "Missing state parameter"}), 400

        # Parse state to determine ChatGPT or regular session
        if '-' in state:
            chat_session_id, state_token = state.split('-', 1)
        else:
            chat_session_id, state_token = None, state

        # Validate state (CSRF protection) using Supabase
        state_query = supabase.table("chatgpt_oauth_states").select("*").eq("state", state).execute()
        if not state_query.data or state_query.data[0]['state'] != state:
            return jsonify({"error": "Invalid state parameter"}), 400

        stored_state = state_query.data[0]
        expiry = datetime.fromisoformat(stored_state["expiry"])
        if datetime.utcnow() > expiry:
            return jsonify({"error": "State token expired"}), 400

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
            return jsonify({"error": f"Failed to retrieve tokens: {token_response.text}"}), 400

        # Parse tokens
        tokens = token_response.json()
        access_token = tokens['access_token']
        refresh_token = tokens['refresh_token']
        expiry = datetime.utcnow() + timedelta(seconds=tokens['expires_in'])
        expiry_str = expiry.isoformat()

        # Handle ChatGPT-based sessions
        if chat_session_id:
            # Store tokens for ChatGPT session
            supabase.table("chatgpt_tokens").upsert({
                "chat_session_id": chat_session_id,
                "realm_id": realm_id,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expiry": expiry_str
            }).execute()

            logging.info(f"QuickBooks authorization successful for ChatGPT session {chat_session_id}")
            return jsonify({"success": True, "message": "QuickBooks tokens stored for ChatGPT session"}), 200

        # Handle app-based sessions
        # Retrieve the user ID from the JWT in cookies
        token = request.cookies.get('session_token')
        if not token:
            return jsonify({"error": "No Authorization token provided"}), 401

        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded.get("user_id")

        if not user_id:
            return jsonify({"error": "User ID missing from token"}), 401

        # Store tokens for the app-based user
        supabase.table("user_profiles").update({
            "realm_id": realm_id,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expiry": expiry_str
        }).eq("id", user_id).execute()

        logging.info(f"QuickBooks authorization successful for user {user_id}")
        return redirect(url_for('dashboard') + "?quickbooks_login_success=true")

    except Exception as e:
        logging.error(f"Error in /callback: {e}")
        return jsonify({"error": str(e)}), 500



# Helper function to store tokens for ChatGPT sessions
def store_tokens_for_chatgpt_session(chat_session_id, realm_id, access_token, refresh_token, expiry):
    """
    Stores QuickBooks tokens associated with a ChatGPT session ID in Supabase.
    """
    try:
        # Upsert tokens into the Supabase database
        response = supabase.table("chatgpt_tokens").upsert({
            "chat_session_id": chat_session_id,
            "realm_id": realm_id,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expiry": expiry
        }).execute()

        if not response.data:
            raise Exception("Failed to store tokens in Supabase")

    except Exception as e:
        logging.error(f"Failed to store tokens for ChatGPT session {chat_session_id}: {e}")
        raise




@app.route('/dashboard')
def dashboard():
    try:
        # Check QuickBooks login success flag
        success_message = request.args.get('quickbooks_login_success')

        # Attempt to decode the session_token from cookies to get user_id
        token = request.cookies.get('session_token')
        if not token:
            # No user logged in, show dashboard without QuickBooks data
            logging.info("No session_token found. Showing dashboard with QuickBooks disconnected.")
            return render_template('dashboard.html', success_message=success_message, quickbooks_login_needed=True)

        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            user_id = decoded.get("user_id")
            if not user_id:
                logging.warning("No user_id found in token. Showing disconnected state.")
                return render_template('dashboard.html', success_message=success_message, quickbooks_login_needed=True)
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            # Token invalid or expired, show disconnected state
            logging.warning("Session token invalid or expired. Showing disconnected.")
            return render_template('dashboard.html', success_message=success_message, quickbooks_login_needed=True)

        # If we have a user_id, try fetching QuickBooks info
        # If tokens are missing or invalid, an exception will be raised
        try:
            company_info = get_company_info(user_id)
            # If successful, show QuickBooks data
            return render_template('dashboard.html', data=company_info, success_message=success_message, quickbooks_login_needed=False)
        except Exception as e:
            # Catch the exception from QuickBooks (like 403 error)
            # Show dashboard with QuickBooks disconnected message
            logging.warning(f"Error fetching QuickBooks data: {e}")
            return render_template('dashboard.html', success_message=success_message, quickbooks_login_needed=True)

    except Exception as e:
        logging.error(f"Error in /dashboard: {e}", exc_info=True)
        return {"error": str(e)}, 500


#----------------------------------Functions-----------------------------------------#

@app.route('/fetch-reports', methods=['GET'])
def fetch_reports_route():
    """
    Route to fetch QuickBooks reports.
    """
    try:
        # Get query parameters
        chat_session_id = request.args.get('chatSessionId')
        report_type = request.args.get('reportType')
        start_date = request.args.get('startDate')
        end_date = request.args.get('endDate')

        if not chat_session_id:
            return jsonify({"error": "chatSessionId is required"}), 400

        if not report_type:
            return jsonify({"error": "reportType is required"}), 400

        # Fetch tokens for the given ChatGPT session from Supabase
        response = supabase.table("chatgpt_tokens").select("*").eq("chat_session_id", chat_session_id).execute()

        if not response.data:
            return jsonify({"error": "Invalid or expired chatSessionId"}), 401

        tokens = response.data[0]
        user_id = tokens['realm_id']  # Assuming `realm_id` corresponds to the user
        access_token = tokens['access_token']
        refresh_token = tokens['refresh_token']
        expiry = tokens['expiry']

        # Validate token expiry
        if expiry and datetime.utcnow() > datetime.fromisoformat(expiry):
            logging.info(f"Access token for chatSessionId {chat_session_id} expired. Attempting refresh...")
            try:
                refreshed_tokens = refresh_access_token_for_chatgpt(chat_session_id, refresh_token)
                access_token = refreshed_tokens['access_token']
                user_id = tokens['realm_id']
            except Exception as e:
                logging.error(f"Failed to refresh tokens for chatSessionId {chat_session_id}: {e}")
                return jsonify({"error": "Failed to refresh tokens. Please log in again."}), 401

        # Call the fetch_report utility
        report_data = fetch_report(
            user_id=user_id,
            report_type=report_type,
            start_date=start_date,
            end_date=end_date
        )

        return jsonify({
            "reportType": report_type,
            "data": report_data
        }), 200

    except Exception as e:
        logging.error(f"Error in /fetch-reports: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/business-info', methods=['GET'])
def business_info():
    try:
        token = request.cookies.get('session_token')
        if not token:
            return {"error": "No session token"}, 401

        # Decode the session token
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded.get("user_id")
        if not user_id:
            return {"error": "No user_id in token"}, 401

        # Fetch QuickBooks tokens using user_id
        tokens = get_quickbooks_tokens(user_id)
        access_token = tokens.get('access_token')
        refresh_token = tokens.get('refresh_token')
        realm_id = tokens.get('realm_id')
        expiry = tokens.get('token_expiry')

        if not access_token or not realm_id:
            return {"error": "QuickBooks not connected"}, 400

        # Refresh if expired
        if expiry and datetime.utcnow() > datetime.fromisoformat(expiry):
            refresh_access_token(user_id)
            tokens = get_quickbooks_tokens(user_id)
            access_token = tokens.get('access_token')
            refresh_token = tokens.get('refresh_token')
            realm_id = tokens.get('realm_id')
            expiry = tokens.get('token_expiry')
            if not access_token:
                return {"error": "Could not refresh tokens"}, 400

        # Now fetch company info
        company_info = get_company_info(user_id)
        # If successful, return the company info
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




@app.route('/analyze', methods=['GET'])
def analyze():
    try:
        company_info = get_company_info()
        logging.info(f"Company Info: {company_info}")

        # Enhanced prompt
        prompt = (
            "Analyse the following business details and provide a concise summary, including:\n"
            "- Company name and legal name\n"
            "- Address (city, country, and postal code)\n"
            "- Contact details (phone and email)\n"
            "- Fiscal year start month\n"
            "- Industry type\n"
            "- Subscription status and offerings\n"
            "Present the information in a formal business tone.\n\n"
            f"Company Info:\n{company_info}"
        )

        logging.info(f"Prompt: {prompt}")

        # Use the new SDK's client
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300,
            temperature=0.7
        )

        # Extract the analysis from the response
        analysis = response.choices[0].message.content

        # Render the analysis.html template with the analysis and company info
        return render_template(
            'analysis.html',
            analysis=analysis,
            data=company_info
        )
    except Exception as e:
        logging.error(f"Error in /analyze: {e}")
        return {"error": str(e)}, 500
    
@app.route('/list-reports', methods=['GET'])
def list_reports():
    """
    Returns a list of supported QuickBooks reports.
    """
    try:
        available_reports = get_reports()
        return {
            "availableReports": available_reports,
            "message": "Use the /fetch-reports endpoint with a valid reportType from this list."
        }, 200
    except Exception as e:
        logging.error(f"Error listing reports: {e}")
        return {"error": str(e)}, 500



@app.route('/analyze-reports', methods=['POST'])
def analyze_reports():
    try:
        reports = request.json

        # Validate that reports contain data
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

#---------------------------------------------------------------------------------#


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
        if not openai.api_key:
            raise ValueError("OpenAI API key not loaded")
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": "Test API key"}],
            max_tokens=10
        )
        return {"response": response['choices'][0]['message']['content']}, 200
    except Exception as e:
        return {"error": str(e)}, 500

@app.route('/eula', methods=['GET'])
def eula():
    """
    Serve the End User License Agreement (EULA) page.
    """
    return render_template('eula.html')


@app.route('/privacy-policy', methods=['GET'])
def privacy_policy():
    """
    Serve the Privacy Policy page.
    """
    return render_template('privacy_policy.html')
    
@app.route('/debug-env', methods=['GET'])
def debug_env():
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
    # Don't expose secrets directly, but useful for debugging.
    logging.info(f"Environment variables: {variables}")
    # Return masked results
    return {key: ("*****" if "KEY" in key or "SECRET" in key else value) for key, value in variables.items()}, 200

# Debugging information
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