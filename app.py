import os
import logging
import requests
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
    required_env_vars.extend(['QB_SANDBOX_CLIENT_ID', 'QB_SANDBOX_CLIENT_SECRET'])
else:
    required_env_vars.extend(['QB_PROD_CLIENT_ID', 'QB_PROD_CLIENT_SECRET'])

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
    logging.info("Using Sandbox QuickBooks credentials.")
else:
    CLIENT_ID = os.getenv('QB_PROD_CLIENT_ID')
    CLIENT_SECRET = os.getenv('QB_PROD_CLIENT_SECRET')
    REDIRECT_URI = os.getenv('PROD_REDIRECT_URI')
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

def refresh_access_token():
    user_id = get_authenticated_user_email()  # Retrieve the user ID or email from the session/JWT
    quickbooks_data = get_quickbooks_tokens(user_id)  # Retrieve tokens for this user

    refresh_token = quickbooks_data['refresh_token']
    auth_header = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    payload = {'grant_type': 'refresh_token', 'refresh_token': refresh_token}
    headers = {'Accept': 'application/json'}
    
    logging.info("Attempting to refresh access token...")
    response = requests.post(TOKEN_URL, auth=auth_header, data=payload, headers=headers)
    
    if response.status_code == 200:
        tokens = response.json()
        new_access_token = tokens['access_token']
        new_refresh_token = tokens['refresh_token']
        new_expiry = (datetime.utcnow() + timedelta(seconds=tokens['expires_in'])).isoformat()

        # Save updated tokens to the database
        save_quickbooks_tokens(
            user_id=user_id,
            realm_id=quickbooks_data['realm_id'],
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            token_expiry=new_expiry
        )
        logging.info("Access token refreshed and saved successfully.")
    else:
        logging.error(f"Failed to refresh access token: {response.text}")
        raise Exception(response.text)


def save_quickbooks_tokens(user_id, realm_id, access_token, refresh_token, token_expiry):
    """
    Save QuickBooks tokens to the quickbooks_tokens table.
    """
    try:
        data = {
            "id": user_id,
            "realm_id": realm_id,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_expiry": token_expiry,
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
        token = request.headers.get("Authorization")
        if not token:
            return {"error": "No Authorization token provided"}, 401
        
        try:
            # Decode the token
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user_email = decoded.get("email")  # Attach the user's email to the request
        except jwt.ExpiredSignatureError:
            return {"error": "Token has expired"}, 401
        except jwt.InvalidTokenError:
            return {"error": "Invalid token"}, 401
        except Exception as e:
            return {"error": "Unauthorized access. Please log in again."}, 401
        
        return f(*args, **kwargs)
    return decorated



def get_company_info():
    # Fetch tokens
    access_token, _, realm_id, expiry = get_tokens_by_email(request.user_email)

    # Validate token expiry
    if expiry and datetime.utcnow() > datetime.fromisoformat(expiry):
        logging.info("Token expired. Refreshing...")
        refresh_access_token()

        # Fetch new tokens after refresh
        access_token, _, realm_id, _ = get_tokens_by_email(request.user_email)

    # Use access_token to fetch data
    headers = {
        'Authorization': f"Bearer {access_token}",
        'Accept': 'application/json'
    }
    query = "SELECT * FROM CompanyInfo"
    api_url = f"https://quickbooks.api.intuit.com/v3/company/{realm_id}/query?query={query}&minorversion=14"
    response = requests.get(api_url, headers=headers)

    # Handle expired token error during request
    if response.status_code == 401:
        logging.info("Access token expired during request. Refreshing...")
        refresh_access_token()
        access_token, _, _, _ = get_tokens_by_email(request.user_email)
        headers['Authorization'] = f"Bearer {access_token}"
        response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        return response.json().get("QueryResponse", {}).get("CompanyInfo", [])[0]
    else:
        raise Exception(response.text)

    

    
def fetch_report(report_type, start_date=None, end_date=None):
    """
    Fetches a financial report from QuickBooks.

    :param report_type: Type of report (e.g., ProfitAndLoss, BalanceSheet).
    :param start_date: Start date for the report (YYYY-MM-DD).
    :param end_date: End date for the report (YYYY-MM-DD).
    :return: Report data as JSON.
    """
    # Fetch tokens
    access_token, _, realm_id, expiry = get_tokens_by_email(request.user_email)

    # Validate token expiry
    if expiry and datetime.utcnow() > datetime.fromisoformat(expiry):
        logging.info("Token expired. Refreshing...")
        refresh_access_token()

        # Fetch updated tokens
        access_token, _, realm_id, _ = get_tokens_by_email(request.user_email)

    # Construct API request
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json'
    }
    base_url = f'https://quickbooks.api.intuit.com/v3/company/{realm_id}/reports/{report_type}'
    params = {}
    if start_date:
        params['start_date'] = start_date
    if end_date:
        params['end_date'] = end_date

    response = requests.get(base_url, headers=headers, params=params)

    # Handle token expiration during request
    if response.status_code == 401:
        logging.info("Access token expired during request. Refreshing...")
        refresh_access_token()

        # Retry request with refreshed token
        access_token, _, _, _ = get_tokens_by_email(request.user_email)
        headers['Authorization'] = f'Bearer {access_token}'
        response = requests.get(base_url, headers=headers, params=params)

    # Check response status
    if response.status_code == 200:
        return response.json()
    else:
        logging.error(f"Error fetching report: {response.text}")
        raise Exception(f"Failed to fetch report: {response.status_code} {response.text}")



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

        # Validation for Missing Fields
        if not email or not password:
            error_message = "Email and password are required."
            return render_template('login.html', error_message=error_message), 400

        # Check if the user exists
        response = supabase.table("users").select("id").eq("email", email).execute()
        logging.info(f"Querying public.users for email: {email}, Response: {response}")

        if not response.data or len(response.data) == 0:
            error_message = "No account found with that email."
            logging.warning(f"Login failed: No account found for email {email}.")
            return render_template('login.html', error_message=error_message), 401

        user_id = response.data[0]["id"]

        # User exists, now attempt to sign in via Supabase Auth
        try:
            auth_response = supabase.auth.sign_in_with_password({"email": email, "password": password})
            logging.info(f"Auth response: {auth_response}")
        except AuthApiError as e:
            error_msg = str(e).lower()
            if 'invalid login credentials' in error_msg or 'invalid password' in error_msg:
                error_message = "Invalid password."
            elif 'too many requests' in error_msg or 'rate limit' in error_msg:
                error_message = "Too many login attempts. Please try again later."
            else:
                error_message = "An error occurred during login. Please try again."
            return render_template('login.html', error_message=error_message), 401

        # Generate session token
        token = generate_session_token(user_id, email)
        logging.info(f"Generated session token for user ID: {user_id}")

        # Set token in cookie
        resp = make_response(redirect(url_for('dashboard')))
        resp.set_cookie(
            "session_token",
            token,
            httponly=True,
            secure=True,  # True in production with HTTPS
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
    return redirect(url_for('index'))

@app.route('/callback', methods=['GET'])
def callback():
    """
    Handles QuickBooks OAuth callback and stores tokens in Supabase.
    """
    try:
        # QuickBooks sends the authorization code and realmId
        code = request.args.get('code')
        realm_id = request.args.get('realmId')

        if not code or not realm_id:
            return {"error": "Missing authorization code or realmId"}, 400

        # Exchange code for tokens
        auth_header = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
        payload = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI
        }
        headers = {'Accept': 'application/json'}
        response = requests.post(TOKEN_URL, auth=auth_header, data=payload, headers=headers)

        if response.status_code != 200:
            return {"error": f"Failed to retrieve tokens: {response.text}"}, 400

        # Parse tokens
        tokens = response.json()
        access_token = tokens['access_token']
        refresh_token = tokens['refresh_token']
        expiry = datetime.utcnow() + timedelta(seconds=tokens['expires_in'])

        # Store tokens in Supabase
        user_id = get_authenticated_user_email()  # Extract user ID or email from JWT
        save_quickbooks_tokens(
            user_id=user_id,
            realm_id=realm_id,
            access_token=access_token,
            refresh_token=refresh_token,
            token_expiry=expiry
        )

        logging.info(f"QuickBooks authorization successful for user {user_id}")

        # Redirect to dashboard with success query parameter
        return redirect(url_for('dashboard') + "?quickbooks_login_success=true")

    except Exception as e:
        logging.error(f"Error in /callback: {e}")
        return {"error": str(e)}, 500



@app.route('/dashboard')
def dashboard():
    try:
        # Check for the QuickBooks login success flag
        success_message = request.args.get('quickbooks_login_success')

        if DEV_MODE:
            # In dev mode, skip token check and set a mock user email
            user_email = "dev_user@example.com"
            logging.info("DEV_MODE is enabled. Using mock user email.")
        else:
            # Production mode: perform token check manually
            token = request.headers.get("Authorization")
            if not token:
                logging.warning("Unauthorized access attempt: Missing token.")
                return {"error": "Unauthorized, missing token"}, 401

            try:
                decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
                user_email = decoded.get("email")
                if not user_email:
                    logging.warning("Invalid token payload: No email found.")
                    return {"error": "Invalid token payload, no email"}, 401
            except jwt.ExpiredSignatureError:
                logging.warning("Token has expired.")
                return {"error": "Token has expired"}, 401
            except jwt.InvalidTokenError:
                logging.warning("Invalid token provided.")
                return {"error": "Invalid token"}, 401

        # Now that we have user_email (from either dev mode or token), proceed as before
        # Check if QuickBooks tokens are available
        access_token, refresh_token, realm_id, expiry = get_tokens_by_email(user_email)

        if not access_token or not refresh_token or not realm_id:
            # No tokens found – prompt the user to log in with QuickBooks
            logging.info("No QuickBooks tokens found. Prompting user to log in with QuickBooks.")
            return render_template('dashboard.html', success_message=success_message, quickbooks_login_needed=True)

        # Refresh token if expired
        if expiry and datetime.utcnow() > datetime.fromisoformat(expiry):
            logging.info("QuickBooks token expired. Refreshing...")
            refresh_access_token()

        # Fetch QuickBooks company info as an example
        company_info = get_company_info()

        # Render the dashboard with optional success message
        return render_template('dashboard.html', data=company_info, success_message=success_message, quickbooks_login_needed=False)

    except Exception as e:
        logging.error(f"Error in /dashboard: {e}", exc_info=True)
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
    try:
        # Use the get_reports() function to return the full list of supported reports
        available_reports = get_reports()
        return {
            "availableReports": available_reports,
            "message": "Use the /fetch-reports endpoint with a valid reportType from this list."
        }, 200
    except Exception as e:
        logging.error(f"Error listing reports: {e}")
        return {"error": str(e)}, 500



@app.route('/fetch-reports', methods=['GET'])
def fetch_reports():
    try:
        report_type = request.args.get('reportType')
        start_date = request.args.get('startDate')
        end_date = request.args.get('endDate')

        if not report_type:
            return {"error": "reportType parameter is required"}, 400

        # Validate reportType against the list of supported reports
        if report_type not in get_reports():
            return {"error": f"Invalid reportType: {report_type}. Use /list-reports to see available reports."}, 400

        # Use the defined fetch_report() function
        report_data = fetch_report(
            report_type=report_type,
            start_date=start_date,
            end_date=end_date
        )

        return {"reportType": report_type, "data": report_data}, 200
    except Exception as e:
        logging.error(f"Error fetching report: {e}")
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
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": "Test API key"}],
            max_tokens=10
        )
        return {"response": response['choices'][0]['message']['content']}, 200
    except Exception as e:
        return {"error": str(e)}, 500
    
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
