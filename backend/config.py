import os
from dotenv import load_dotenv


load_dotenv()  # Load environment variables from .env


# Load .env only in development mode
if os.getenv("FLASK_ENV") == "development":
    load_dotenv()

class Config:
    """Application Configuration"""
    
    # ✅ Environment & Debugging
    FLASK_ENV = os.getenv("FLASK_ENV", "production")
    DEBUG = FLASK_ENV == "development"
    
    # ✅ Core Security Keys
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
    if not SECRET_KEY:
        raise RuntimeError("Missing FLASK_SECRET_KEY environment variable!")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
    
    # ✅ Session & Cookie Settings
    if FLASK_ENV == "development":
        SESSION_COOKIE_SECURE = False
        SESSION_COOKIE_DOMAIN = None
    else:
        SESSION_COOKIE_SECURE = True
        SESSION_COOKIE_DOMAIN = '.linkbooksai.com'
    SESSION_COOKIE_HTTPONLY = True
    
    # ✅ Set the frontend URL dynamically (use the deployed URL in production)
    FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")  # Default for local dev

    # ✅ OpenAI Configuration
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    OPENAI_ASSISTANT_ID = os.getenv("OPENAI_ASSISTANT_ID")

    # ✅ Supabase Configuration
    SUPABASE_URL = os.getenv("SUPABASE_URL")
    SUPABASE_KEY = os.getenv("SUPABASE_KEY")

    # ✅ Stripe Configuration
    STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
    STRIPE_PUBLIC_KEY = os.getenv("STRIPE_PUBLIC_KEY")
    
    # ✅ Brevo Configuration
    BREVO_API_KEY = os.getenv('BREVO_API_KEY')
    BREVO_SEND_EMAIL_URL = "https://api.brevo.com/v3/smtp/email"

    # ✅ Email Configuration (Brevo, Mailgun, etc.)
    MAIL_SERVER = os.getenv("MAIL_SERVER")
    MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "True") == "True"
    MAIL_USERNAME = os.getenv("MAIL_USERNAME")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
    

    # ✅ CORS Configuration
    CORS_ORIGIN = os.getenv("CORS_ORIGIN", "https://linkbooksai.com")  # Production
    CORS_ORIGIN_LOCAL = os.getenv("CORS_ORIGIN_LOCAL", "http://localhost:5173")  # Local Dev
    ACTIVE_CORS_ORIGIN = CORS_ORIGIN_LOCAL if os.getenv("FLASK_ENV") == "development" else CORS_ORIGIN

    ALLOWED_CORS_ORIGINS = [
        "https://linkbooksai.com",
        "https://app.linkbooksai.com"
    ]
    if os.getenv("FLASK_ENV") == "development":
        ALLOWED_CORS_ORIGINS.append("http://localhost:5173")

    # ✅ WebSocket Configuration
    SOCKETIO_CORS_ALLOWED_ORIGINS = ALLOWED_CORS_ORIGINS
    SOCKETIO_TRANSPORTS = ["websocket"]  # Force WebSockets (no polling)
    SOCKETIO_PING_INTERVAL = 25  # Helps keep connection alive
    SOCKETIO_PING_TIMEOUT = 60  # Prevents WebSocket from closing too soon
    
    print(f"✅ CORS Allowed Origins: {ALLOWED_CORS_ORIGINS}")
    print(f"✅ WebSockets Allowed Origins: {SOCKETIO_CORS_ALLOWED_ORIGINS}")
    
    # ✅ QuickBooks OAuth Settings
    if FLASK_ENV == "development":
        QB_CLIENT_ID = os.getenv("QB_SANDBOX_CLIENT_ID")
        QB_CLIENT_SECRET = os.getenv("QB_SANDBOX_CLIENT_SECRET")
        QB_REDIRECT_URI = os.getenv("SANDBOX_REDIRECT_URI")
        QUICKBOOKS_API_BASE_URL = "https://sandbox-quickbooks.api.intuit.com/v3/company/"
        LOGGING_LEVEL = 'DEBUG'
    else:
        QB_CLIENT_ID = os.getenv("QB_PROD_CLIENT_ID")
        QB_CLIENT_SECRET = os.getenv("QB_PROD_CLIENT_SECRET")
        QB_REDIRECT_URI = os.getenv("PROD_REDIRECT_URI")
        QUICKBOOKS_API_BASE_URL = "https://quickbooks.api.intuit.com/v3/company/"
        LOGGING_LEVEL = 'INFO'
        
    AUTHORIZATION_BASE_URL = "https://appcenter.intuit.com/connect/oauth2"
    TOKEN_URL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
    SCOPE = "com.intuit.quickbooks.accounting"
    REVOKE_TOKEN_URL = "https://developer.api.intuit.com/v2/oauth2/tokens/revoke"

    # ✅ Validate Required Environment Variables
    REQUIRED_ENV_VARS = [
        "SUPABASE_URL", "SUPABASE_KEY", "FLASK_SECRET_KEY"
    ]
    if FLASK_ENV == "development":
        REQUIRED_ENV_VARS.extend(["QB_SANDBOX_CLIENT_ID", "QB_SANDBOX_CLIENT_SECRET", "SANDBOX_REDIRECT_URI"])
    else:
        REQUIRED_ENV_VARS.extend(["QB_PROD_CLIENT_ID", "QB_PROD_CLIENT_SECRET", "PROD_REDIRECT_URI"])
        
    # Check for missing environment variables
    MISSING_VARS = [var for var in REQUIRED_ENV_VARS if not os.getenv(var)]
    if MISSING_VARS:
        raise RuntimeError(f"Missing required environment variables: {', '.join(MISSING_VARS)}")

    if os.getenv("FLASK_ENV") == "development":  
        print("✅ Loaded Environment Variables:")
        for key in REQUIRED_ENV_VARS:
            value = os.getenv(key)
            masked_value = "*****" if "KEY" in key or "SECRET" in key else value
            print(f"{key}: {masked_value}")

    

# ✅ Function to get the current config
def get_config():
    return Config()