import os
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env

class Config:
    # ✅ Core Security Keys
    SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "myjwtsecret")

    # ✅ OpenAI Configuration
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    OPENAI_ASSISTANT_ID = os.getenv("OPENAI_ASSISTANT_ID")  # For Threaded Chat Support

    # ✅ Supabase Configuration
    SUPABASE_URL = os.getenv("SUPABASE_URL")
    SUPABASE_KEY = os.getenv("SUPABASE_KEY")

    # ✅ Stripe Configuration
    STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
    STRIPE_PUBLIC_KEY = os.getenv("STRIPE_PUBLIC_KEY")

    # ✅ Email Configuration (Brevo, Mailgun, etc.)
    MAIL_SERVER = os.getenv("MAIL_SERVER")
    MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "True") == "True"
    MAIL_USERNAME = os.getenv("MAIL_USERNAME")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")

    # ✅ CORS Configurations
    ALLOWED_CORS_ORIGINS = [
        "https://linkbooksai.com",
        "https://app.linkbooksai.com"
    ]
    if os.getenv("FLASK_ENV") == "development":
        ALLOWED_CORS_ORIGINS.append("http://localhost:5173")

    # ✅ Logging & Debugging
    DEBUG = os.getenv("FLASK_ENV") == "development"


def get_config():
    """Returns the correct config based on environment."""
    return Config()
