import os
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO
from supabase import Client, create_client
from openai import OpenAI
from config import Config
import logging
import stripe


# ✅ Initialize CORS (without `app`, will be attached later in `app.py`)
cors = CORS(supports_credentials=True)

# ✅ Initialize WebSocket SocketIO
socketio = SocketIO(
    cors_allowed_origins=Config.SOCKETIO_CORS_ALLOWED_ORIGINS,
    transports=Config.SOCKETIO_TRANSPORTS,
    ping_interval=Config.SOCKETIO_PING_INTERVAL,
    ping_timeout=Config.SOCKETIO_PING_TIMEOUT
)

# ✅ Initialize Supabase Client
try:
    supabase: Client = create_client(Config.SUPABASE_URL, Config.SUPABASE_KEY)
    logging.info("✅ Supabase client initialized successfully.")
except Exception as e:
    logging.error(f"❌ Error initializing Supabase client: {e}")
    supabase = None
    raise e  # Stop execution if Supabase fails to initialize

# Initialize Flask Extensions
jwt = JWTManager()
limiter = Limiter(key_func=get_remote_address)
socketio = SocketIO(cors_allowed_origins="*")

# Initialize Stripe
stripe.api_key = Config.STRIPE_SECRET_KEY

# Initialize OpenAI
openai_client = OpenAI(api_key=Config.OPENAI_API_KEY)