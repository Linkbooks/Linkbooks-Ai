from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_socketio import SocketIO
import supabase

# Initialize Supabase Client
from config import Config

supabase_url = Config.SUPABASE_URL
supabase_key = Config.SUPABASE_KEY
supabase_client = supabase.create_client(supabase_url, supabase_key)

# Initialize Flask Extensions
jwt = JWTManager()
limiter = Limiter()
socketio = SocketIO(cors_allowed_origins="*")
