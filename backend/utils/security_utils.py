import secrets
import random, string
import jwt
from flask import request
from config import Config
from functools import wraps



def generate_random_state(length=16):
    """
    Generates a random `state` string for OAuth (CSRF protection).
    """
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def token_required(f):
    """
    Decorator requiring a valid token from the session_token cookie.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("session_token")
        if not token:
            return {"error": "No Authorization token provided"}, 401
        try:
            decoded = jwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])
            request.user_id = decoded.get("user_id")
            if not request.user_id:
                raise Exception("No user_id found in the token.")
        except jwt.ExpiredSignatureError:
            return {"error": "Token has expired"}, 401
        except jwt.InvalidTokenError:
            return {"error": "Invalid token"}, 401
        except Exception:
            return {"error": "Unauthorized access. Please log in again."}, 401

        return f(*args, **kwargs)
    return decorated


