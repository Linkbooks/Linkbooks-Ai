import logging
from datetime import datetime, timedelta, timezone
import jwt
from config import Config
from extensions import supabase
from bcrypt import checkpw


def create_user_with_email(user_data):
    """
    Creates a user in Supabase Auth and user_profiles.
    Raises an exception if any step fails.
    Returns the user_id on success.
    """
    email = user_data.get("email")
    password = user_data.get("password")
    name = user_data.get("name")
    phone = user_data.get("phone")
    address = user_data.get("address")

    # Step 1: Create the user in Supabase Auth
    try:
        auth_response = supabase.auth.sign_up({"email": email, "password": password})
        if auth_response.get('user'):
            user_id = auth_response['user']['id']
            logging.info(f"User {name} created successfully in Supabase Auth with ID: {user_id}")
        else:
            logging.error(f"Error creating user in Supabase Auth: {auth_response}")
            raise Exception("Failed to create user in Supabase Auth.")
    except Exception as e:
        logging.error(f"Error creating user in Supabase Auth: {e}")
        raise Exception("Failed to create user.")

    # Step 2: Insert additional user data
    try:
        profile_response = supabase.table('user_profiles').insert({
            'id': user_id,
            'name': name,
            'email': email,
            'phone': phone,
            'address': address,
            'subscription_status': 'pending',  # Set to 'pending' initially
        }).execute()

        if profile_response.data:
            logging.info(f"User profile created successfully for {name}.")
        else:
            logging.error(f"Error creating user profile: {profile_response}")
            raise Exception("Failed to create user profile.")
    except Exception as e:
        logging.error(f"Error creating user profile: {e}")
        # Rollback user creation in Supabase Auth
        try:
            supabase.auth.api.delete_user(user_id)
            logging.info(f"Deleted user {user_id} due to profile creation failure.")
        except Exception as delete_error:
            logging.error(f"Error deleting user {user_id}: {delete_error}")
        raise Exception("Failed to create user profile.")

    return user_id

# ✅ Debug Logging Function (Ensure this is before generate())
def log_debug(msg):
    print(f"{datetime.now().isoformat()} - {msg}", flush=True)

def generate_session_token(user_id, email):
    """
    Generates a JWT token with 24-hour expiry.
    """
    token = jwt.encode(
        {
            "user_id": user_id,
            "email": email,
            "exp": datetime.now(timezone.utc) + timedelta(hours=24)
        },
        Config.SECRET_KEY,
        algorithm="HS256"
    )
    return token

