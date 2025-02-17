import logging
from datetime import datetime
from extensions import supabase

def validate_state(state):
    """
    Validates the incoming OAuth state against chatgpt_oauth_states (CSRF protection).
    Ensures that the state exists and hasn't expired.
    """
    response = supabase.table("chatgpt_oauth_states").select("*").eq("state", state).execute()
    if not response.data:
        logging.error(f"❌ State not found in database: {state}")
        raise ValueError("Invalid or expired state parameter.")

    stored_state = response.data[0]
    expiry = datetime.fromisoformat(stored_state["expiry"])
    if datetime.utcnow() > expiry:
        logging.error(f"State expired. Generated: {stored_state['expiry']} Current: {datetime.utcnow()}")
        raise ValueError("State token expired.")
    
    return stored_state # ✅ Returns stored session details if valid
