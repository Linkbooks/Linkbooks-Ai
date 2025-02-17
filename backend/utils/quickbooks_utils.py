import logging
from datetime import datetime
from extensions import supabase

def get_quickbooks_tokens(user_id):
    """
    Retrieve QuickBooks tokens for a given user ID from quickbooks_tokens table.
    """
    try:
        response = supabase.table("quickbooks_tokens").select("*").eq("user_id", user_id).execute()
        if not response.data:  # No tokens found
            logging.error(f"❌ No QuickBooks tokens found for user {user_id}.")
            raise ValueError("No QuickBooks tokens found for the user.")
        return response.data[0]
    except Exception as e:
        logging.error(f"❌ Error fetching QuickBooks tokens: {e}")
        raise ValueError("Failed to fetch QuickBooks tokens.")

def save_quickbooks_tokens(user_id, realm_id, access_token, refresh_token, token_expiry):
    """
    Upserts QuickBooks tokens for the single user row identified by user_id.
    This ensures only ONE row per user in quickbooks_tokens.
    """
    try:
        response = supabase.table("quickbooks_tokens") \
            .upsert({
                "user_id": user_id,
                "realm_id": realm_id,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_expiry": token_expiry,
                "last_updated": datetime.utcnow().isoformat()
            }) \
            .execute()

        logging.info(f"✅ QuickBooks tokens saved successfully for user_id={user_id}.")
    except Exception as e:
        logging.error(f"❌ Error saving QuickBooks tokens for user_id={user_id}: {e}")
        raise ValueError("Failed to save QuickBooks tokens.")
