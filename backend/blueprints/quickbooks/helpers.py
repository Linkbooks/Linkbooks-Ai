import logging, requests, json
from extensions import supabase
from datetime import datetime, timedelta
from config import Config

#-------- Config Variables --------#
CLIENT_ID = Config.QB_CLIENT_ID
CLIENT_SECRET = Config.QB_CLIENT_SECRET
REDIRECT_URI = Config.QB_REDIRECT_URI


#------------------------------------------------------------#
#------------------- Quickbooks Utils -----------------------#
#------------------------------------------------------------#

#--------------- Refresh Access Token Def -------------------#

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
        response = requests.post(Config.REVOKE_TOKEN_URL, auth=auth_header, data=payload, headers=headers)
        if response.status_code != 200:
            raise Exception(f"Failed to revoke tokens: {response.text}")
        logging.info("QuickBooks tokens revoked successfully.")
    except Exception as e:
        logging.error(f"Error revoking tokens: {e}")
        raise
    
    
def refresh_access_token(user_id):
    """
    Refreshes the QuickBooks access token for an app-based user (one row per user).
    """
    quickbooks_data = get_quickbooks_tokens(user_id)
    if not quickbooks_data:
        raise Exception("No QuickBooks tokens found for this user.")

    refresh_token = quickbooks_data['refresh_token']
    auth_header = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    payload = {'grant_type': 'refresh_token', 'refresh_token': refresh_token}
    headers = {'Accept': 'application/json'}

    response = requests.post(Config.TOKEN_URL, auth=auth_header, data=payload, headers=headers)
    if response.status_code == 200:
        tokens_json = response.json()
        new_access_token = tokens_json['access_token']
        new_refresh_token = tokens_json.get('refresh_token', refresh_token)
        new_expiry = (datetime.utcnow() + timedelta(seconds=tokens_json['expires_in'])).isoformat()

        save_quickbooks_tokens(
            user_id=user_id,
            realm_id=quickbooks_data['realm_id'],
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            token_expiry=new_expiry
        )
        logging.info(f"Access token refreshed for user {user_id}.")
    else:
        logging.error(f"Failed to refresh access token for user_id={user_id}: {response.text}")
        raise Exception(response.text)
    
    
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
