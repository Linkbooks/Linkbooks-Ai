import logging
import requests
import openai
from datetime import datetime, timedelta
from extensions import supabase
from config import Config

# -------- Config Variables --------#

CLIENT_ID = Config.QB_CLIENT_ID
CLIENT_SECRET = Config.QB_CLIENT_SECRET
TOKEN_URL = Config.TOKEN_URL


def refresh_access_token_for_chatgpt(chat_session_id, refresh_token):
    """
    Refreshes the QuickBooks access token for a ChatGPT session using Supabase.
    """
    auth_header = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    payload = {'grant_type': 'refresh_token', 'refresh_token': refresh_token}
    headers = {'Accept': 'application/json'}

    response = requests.post(TOKEN_URL, auth=auth_header, data=payload, headers=headers)
    
    if response.status_code == 200:
        tokens = response.json()
        access_token = tokens['access_token']
        new_refresh_token = tokens.get('refresh_token', refresh_token)
        expiry = (datetime.utcnow() + timedelta(seconds=tokens['expires_in'])).isoformat()

        try:
            update_resp = supabase.table("chatgpt_tokens").update({
                "access_token": access_token,
                "refresh_token": new_refresh_token,
                "expiry": expiry
            }).eq("chat_session_id", chat_session_id).execute()

            if not update_resp.data:
                raise Exception("Failed to update tokens in Supabase")

            logging.info(f"✅ Access token refreshed for ChatGPT session {chat_session_id}")
            return {
                "access_token": access_token,
                "refresh_token": new_refresh_token,
                "expiry": expiry
            }
        except Exception as e:
            logging.error(f"❌ Failed to store refreshed tokens for ChatGPT session {chat_session_id}: {e}")
            raise
    else:
        logging.error(f"❌ Failed to refresh access token for chatSessionId {chat_session_id}: {response.text}")
        raise Exception(response.text)


def store_tokens_for_chatgpt_session(chat_session_id, realm_id, access_token, refresh_token, expiry):
    """
    Stores QuickBooks tokens associated with a ChatGPT session ID into 'chatgpt_tokens'.
    """
    try:
        # Retrieve user_id from user_profiles
        user_profile = supabase.table("user_profiles").select("id").eq("chat_session_id", chat_session_id).execute()
        if not user_profile.data:
            logging.error(f"No user found for chatSessionId: {chat_session_id}")
            raise ValueError("User not found for given chatSessionId")

        user_id = user_profile.data[0]["id"]

        payload = {
            "chat_session_id": chat_session_id,
            "user_id": user_id,
            "realm_id": realm_id,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expiry": expiry
        }
        logging.info(f"Payload for chatgpt_tokens upsert: {payload}")

        token_response = supabase.table("chatgpt_tokens").upsert(payload).execute()

        if not token_response.data:  # Ensure response contains data
            logging.error(f"Failed to store tokens. Response: {token_response}")
            raise ValueError("Failed to store tokens")



        logging.info(f"Tokens stored successfully for chatSessionId: {chat_session_id}")
    except Exception as e:
        logging.error(f"Error storing tokens for ChatGPT session {chat_session_id}: {e}")
        raise
    
    
def should_use_gpt4o(query):
    """
    Determines if GPT-4o should be used based on complexity.
    """
    if len(query) > 100:  # Example: Longer queries are likely more complex
        return True
    keywords = ["approximate", "similar to", "fuzzy match", "group by", "trend"]
    if any(kw in query.lower() for kw in keywords):  # Keywords suggest deeper reasoning
        return True
    return False


def ask_gpt_to_filter(transactions, query, model):
    """
    Sends transactions and a query to OpenAI for intelligent filtering.
    """
    openai_client = openai.OpenAI()  # Ensure OpenAI client is initialized properly

    response = openai_client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are an AI that analyzes financial transactions and filters them based on user requests."},
            {"role": "user", "content": f"Here are my transactions:\n{transactions}\n\nFilter them based on this request: {query}"}
        ]
    )
    return response.choices[0].message.content  # Corrected path to response content
