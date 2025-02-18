import logging
import atexit
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.events import EVENT_JOB_ERROR
from extensions import supabase

# ✅ Initialize Scheduler
scheduler = BackgroundScheduler()

# --------------------------------------------#
#              Cleanup Jobs                   #
# --------------------------------------------#

def cleanup_expired_states():
    """Deletes expired entries in 'chatgpt_oauth_states'."""
    try:
        now = datetime.utcnow().isoformat()
        supabase.table("chatgpt_oauth_states").delete().lt("expiry", now).execute()
        logging.info("✅ Expired state tokens cleaned up.")
    except Exception as e:
        logging.error(f"❌ Error cleaning up expired states: {e}")

def cleanup_expired_verifications():
    """Deletes expired email verifications from 'email_verifications'."""
    try:
        now = datetime.utcnow().isoformat()
        supabase.table("email_verifications").delete().lt("expires_at", now).execute()
        logging.info("✅ Expired email verifications cleaned up.")
    except Exception as e:
        logging.error(f"❌ Error cleaning up expired email verifications: {e}")

def cleanup_expired_verifications_and_pending_users():
    """Deletes expired email verifications & pending users after 24 hours."""
    try:
        now = datetime.utcnow().isoformat()

        # Delete expired email verifications
        supabase.table("email_verifications").delete().lt("expires_at", now).execute()
        logging.info("✅ Expired email verifications cleaned up.")

        # Delete users with 'pending' status who haven't verified within 24 hours
        expired_cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
        expired_users = supabase.table("user_profiles").select("id").eq("subscription_status", "pending").lt("created_at", expired_cutoff).execute()

        for user in expired_users.data:
            user_id = user['id']
            supabase.auth.api.delete_user(user_id)
            supabase.table("user_profiles").delete().eq("id", user_id).execute()
            logging.info(f"✅ Deleted pending user {user_id} due to expired verification.")
    except Exception as e:
        logging.error(f"❌ Error during cleanup: {e}")

def cleanup_inactive_users():
    """Deletes inactive user accounts created over 24 hours ago."""
    try:
        cutoff_time = (datetime.utcnow() - timedelta(hours=48)).isoformat()
        supabase.table("user_profiles").delete().lt("created_at", cutoff_time).eq("subscription_status", "inactive").execute()
        logging.info("✅ Inactive user accounts cleaned up.")
    except Exception as e:
        logging.error(f"❌ Error cleaning up inactive user accounts: {e}")

def log_scheduler_error(event):
    """Logs errors occurring in scheduled jobs."""
    if event.exception:
        logging.error(f"❌ Scheduler job failed: {event.job_id}, Exception: {event.exception}")

# --------------------------------------------#
#              Scheduler Setup                #
# --------------------------------------------#

def start_scheduler():
    """Starts the scheduler and registers cleanup jobs."""
    global scheduler
    if not scheduler.running:  # Avoid double-starting the scheduler
        logging.info("🚀 Starting background scheduler...")

        # ✅ Schedule cleanup jobs
        scheduler.add_job(cleanup_expired_states, 'interval', hours=200, id='cleanup_expired_states')
        scheduler.add_job(cleanup_expired_verifications, 'cron', hour=0, id='cleanup_expired_verifications')
        scheduler.add_job(cleanup_expired_verifications_and_pending_users, 'interval', hours=1, id='cleanup_expired_verifications_and_pending_users')
        scheduler.add_job(cleanup_inactive_users, 'cron', hour=1, id='cleanup_inactive_users')

        # ✅ Register error listener
        scheduler.add_listener(log_scheduler_error, EVENT_JOB_ERROR)

        # ✅ Start the scheduler
        scheduler.start()
        logging.info("✅ Scheduler started successfully.")

        # ✅ Register scheduler shutdown
        atexit.register(lambda: scheduler.shutdown())

# ✅ Start the scheduler when module is loaded
start_scheduler()
