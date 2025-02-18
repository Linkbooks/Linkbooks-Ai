import logging
import os
from extensions import stripe
from extensions import supabase
import secrets
from datetime import datetime, timedelta
from flask import jsonify, render_template
from utils import send_verification_email

# Initialize Stripe
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')


# --------------------------------------------
#          Stripe Event Handling
# --------------------------------------------
def handle_stripe_event(payload, sig_header):
    endpoint_secret = os.getenv('STRIPE_WEBHOOK_SECRET')

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    except (ValueError, stripe.error.SignatureVerificationError):
        logging.error("Invalid Stripe Webhook Signature")
        return "Invalid signature", 400

    event_type = event["type"]
    data = event["data"]["object"]

    try:
        if event_type == "checkout.session.completed":
            handle_checkout_session_completed(data)
        elif event_type == "invoice.payment_succeeded":
            handle_invoice_payment_succeeded(data)
        elif event_type == "customer.subscription.updated":
            handle_customer_subscription_updated(data)
        else:
            logging.info(f"Unhandled event type: {event_type}")
    except Exception as e:
        logging.error(f"Error processing event {event_type}: {e}", exc_info=True)
        return "Error processing event", 500

    return "", 200


# --------------------------------------------
#          Stripe Subscription Handlers
# --------------------------------------------
def handle_checkout_session_completed(session):
    email = session.get("customer_email")
    metadata = session.get("metadata", {})
    user_id = metadata.get("user_id")
    subscription_plan = metadata.get("subscription_plan")
    chat_session_id = metadata.get("chat_session_id")
    customer_id = session.get("customer")
    subscription_id = session.get("subscription")

    if not user_id:
        raise Exception("No user_id found in session metadata.")

    supabase.table("user_profiles").upsert({
        "id": user_id,
        "email": email,
        "subscription_status": "active",
        "subscription_plan": subscription_plan,
        "subscription_id": subscription_id,
        "chat_session_id": chat_session_id,
        "customer_id": customer_id,
        "updated_at": datetime.utcnow().isoformat()
    }).execute()

    token = secrets.token_urlsafe(32)
    expiry = datetime.utcnow() + timedelta(hours=24)

    supabase.table("email_verifications").insert({
        "user_id": user_id,
        "token": token,
        "expires_at": expiry.isoformat(),
        "created_at": datetime.utcnow().isoformat()
    }).execute()

    send_verification_email(email, token)


def handle_invoice_payment_succeeded(invoice):
    customer_id = invoice['customer']
    supabase.table("user_profiles").update({"subscription_status": "active"}).eq("customer_id", customer_id).execute()


def handle_customer_subscription_updated(subscription):
    customer_id = subscription["customer"]
    subscription_id = subscription.get("id")
    status = subscription["status"]
    trial_end = subscription.get("trial_end")

    updates = {"subscription_status": status, "subscription_id": subscription_id}
    if trial_end and trial_end < datetime.utcnow().timestamp():
        updates["free_week"] = False

    supabase.table("user_profiles").update(updates).eq("customer_id", customer_id).execute()


# --------------------------------------------
#          Stripe Session Creation
# --------------------------------------------
def create_stripe_checkout_session(user_id, email, subscription_plan, chat_session_id=None):
    """
    Creates and returns a Stripe Checkout Session 
    for the given user and subscription plan.
    """
    # Map subscription plans to Stripe Price IDs and trial durations
    plan_details = {
        "monthly_no_offer": {"price_id": "price_1QhXfxDi1nqWbBYc76q14cWL", "trial_days": 0},
        "monthly_3mo_discount": {"price_id": "price_1QhdvrDi1nqWbBYcWOcfXTRJ", "trial_days": 0},
        "annual_free_week": {"price_id": "price_1QhdyFDi1nqWbBYcdzAdZ7lE", "trial_days": 7},
        "annual_further_discount": {"price_id": "price_1Qhe01Di1nqWbBYcixjWCokH", "trial_days": 0}
    }

    # Validate the selected plan
    plan = plan_details.get(subscription_plan)
    if not plan:
        raise ValueError("Invalid subscription plan selected")

    # Extract price ID and trial period for the selected plan
    price_id = plan["price_id"]
    trial_period_days = plan["trial_days"]

    # Build success and cancel URLs with optional chat_session_id
    base_success_url = "https://linkbooksai.com/payment_success"
    base_cancel_url = "https://linkbooksai.com/payment_cancel"

    success_url = f"{base_success_url}?session_id={{CHECKOUT_SESSION_ID}}"
    cancel_url = base_cancel_url

    if chat_session_id:
        success_url += f"&chat_session_id={chat_session_id}"
        cancel_url += f"?chat_session_id={chat_session_id}"

    try:
        # Prepare subscription data
        subscription_data = {}
        if trial_period_days > 0:
            subscription_data["trial_period_days"] = trial_period_days  # Include trial only for eligible plans

        # Create the Stripe Checkout Session
        stripe_session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode="subscription",
            line_items=[{"price": price_id, "quantity": 1}],
            customer_email=email,
            subscription_data=subscription_data,  # Add trial days only if > 0
            success_url=success_url,
            cancel_url=cancel_url,
            metadata={
                "subscription_plan": subscription_plan,
                "chat_session_id": chat_session_id,
                "user_id": user_id  # Include user_id for webhook association
            }
        )
        return stripe_session  # Return the full stripe session object
    
    except stripe.error.StripeError as e:
        logging.error(f"Stripe API error: {e}")
        raise Exception(f"Failed to create Stripe session: {str(e)}")

# --------------------------------------------
#          Email Verification
# --------------------------------------------
def verify_email_token(token):
    verification = supabase.table("email_verifications").select("*").eq("token", token).execute()
    if not verification.data:
        return render_template('verify_email.html', error="Invalid or expired token."), 400
    return render_template('email_verified.html'), 200
