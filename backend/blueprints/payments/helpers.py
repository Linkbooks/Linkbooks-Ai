import logging
import os
import stripe
import secrets
from datetime import datetime, timedelta
from flask import jsonify, render_template
from extensions import supabase
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
def create_stripe_checkout_session(user_id, email, subscription_plan, chat_session_id):
    checkout_session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        mode='subscription',
        line_items=[{
            'price': os.getenv(f'STRIPE_{subscription_plan.upper()}_PRICE_ID'),
            'quantity': 1,
        }],
        success_url=f"https://linkbooksai.com/payment_success?session_id={{CHECKOUT_SESSION_ID}}&chat_session_id={chat_session_id}",
        cancel_url="https://linkbooksai.com/payment_cancel",
        metadata={'user_id': user_id, 'subscription_plan': subscription_plan, 'chat_session_id': chat_session_id}
    )
    return checkout_session


# --------------------------------------------
#          Email Verification
# --------------------------------------------
def verify_email_token(token):
    verification = supabase.table("email_verifications").select("*").eq("token", token).execute()
    if not verification.data:
        return render_template('verify_email.html', error="Invalid or expired token."), 400
    return render_template('email_verified.html'), 200
