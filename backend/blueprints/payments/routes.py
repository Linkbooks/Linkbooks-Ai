import logging
from flask import Blueprint, request, session, redirect, url_for, jsonify, render_template
from extensions import supabase, stripe
from .helpers import (
    handle_stripe_event,
    create_stripe_checkout_session,
    verify_email_token
)

# Create Blueprint
payments_bp = Blueprint('payments', __name__, url_prefix='/payments')

# --------------------------------------------
#              Subscriptions
# --------------------------------------------
@payments_bp.route('/subscriptions', methods=['GET', 'POST'])
def subscriptions():
    if request.method == 'GET':
        email = session.get('email')
        chat_session_id = session.get('chat_session_id', None)
        user_id = session.get('user_id')

        if not email:
            return redirect(url_for('auth.create_account'))

        user_profile = supabase.table("user_profiles").select("subscription_status").eq("email", email).execute()
        if user_profile.data:
            subscription_status = user_profile.data[0].get("subscription_status")
            if subscription_status == "active":
                return redirect(url_for('dashboard'))
            elif subscription_status == "pending":
                return render_template('subscriptions.html', email=email, chat_session_id=chat_session_id, user_id=user_id, message="Your payment is being processed.")

        return render_template('subscriptions.html', email=email, chat_session_id=chat_session_id, user_id=user_id)
    
    elif request.method == 'POST':
        data = request.json
        email = data.get('email')
        subscription_plan = data.get('subscription_plan')
        chat_session_id = data.get('chat_session_id', None)

        if not email or not subscription_plan:
            return jsonify({'error': 'Email and subscription plan are required'}), 400

        user_profile = supabase.table("user_profiles").select("id").eq("email", email).execute()
        if not user_profile.data:
            return jsonify({'error': 'No user found with that email'}), 404

        user_id = user_profile.data[0]['id']

        try:
            stripe_session = create_stripe_checkout_session(user_id, email, subscription_plan, chat_session_id)
            return jsonify({'checkoutUrl': stripe_session.url}), 200
        except Exception as e:
            logging.error(f"Stripe session creation failed: {e}, chat_session_id: {chat_session_id}")
            return jsonify({'error': str(e)}), 500


# --------------------------------------------
#              Stripe Webhooks
# --------------------------------------------
@payments_bp.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    """
    Calls `handle_stripe_event` to process Stripe webhook events.
    """
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')

    return handle_stripe_event(payload, sig_header)


# --------------------------------------------
#              Stripe Redirects
# --------------------------------------------
@payments_bp.route('/payment_success')
def payment_success():
    session_id = request.args.get('session_id')
    chat_session_id = request.args.get('chat_session_id')

    if not session_id:
        return "Missing session ID", 400

    return render_template('payment_success.html', session_id=session_id, chat_session_id=chat_session_id)


@payments_bp.route('/payment_cancel')
def payment_cancel():
    chat_session_id = request.args.get('chat_session_id')
    return render_template('payment_cancel.html', chat_session_id=chat_session_id)


# --------------------------------------------
#              Email Verification
# --------------------------------------------
@payments_bp.route('/verify-email', methods=['GET'])
def verify_email():
    token = request.args.get('token')
    return verify_email_token(token)
